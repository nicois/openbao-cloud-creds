// Package capability verifies that a minter can actually mint — not merely
// authenticate.
//
// A health check proves a minter credential is live; it does not prove the
// credential holds the upstream privileges the roles bound to its set require.
// A minter that authenticates but lacks (say) DigitalOcean's droplet:create
// scope is reported healthy indefinitely by the recovery state machine and only
// fails at the first credential read, as an upstream 403.
//
// This package drives a throwaway "probe" mint instead: create a credential
// with the same request shape a real issuance would use, then immediately
// delete it. Probes run at minter-set write, at role write, and before a
// rotation commits, so an incapable minter is rejected at configuration time by
// the operator who caused it rather than at read time by an unrelated caller.
//
// Probes are deduplicated per (minter, mint-request shape): two roles that
// would produce an identical mint request are proved by one probe.
package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// rolesPrefix is the storage prefix every plugin stores its roles under.
const rolesPrefix = "roles/"

// ErrUnsupported reports that a cloud cannot be probed safely, so its capability
// is taken on trust. Only OCI returns it: its 2-auth-tokens-per-user quota means
// a probe mint would consume a rotation slot and could itself break issuance.
// A Run that returns it is counted as skipped, not failed.
var ErrUnsupported = errors.New("capability verification is not supported on this cloud")

// Check is one probe: Run must mint a credential using the same request shape a
// real issuance for Roles would use, then delete whatever it created. Run
// returning an error means the minter cannot serve those roles.
type Check struct {
	// Key deduplicates probes. Two Checks with the same Key issue the same mint
	// request from the same minter, so only the first is run. Build it from the
	// minter ID plus every role field that reaches the upstream mint call.
	Key string
	// Minter is the ID of the minter being probed, for the failure message.
	Minter string
	// Roles are the role names that share this Key, for the failure message.
	Roles []string
	// Run performs the probe mint and deletes what it created. It returns the
	// upstream HTTP status alongside the error (credenvelope.StatusNone when there
	// was no response) so that a probe's own 429 can open the same cooldown a
	// caller's read would — a probe is a real mint against the same quota, and
	// leaving it outside the rate limiter meant a probe storm could neither be
	// gated by a cooldown nor open one (A29).
	Run func(context.Context) (int, error)
	// MinterJSON is the minter's stored form, used only to fingerprint a cached
	// verdict so that replacing the credential behind a minter id invalidates it.
	// It is never stored, logged or returned.
	MinterJSON []byte
}

// Result counts what a Verify pass did, for operator-facing logging.
type Result struct {
	// Ran is the number of distinct probes actually attempted.
	Ran int
	// Skipped is the number that reported ErrUnsupported.
	Skipped int
	// Cached is the number satisfied by a recent identical probe rather than by a
	// fresh mint.
	Cached int
}

// BoundRole is a stored role bound to a minter set. Raw is the role's stored
// JSON, so the caller can decode it into its own per-cloud role type without
// this package knowing any cloud's role schema.
type BoundRole struct {
	Name string
	Raw  []byte
}

// Failure describes a probe that failed, and exists to keep two audiences apart.
//
// Its Error() carries the upstream error verbatim, which is what the operator's
// log needs — and which must NOT reach an API caller: a probe error chains down to
// the cloud's raw response body, so returning it handed a caller with only
// `create` on roles/* the cloud's verbatim diagnostics (Azure AADSTS codes with
// tenant and correlation ids, Graph object ids, GCP project detail). That
// contradicted an unqualified claim in README and SUMMARY and defeated the fixed
// error string on the read path, since a role write probes the same minter with
// the same mint shape (A4 in docs/audit-2026-08-22.md).
//
// ClientMessage is the safe rendering: it names the minter and roles — which the
// caller supplied and already knows — and points at the log for the rest.
type Failure struct {
	Minter string
	Roles  []string
	Err    error
}

func (f *Failure) Error() string {
	return fmt.Sprintf("minter %q cannot mint the credential role(s) %s require: %v",
		f.Minter, strings.Join(f.Roles, ", "), f.Err)
}

func (f *Failure) Unwrap() error { return f.Err }

// ClientMessage renders the failure for an API response: no upstream body, no
// upstream error text, nothing the caller did not already provide — plus any
// OperatorHint a plugin attached, which is our own words rather than the cloud's.
func (f *Failure) ClientMessage() string {
	message := fmt.Sprintf("minter %q cannot mint the credential role(s) %s require; the upstream "+
		"refused the probe mint and its response is in the OpenBao server log",
		f.Minter, strings.Join(f.Roles, ", "))
	if hint := HintFor(f.Err); hint != "" {
		message += ". " + hint
	}
	return message
}

// operatorHint carries a plugin's own diagnosis alongside a probe failure. Deliberately
// unexported: nothing needs the concrete type, and WithHint/HintFor are the whole of
// the useful surface.
type operatorHint struct {
	hint string
	err  error
}

func (h *operatorHint) Error() string {
	if h.err == nil {
		return h.hint
	}
	return h.err.Error() + ": " + h.hint
}

func (h *operatorHint) Unwrap() error { return h.err }

// WithHint attaches an operator-facing diagnosis to a probe failure, so it reaches the
// operator instead of being redacted along with the upstream's response.
//
// # Why redaction needed an exception
//
// A probe failure's upstream text is withheld from the API response deliberately: the
// same probe runs on a role write and on a credential read, and a cloud's error body
// can name other tenants' resources or echo the credential (A4). But that rule was
// swallowing something it was never aimed at. A plugin sometimes knows a conclusion
// the cloud's own message actively obscures, and the conclusion is the entire value
// of the response.
//
// The case that proved it: DigitalOcean answers a fenced mint with a bare "You are
// not authorized to perform this operation", which invites an operator to go hunting
// for a missing privilege that does not exist (KI-009). credential-do has said so in
// `forbiddenMintHint` since that was verified — and it went into the wrapped error,
// so ClientMessage dropped every word of it. The operator got "the upstream refused
// the probe mint" and a pointer to a log line saying they were not authorized.
//
// A hint is safe to return where upstream text is not, for one reason worth stating:
// it is authored HERE, as a constant, by whoever read the cloud's documentation. It
// cannot contain a credential or another tenant's data because it does not come from
// the cloud at all. Never build one from a response body.
//
// hint must be operator-facing prose: what is actually wrong, and what to change. err
// keeps its own (redacted) path to the log. A nil err still yields a hint-carrying
// error, so a caller need not special-case one.
func WithHint(hint string, err error) error {
	return &operatorHint{hint: hint, err: err}
}

// HintFor returns the first operator hint in err's chain, or "" if there is none.
func HintFor(err error) string {
	if hint, ok := errors.AsType[*operatorHint](err); ok {
		return hint.hint
	}
	return ""
}

// Verify runs each distinct Check once and stops at the first failure, so an
// operator sees the first thing that is wrong rather than a list of cascading
// consequences. A failure is returned as *Failure.
func Verify(ctx context.Context, checks []Check) (Result, error) {
	return Runner{}.Verify(ctx, checks)
}

// Runner is Verify with the two things a bare probe pass lacked: a shared view of
// the rate limiter, and a memory.
//
// Both address the same complaint. A single minter-set write costs up to
// (minters x bound roles) real mints against the cloud, with nothing deduplicating
// across writes — so an idempotent `terraform apply` re-minted the whole fan-out
// every time, and on OVH each of those probes leaves a live one-hour token behind
// because that cloud has no revoke API at all. Meanwhile none of it went through
// the circuit breaker, so probes hammered a throttled cloud and a probe's own 429
// stayed invisible to the readers sharing that quota (A29).
//
// Both fields are optional: a zero Runner is the old behaviour, which is what the
// package's own tests want.
type Runner struct {
	// Cache remembers recent successful probes. Nil disables it.
	Cache *Cache
	// Limiter shares the issuance path's rate-limit state. Nil disables it.
	Limiter *Limiter
}

// Verify runs the deduplicated checks, consulting the cache and the limiter.
func (r Runner) Verify(ctx context.Context, checks []Check) (Result, error) {
	var result Result
	for _, c := range Dedupe(checks) {
		if r.Cache.fresh(ctx, c) {
			result.Cached++
			continue
		}
		if err := r.Limiter.acquire(c.Minter); err != nil {
			return result, err
		}
		status, err := c.Run(ctx)
		r.Limiter.record(c.Minter, status, err)
		switch {
		case err == nil:
			result.Ran++
			r.Cache.store(ctx, c)
		case errors.Is(err, ErrUnsupported):
			result.Skipped++
		default:
			return result, &Failure{Minter: c.Minter, Roles: c.Roles, Err: err}
		}
	}
	return result, nil
}

// Dedupe collapses Checks that share a Key into one, merging their Roles so a
// failure message still names every affected role. Order is by Key, so probe
// order (and therefore which failure an operator sees first) is deterministic.
func Dedupe(checks []Check) []Check {
	byKey := make(map[string]*Check, len(checks))
	keys := make([]string, 0, len(checks))
	for i := range checks {
		c := checks[i]
		existing, ok := byKey[c.Key]
		if !ok {
			copied := c
			byKey[c.Key] = &copied
			keys = append(keys, c.Key)
			continue
		}
		existing.Roles = appendMissing(existing.Roles, c.Roles)
	}
	sort.Strings(keys)
	out := make([]Check, 0, len(keys))
	for _, k := range keys {
		out = append(out, *byKey[k])
	}
	return out
}

func appendMissing(dst, src []string) []string {
	for _, s := range src {
		found := slices.Contains(dst, s)
		if !found {
			dst = append(dst, s)
		}
	}
	return dst
}

// boundRole is the minimal shape needed to decide whether a stored role belongs
// to a set and should be probed. Every plugin's role type is a superset of it.
type boundRole struct {
	Name      string `json:"name"`
	MinterSet string `json:"minter_set"`
	Disabled  bool   `json:"disabled"`
}

// RolesBoundTo returns every enabled role bound to setName, sorted by name.
// Disabled roles are excluded: they cannot issue, so an incapable minter cannot
// hurt them, and probing them would block a set write over a role the operator
// has already turned off.
func RolesBoundTo(ctx context.Context, storage logical.Storage, setName string) ([]BoundRole, error) {
	names, err := storage.List(ctx, rolesPrefix)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	bound := make([]BoundRole, 0, len(names))
	for _, name := range names {
		entry, err := storage.Get(ctx, rolesPrefix+name)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			continue
		}
		var probe boundRole
		if err := json.Unmarshal(entry.Value, &probe); err != nil {
			// An unparseable role cannot be probed, but it also cannot issue, so
			// treating it as "not bound" is safe rather than blocking set writes.
			continue
		}
		if probe.Disabled || probe.MinterSet != setName {
			continue
		}
		bound = append(bound, BoundRole{Name: probe.Name, Raw: entry.Value})
	}
	return bound, nil
}

// probeSeq disambiguates two probes minted inside the same nanosecond.
var probeSeq atomic.Uint64

// ProbeName returns a unique name for a throwaway probe credential.
//
// ownerPrefix must be THIS mount's prefix (ownertag.Prefix), so that a probe whose own
// delete failed is reclaimed by the mount that created it and by no other. Probe
// credentials are never recorded in lease tracking, so the reconciler sees them as
// orphans by construction — which is the point, and which is also why the prefix has
// to be instance-scoped (A19 in docs/audit-2026-08-22.md).
func ProbeName(ownerPrefix, role string) string {
	return ownerPrefix + role + "-" + ProbeSuffix()
}

// ProbeSuffix is the unique, self-identifying tail of a probe name, exposed
// separately for clouds that cap a credential name and must therefore assemble
// the name themselves (see ownertag.FitName, which shortens the role rather than
// this suffix — truncating the tail would make two concurrent probes collide).
func ProbeSuffix() string {
	return "probe-" +
		strconv.FormatInt(time.Now().UnixNano(), 36) +
		strconv.FormatUint(probeSeq.Add(1), 36)
}
