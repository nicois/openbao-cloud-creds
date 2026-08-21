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
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// rolesPrefix is the storage prefix every plugin stores its roles under.
const rolesPrefix = "roles/"

// ownerPrefix is the owner-tag prefix the reconciler reclaims by. Probe
// credentials carry it so a probe whose own delete failed is still reclaimable.
const ownerPrefix = "cloud-creds-"

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
	// Run performs the probe mint and deletes what it created.
	Run func(context.Context) error
}

// Result counts what a Verify pass did, for operator-facing logging.
type Result struct {
	// Ran is the number of distinct probes actually attempted.
	Ran int
	// Skipped is the number that reported ErrUnsupported.
	Skipped int
}

// BoundRole is a stored role bound to a minter set. Raw is the role's stored
// JSON, so the caller can decode it into its own per-cloud role type without
// this package knowing any cloud's role schema.
type BoundRole struct {
	Name string
	Raw  []byte
}

// Verify runs each distinct Check once and stops at the first failure, so an
// operator sees the first thing that is wrong rather than a list of cascading
// consequences. The returned error names the minter and the affected roles.
func Verify(ctx context.Context, checks []Check) (Result, error) {
	var result Result
	for _, c := range Dedupe(checks) {
		err := c.Run(ctx)
		switch {
		case err == nil:
			result.Ran++
		case errors.Is(err, ErrUnsupported):
			result.Skipped++
		default:
			return result, fmt.Errorf(
				"minter %q cannot mint the credential role(s) %s require: %w",
				c.Minter, strings.Join(c.Roles, ", "), err)
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
		found := false
		for _, existing := range dst {
			if existing == s {
				found = true
				break
			}
		}
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

// ProbeName returns a unique name for a throwaway probe credential, carrying the
// cloud-creds-<role>- owner prefix so that if the probe's own delete fails the
// owner-tag reconciler still reclaims it. Probe credentials are never recorded
// in lease tracking, so the reconciler sees them as orphans by construction.
func ProbeName(role string) string {
	return ownerPrefix + role + "-probe-" +
		strconv.FormatInt(time.Now().UnixNano(), 36) +
		strconv.FormatUint(probeSeq.Add(1), 36)
}
