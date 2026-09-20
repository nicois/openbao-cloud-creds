package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// minterSetPrefix is the storage prefix every plugin stores its minter sets
// under.
const minterSetPrefix = "minter-sets/"

// skipHint tells an operator how to turn verification off, so a probe that
// cannot succeed in their environment is not a dead end.
const skipHint = " (set verify_minter_capability=false on the config endpoint to skip this check)"

// ChecksFunc is the only cloud-specific part of verification: given a candidate
// minter set and one role's stored JSON, it returns the probes proving that
// set's minters can mint what that role asks for. Roles are handed over as
// stored JSON so this package never needs to know any cloud's role schema — and
// so the probe exercises exactly the representation that will be persisted.
type ChecksFunc func(set *cloudconfig.MinterSet, roleJSON []byte) []Check

// probeFanOutNoticeThreshold is the number of distinct probes in one write above
// which the count is logged.
//
// There is deliberately no hard CAP. A cap large enough for a legitimate set (five
// minters across thirty roles) would never fire, and one small enough to fire would
// block that set from ever being written except by turning verification off
// entirely — trading a cost problem for a security one. Dedupe plus the cache is
// what actually bounds the cost; this line is so an operator can SEE a fan-out
// they did not intend, which is the case a cap was really aimed at.
const probeFanOutNoticeThreshold = 20

// Gate is the config-time capability check shared by every plugin: it turns a
// set of probes into either nil (proceed with the write) or an operator-facing
// error response (reject it).
type Gate struct {
	// Cloud identifies the plugin in log lines.
	Cloud string
	// Logger receives the pass/fail record; may be nil.
	Logger hclog.Logger
	// Enabled is false when the operator has set verify_minter_capability=false,
	// in which case every Verify* method is a no-op.
	Enabled bool
	// Limiter shares the issuance path's rate-limit state with the probes; nil
	// leaves probes outside the circuit breaker.
	Limiter *Limiter
	// CacheTTL is how long a successful probe stands in for a fresh one; zero
	// disables the cache. See DefaultCacheTTL for the trade this makes.
	CacheTTL time.Duration
}

// VerifySet proves every active minter in a candidate set can mint for every
// enabled role already bound to that set. Call it before persisting the set, so
// a replacement minter that authenticates but cannot mint is rejected rather
// than silently becoming the set every bound role draws from.
func (g Gate) VerifySet(ctx context.Context, storage logical.Storage, set *cloudconfig.MinterSet, checks ChecksFunc) *logical.Response {
	if !g.Enabled {
		return nil
	}
	roles, err := RolesBoundTo(ctx, storage, set.Name)
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrInternal, "could not enumerate the roles bound to minter set %q: %v", set.Name, err)
	}
	var all []Check
	for i := range roles {
		all = append(all, checks(set, roles[i].Raw)...)
	}
	return g.run(ctx, storage, all)
}

// VerifySuccessor proves a rotation successor can mint everything the set's
// bound roles need, before it is swapped in. A health check cannot: it proves
// the successor is live, not that it inherited the privileges its predecessor
// held, and on clouds where a successor's grants are constructed rather than
// inherited the two differ.
func (g Gate) VerifySuccessor(ctx context.Context, storage logical.Storage, setName string, successor cloudconfig.Minter, checks ChecksFunc) *logical.Response {
	return g.VerifySet(ctx, storage, &cloudconfig.MinterSet{
		Name:    setName,
		Minters: []cloudconfig.Minter{successor},
	}, checks)
}

// VerifyRole proves the minters of the set a role is being bound to can mint
// what that role asks for. Call it before persisting the role: this is what stops
// an operator defining a role whose minting key is unsuitable, and it also means
// a set must exist and be capable before roles can be attached to it.
//
// A DISABLED role is not probed. It asks nothing of a minter, and the write that
// disables one is the write most likely to be made while the cloud is refusing us —
// a compromised minter, a revoked key, an account locked out — so a probe standing
// in front of it would make the containment lever fail exactly when it is needed. A
// set write excludes disabled roles for the same reason (RolesBoundTo).
//
// Nor is an enabled role probed against a minter already known to be failing
// authentication. The probe would spend a login on an account that is refusing us,
// which on a cloud that locks out after a few attempts is how the remaining attempts
// get burned while the operator is still enabling roles one at a time.
func (g Gate) VerifyRole(ctx context.Context, storage logical.Storage, setName string, roleJSON []byte, checks ChecksFunc) *logical.Response {
	if !g.Enabled || disabledRole(roleJSON) {
		return nil
	}
	set, err := LoadMinterSet(ctx, storage, setName)
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrInternal, "could not load minter set %q: %v", setName, err)
	}
	if set == nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_set %q does not exist", setName)
	}
	if refusal := g.refuseLoginRejected(set); refusal != nil {
		return refusal
	}
	return g.run(ctx, storage, checks(set, roleJSON))
}

// refuseLoginRejected rejects the write when any minter the probe would use has had a login
// rejected since its last success, naming which one.
//
// ANY rather than ALL, because the probe fans out to every active minter in the set:
// one member with a rejected login is one wasted login however healthy its siblings are.
//
// This is deliberately not symmetric with a set write. The rejected-login count clears
// only on a success, so gating the set write too would make a failed
// minter unrepairable — the operator's fix is to write a working credential under the
// same minter id, and that write is exactly what would be refused. Role writes have
// no such problem: nothing about a role changes a credential.
func (g Gate) refuseLoginRejected(set *cloudconfig.MinterSet) *logical.Response {
	active := cloudconfig.ActiveMinters(set.Minters)
	for i := range active {
		failing := g.Limiter.loginRejected(active[i].ID)
		if failing == nil {
			continue
		}
		if g.Logger != nil {
			g.Logger.Warn("capability verification refused: the minter is failing authentication",
				"cloud", g.Cloud, "minter_id", failing.Minter,
				"consecutive_auth_failures", failing.Failures)
		}
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed,
			"minter capability verification could not run: %v. Repair or retire that minter "+
				"before enabling roles bound to it; a minter-set write is not gated on this, so "+
				"replacing its credential is the way out", failing)
	}
	return nil
}

// disabledRole reports whether the role being written is turned off. An unparseable
// role reads as enabled, so it is probed: that is the safe direction, since the only
// cost is a probe and the alternative is a malformed role skipping verification.
func disabledRole(roleJSON []byte) bool {
	var probe boundRole
	if err := json.Unmarshal(roleJSON, &probe); err != nil {
		return false
	}
	return probe.Disabled
}

// run executes the probes and renders the outcome.
func (g Gate) run(ctx context.Context, storage logical.Storage, checks []Check) *logical.Response {
	if n := len(Dedupe(checks)); n > probeFanOutNoticeThreshold && g.Logger != nil {
		g.Logger.Info("capability verification will mint a large number of probe credentials",
			"cloud", g.Cloud, "probes", n,
			"note", "each probe is a real mint against the cloud; a recent identical probe is "+
				"reused for capability_cache_ttl")
	}
	runner := Runner{
		Limiter: g.Limiter,
		Cache:   &Cache{Storage: storage, TTL: g.CacheTTL},
	}
	result, err := runner.Verify(ctx, checks)
	if err != nil {
		return g.renderFailure(err)
	}
	if g.Logger != nil && (result.Ran > 0 || result.Skipped > 0 || result.Cached > 0) {
		g.Logger.Info("minter capability verified", "cloud", g.Cloud,
			"probes", result.Ran, "skipped", result.Skipped, "cached", result.Cached)
	}
	return nil
}

// renderFailure turns a verification error into the response the caller sees. The
// three cases are deliberately distinct: a cooldown is "ask again", a *Failure is a
// verdict on the minter, and anything else is ours.
func (g Gate) renderFailure(err error) *logical.Response {
	if throttled, ok := errors.AsType[*Throttled](err); ok {
		if g.Logger != nil {
			g.Logger.Warn("capability verification deferred by a rate-limit cooldown",
				"cloud", g.Cloud, "minter_id", throttled.Minter, "retry_in", throttled.RetryIn)
		}
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamQuotaExceeded,
			"minter capability verification could not run: %v", throttled)
	}
	// The full error, upstream body and all, goes to the operator's log; the caller
	// gets identities and a pointer to that log (A4).
	if g.Logger != nil {
		g.Logger.Warn("minter capability verification failed", "cloud", g.Cloud, "error", err)
	}
	if failure, ok := errors.AsType[*Failure](err); ok {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"minter capability verification failed: %s"+skipHint, failure.ClientMessage())
	}
	return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
		"minter capability verification failed"+skipHint)
}

// ChecksPerMinter builds one Check per active minter in the set. Every active
// minter is probed, not just one: minter selection picks arbitrarily among the
// selectable minters of a set, so a single incapable minter makes issuance fail
// intermittently rather than not at all. shape describes the mint request (the
// role fields that reach the cloud) and forms the dedup key together with the
// minter ID; run builds the probe for one minter.
func ChecksPerMinter(set *cloudconfig.MinterSet, roleName, shape string, run func(cloudconfig.Minter) func(context.Context) (int, error)) []Check {
	active := cloudconfig.ActiveMinters(set.Minters)
	checks := make([]Check, 0, len(active))
	for i := range active {
		minter := active[i]
		// A minter that will not marshal simply gets no fingerprint, and an
		// unfingerprintable check is never cached — so the probe runs, which is the
		// safe direction.
		raw, _ := json.Marshal(minter)
		checks = append(checks, Check{
			Key:        minter.ID + "|" + shape,
			Minter:     minter.ID,
			Roles:      []string{roleName},
			Run:        run(minter),
			MinterJSON: raw,
		})
	}
	return checks
}

// LoadMinterSet reads a stored minter set. A missing set yields (nil, nil).
func LoadMinterSet(ctx context.Context, storage logical.Storage, name string) (*cloudconfig.MinterSet, error) {
	entry, err := storage.Get(ctx, minterSetPrefix+name)
	if err != nil || entry == nil {
		return nil, err
	}
	var set cloudconfig.MinterSet
	if err := json.Unmarshal(entry.Value, &set); err != nil {
		return nil, fmt.Errorf("stored minter set %q is unparseable: %w", name, err)
	}
	return &set, nil
}

// RoleJSON marshals a plugin's role value into the stored representation that
// ChecksFunc receives, so the role-write path can verify the exact shape it is
// about to persist.
func RoleJSON(role any) []byte {
	raw, err := json.Marshal(role)
	if err != nil {
		return nil
	}
	return raw
}
