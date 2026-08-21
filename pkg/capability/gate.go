package capability

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
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
		return logical.ErrorResponse("could not enumerate the roles bound to minter set %q: %v", set.Name, err)
	}
	var all []Check
	for i := range roles {
		all = append(all, checks(set, roles[i].Raw)...)
	}
	return g.run(ctx, all)
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
func (g Gate) VerifyRole(ctx context.Context, storage logical.Storage, setName string, roleJSON []byte, checks ChecksFunc) *logical.Response {
	if !g.Enabled {
		return nil
	}
	set, err := LoadMinterSet(ctx, storage, setName)
	if err != nil {
		return logical.ErrorResponse("could not load minter set %q: %v", setName, err)
	}
	if set == nil {
		return logical.ErrorResponse("minter_set %q does not exist", setName)
	}
	return g.run(ctx, checks(set, roleJSON))
}

// run executes the probes and renders the outcome.
func (g Gate) run(ctx context.Context, checks []Check) *logical.Response {
	result, err := Verify(ctx, checks)
	if err != nil {
		if g.Logger != nil {
			g.Logger.Warn("minter capability verification failed", "cloud", g.Cloud, "error", err)
		}
		return logical.ErrorResponse("minter capability verification failed: %v"+skipHint, err)
	}
	if g.Logger != nil && (result.Ran > 0 || result.Skipped > 0) {
		g.Logger.Info("minter capability verified", "cloud", g.Cloud,
			"probes", result.Ran, "skipped", result.Skipped)
	}
	return nil
}

// ChecksPerMinter builds one Check per active minter in the set. Every active
// minter is probed, not just one: minter selection picks arbitrarily among the
// selectable minters of a set, so a single incapable minter makes issuance fail
// intermittently rather than not at all. shape describes the mint request (the
// role fields that reach the cloud) and forms the dedup key together with the
// minter ID; run builds the probe for one minter.
func ChecksPerMinter(set *cloudconfig.MinterSet, roleName, shape string, run func(cloudconfig.Minter) func(context.Context) error) []Check {
	active := cloudconfig.ActiveMinters(set.Minters)
	checks := make([]Check, 0, len(active))
	for i := range active {
		minter := active[i]
		checks = append(checks, Check{
			Key:    minter.ID + "|" + shape,
			Minter: minter.ID,
			Roles:  []string{roleName},
			Run:    run(minter),
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
func RoleJSON(role interface{}) []byte {
	raw, err := json.Marshal(role)
	if err != nil {
		return nil
	}
	return raw
}
