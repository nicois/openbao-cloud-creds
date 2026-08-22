package credentialexoscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Capability verification for Exoscale.
//
// CheckHealth reads /v2/zone, which any live API key can do. Creating a key
// bound to a role, by contrast, needs the minter's own IAM role to permit
// api-key creation AND to be allowed to grant the specific role-id a credential
// role names — a key can be perfectly healthy and still be refused on either
// count. The probe creates a key with the role's own role-id and deletes it,
// which is the only way to establish both at configuration time.
//
// The mint shape is the role-id: two roles naming the same role-id produce the
// same mint request and share one probe.

// capabilityChecks builds the probes proving each active minter in the set can
// create an API key bound to the role's role-id.
func (b *backend) capabilityChecks(set *cloudconfig.MinterSet, roleJSON []byte) []capability.Check {
	var role exoscaleRole
	if err := json.Unmarshal(roleJSON, &role); err != nil {
		return nil
	}
	return capability.ChecksPerMinter(set, role.Name, role.RoleID, func(minter cloudconfig.Minter) func(context.Context) (int, error) {
		return b.probeMint(minter, role.Name, role.RoleID)
	})
}

// probeMint returns a probe that creates an API key for roleID and deletes it. A
// failed delete does not fail the probe — minting is what was being proved, and
// the probe key carries the owner prefix in its name so the reconciler reclaims
// it.
func (b *backend) probeMint(minter cloudconfig.Minter, roleName, roleID string) func(context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		client := b.newClientForMinter(minter)
		key, status, err := client.CreateAPIKey(ctx, capability.ProbeName(ownertag.Prefix(b.ownerInstance()), roleName), roleID)
		if err != nil {
			return status, fmt.Errorf("probe api-key creation for role-id %s returned %d: %w", roleID, status, err)
		}
		if delStatus, delErr := client.DeleteAPIKey(ctx, key.KeyID); delErr != nil && delStatus != http.StatusNotFound {
			b.Logger().Warn("capability probe api-key could not be deleted; left for the owner-tag reconciler",
				fieldCloud, cloudName, "key_id", key.KeyID, "status", delStatus, "error", delErr)
		}
		return status, nil
	}
}

// verifySetCapability gates a minter-set write on every active minter being able
// to mint for every role already bound to the set.
func (b *backend) verifySetCapability(ctx context.Context, storage logical.Storage, set *cloudconfig.MinterSet) *logical.Response {
	// Resolve the owner instance while we still have storage: the probe closure
	// runs later and only has a context, and its credential name must carry THIS
	// mount's prefix so a failed delete is reclaimable by us and nobody else (A19).
	if _, err := b.ownerInstanceID(ctx, storage); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err)
	}
	return b.gate().VerifySet(ctx, storage, set, b.capabilityChecks)
}

// verifyRoleCapability gates a role write on the minters of the set it binds to
// being able to mint what it asks for.
func (b *backend) verifyRoleCapability(ctx context.Context, storage logical.Storage, role *exoscaleRole) *logical.Response {
	// Resolve the owner instance while we still have storage: the probe closure
	// runs later and only has a context, and its credential name must carry THIS
	// mount's prefix so a failed delete is reclaimable by us and nobody else (A19).
	if _, err := b.ownerInstanceID(ctx, storage); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err)
	}
	return b.gate().VerifyRole(ctx, storage, role.MinterSet, capability.RoleJSON(role), b.capabilityChecks)
}

// verifySuccessorCapability gates a rotation commit on the successor being able
// to mint for every bound role — the successor's key-management role is granted
// at mint time, so "live" does not imply "can still grant these role-ids".
func (b *backend) verifySuccessorCapability(ctx context.Context, storage logical.Storage, setName string, successor cloudconfig.Minter) *logical.Response {
	// Resolve the owner instance while we still have storage: the probe closure
	// runs later and only has a context, and its credential name must carry THIS
	// mount's prefix so a failed delete is reclaimable by us and nobody else (A19).
	if _, err := b.ownerInstanceID(ctx, storage); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err)
	}
	return b.gate().VerifySuccessor(ctx, storage, setName, successor, b.capabilityChecks)
}

// gate snapshots the operator's verification settings for this backend, and hands
// the probes the two things they used to lack: the read path's rate-limit state,
// and a memory of what has recently been proved (A29).
func (b *backend) gate() capability.Gate {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return capability.Gate{
		Cloud:    cloudName,
		Logger:   b.Logger(),
		Enabled:  b.config.CapabilityVerificationEnabled(),
		Limiter:  &capability.Limiter{States: b.minterStateByID},
		CacheTTL: b.config.CapabilityCacheDuration(),
	}
}

// minterStateByID finds a minter's recovery state machine by id, across every set,
// so a probe can see (and open) the same rate-limit cooldown issuance uses. A
// candidate minter being written for the first time has no state yet; nil then
// means "unthrottled as far as we know", which is the only honest answer.
func (b *backend) minterStateByID(minterID string) *recovery.StateMachine {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, states := range b.minterSets {
		if ms, ok := states[minterID]; ok {
			return ms.sm
		}
	}
	return nil
}
