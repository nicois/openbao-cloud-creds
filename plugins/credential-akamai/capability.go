package credentialakamai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Capability verification for Akamai.
//
// CheckHealth reads GET /api-clients/self, which any live EdgeGrid credential
// can do — it says nothing about whether that credential may CREATE api clients,
// nor whether it holds the apis and groups a role hands out. Akamai will not let
// an api client grant access it does not itself hold, so a minter provisioned
// with Identity-Management access alone authenticates, reports healthy forever,
// and fails at the first credential read with a 403 on the role's own apiAccess.
//
// The probe creates a throwaway api client using the role's exact apiAccess /
// groupAccess (roleAccess — the same call issuance makes) and deletes it again.
// That is the only way to establish both rights at once: create, and delegate
// this particular grant.
//
// It matters most for rotation. A successor's grants are copied from the
// incumbent's own (see successorGrants); if that copy comes back narrower than
// the incumbent — a group the successor is not authorized for, an api the
// authorizing user has since lost — the successor still passes CheckHealth. The
// probe run before the rotation commits is what catches that.

// capabilityChecks builds the probes proving each active minter in the set can
// create an api client with the grant one stored role asks for. The dedup key is
// the minter plus that grant: apiAccess and groupId are the whole of what
// reaches the upstream create call.
func (b *backend) capabilityChecks(set *cloudconfig.MinterSet, roleJSON []byte) []capability.Check {
	var role akamaiRole
	if err := json.Unmarshal(roleJSON, &role); err != nil {
		return nil
	}
	shape := role.APIAccess + "|" + strconv.Itoa(role.GroupID)
	return capability.ChecksPerMinter(set, role.Name, shape, func(minter cloudconfig.Minter) func(context.Context) (int, error) {
		return b.probeMint(minter, &role)
	})
}

// probeMint returns a probe that creates an api client with the role's grant and
// deletes it. A failed delete does not fail the probe — creation is what was
// being proved, and the probe client's name carries the owner prefix, so the
// reconciler reclaims it (it is an orphan by construction: probe clients are
// never recorded in active-clients).
func (b *backend) probeMint(minter cloudconfig.Minter, role *akamaiRole) func(context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		client, err := b.clientForMinter(minter)
		if err != nil {
			return credenvelope.StatusNone, fmt.Errorf("probe client could not be built: %w", err)
		}
		apiAccess, groupAccess := roleAccess(role)
		created, status, err := client.CreateClient(ctx, capability.ProbeName(ownertag.Prefix(b.ownerInstance()), role.Name), apiAccess, groupAccess)
		if err != nil {
			return status, fmt.Errorf("probe api-client creation returned %d: %w", status, err)
		}
		if delStatus, delErr := client.DeleteClient(ctx, created.ClientID); delErr != nil && delStatus != http.StatusNotFound {
			b.Logger().Warn("capability probe api client could not be deleted; left for the owner-tag reconciler",
				fieldCloud, cloudName, fieldClientID, created.ClientID, "status", delStatus, "error", delErr)
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
func (b *backend) verifyRoleCapability(ctx context.Context, storage logical.Storage, role *akamaiRole) *logical.Response {
	// Resolve the owner instance while we still have storage: the probe closure
	// runs later and only has a context, and its credential name must carry THIS
	// mount's prefix so a failed delete is reclaimable by us and nobody else (A19).
	if _, err := b.ownerInstanceID(ctx, storage); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err)
	}
	return b.gate().VerifyRole(ctx, storage, role.MinterSet, capability.RoleJSON(role), b.capabilityChecks)
}

// verifySuccessorCapability gates a rotation commit on the successor being able
// to mint for every role bound to the set — not merely on it being live.
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
