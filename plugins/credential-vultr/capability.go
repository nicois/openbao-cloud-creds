package credentialvultr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Capability verification for Vultr.
//
// CheckHealth reads the account, which any live API key can do. Issuance instead
// creates a sub-user with a specific ACL list, and Vultr refuses to grant a
// sub-user an ACL the creating key does not itself hold — so a minter can be
// healthy, and hold most of a role's ACLs, and still fail that role's first read.
// The probe creates a sub-user with the role's exact ACL list and deletes it.
//
// The mint shape is the ACL list plus the email domain (both reach the create
// call), so roles that would produce an identical request share one probe.

// capabilityChecks builds the probes proving each active minter in the set can
// create a sub-user with the role's ACLs.
func (b *backend) capabilityChecks(set *cloudconfig.MinterSet, roleJSON []byte) []capability.Check {
	var role vultrRole
	if err := json.Unmarshal(roleJSON, &role); err != nil {
		return nil
	}
	shape := strings.Join(role.ACLs, ",") + "|" + role.EmailDomain
	return capability.ChecksPerMinter(set, role.Name, shape, func(minter cloudconfig.Minter) func(context.Context) (int, error) {
		return b.probeMint(minter, &role)
	})
}

// probeMint returns a probe that creates a sub-user with the role's ACLs and
// deletes it. A failed delete does not fail the probe — minting is what was being
// proved, and the probe sub-user carries the owner prefix in its name so the
// reconciler reclaims it.
func (b *backend) probeMint(minter cloudconfig.Minter, role *vultrRole) func(context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		client := b.clientForMinter(minter)
		// The probe name carries the owner prefix, and the email is formed from it
		// in the role's own domain, so the request differs from a real issuance only
		// in the identifier — the ACL list, which is what Vultr checks, is identical.
		probeName := capability.ProbeName(ownertag.Prefix(b.ownerInstance()), role.Name)
		email := probeName + "@" + emailDomainFor(role)
		user, status, err := client.CreateUser(ctx, probeName, email, role.ACLs)
		if err != nil {
			return status, fmt.Errorf("probe sub-user creation with acls %v returned %d: %w", role.ACLs, status, err)
		}
		if delStatus, delErr := client.DeleteUser(ctx, user.User.ID); delErr != nil && delStatus != http.StatusNotFound {
			b.Logger().Warn("capability probe sub-user could not be deleted; left for the owner-tag reconciler",
				fieldCloud, cloudName, "user_id", user.User.ID, "status", delStatus, "error", delErr)
		}
		return status, nil
	}
}

// clientForMinter builds a client authenticating AS the given minter's key.
func (b *backend) clientForMinter(m cloudconfig.Minter) *vultrClient {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return newVultrClient(b.vultrAPIURL(), m.Token)
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
// being able to mint what it asks for. On Vultr that is what catches a role whose
// ACL list exceeds what the set's minters can delegate.
func (b *backend) verifyRoleCapability(ctx context.Context, storage logical.Storage, role *vultrRole) *logical.Response {
	// Resolve the owner instance while we still have storage: the probe closure
	// runs later and only has a context, and its credential name must carry THIS
	// mount's prefix so a failed delete is reclaimable by us and nobody else (A19).
	if _, err := b.ownerInstanceID(ctx, storage); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err)
	}
	return b.gate().VerifyRole(ctx, storage, role.MinterSet, capability.RoleJSON(role), b.capabilityChecks)
}

// gate snapshots the operator's verification setting for this backend. Vultr has
// no rotation successor to verify — pathMinterSetRotate always rejects, because
// sub-user API keys cannot be self-rotated headlessly.
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
