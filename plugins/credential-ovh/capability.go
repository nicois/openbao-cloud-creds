package credentialovh

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Capability verification for OVH.
//
// OVH is the one JIT cloud where minting is the ONLY upstream operation: a
// credential is an OAuth2 client_credentials access token, and the role carries
// nothing that reaches the token request (its scopes come from the OVH IAM policy
// attached to the service account itself). So the probe is a MintToken call — the
// same call the health check makes — and it dedupes to one probe per minter
// regardless of how many roles the set serves.
//
// The probe therefore proves less new information here than elsewhere, but it
// still enforces the uniform guarantee: a role cannot be bound to a set whose
// minters have not been shown to mint, and a minter set cannot be written with a
// replacement credential that does not work, without waiting for a background
// health check to notice.
//
// Cost, accepted deliberately: OVH tokens cannot be revoked, so each probe leaves
// one 1h access token in existence that nobody holds. It is never returned to a
// caller and is not recorded in any lease. Operators who cannot accept that set
// verify_minter_capability=false.

// capabilityChecks builds the probes proving each active minter in the set can
// mint a token. The mint shape is empty: OVH takes no role-specific input.
func (b *backend) capabilityChecks(set *cloudconfig.MinterSet, roleJSON []byte) []capability.Check {
	var role ovhRole
	if err := json.Unmarshal(roleJSON, &role); err != nil {
		return nil
	}
	return capability.ChecksPerMinter(set, role.Name, "", func(minter cloudconfig.Minter) func(context.Context) (int, error) {
		return b.probeMint(minter)
	})
}

// probeMint returns a probe that mints an access token. There is nothing to clean
// up: OVH exposes no token-revocation API, so the token simply expires.
func (b *backend) probeMint(minter cloudconfig.Minter) func(context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		b.mu.RLock()
		client := b.buildTokenClient(minter)
		b.mu.RUnlock()
		if _, _, err := client.MintToken(ctx); err != nil {
			return classifyOVHError(err), fmt.Errorf("probe token mint failed: %w", err)
		}
		return http.StatusOK, nil
	}
}

// verifySetCapability gates a minter-set write on every active minter being able
// to mint for every role already bound to the set.
func (b *backend) verifySetCapability(ctx context.Context, storage logical.Storage, set *cloudconfig.MinterSet) *logical.Response {
	return b.gate().VerifySet(ctx, storage, set, b.capabilityChecks)
}

// verifyRoleCapability gates a role write on the minters of the set it binds to
// being able to mint.
func (b *backend) verifyRoleCapability(ctx context.Context, storage logical.Storage, role *ovhRole) *logical.Response {
	return b.gate().VerifyRole(ctx, storage, role.MinterSet, capability.RoleJSON(role), b.capabilityChecks)
}

// gate snapshots the operator's verification setting for this backend. OVH has no
// rotation successor to verify — pathMinterSetRotate always rejects, because OVH
// exposes no API for a service account to replace its own secret.
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
