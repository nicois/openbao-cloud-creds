package credentialdo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Capability verification for DigitalOcean.
//
// A DO PAT that authenticates is not necessarily a PAT that can mint: scopes are
// fixed at creation, DO refuses to let a token confer privileges its creator
// lacks, and there is no scope-introspection API — so the only way to learn
// whether a minter can serve a role is to ask it to. Each probe creates a token
// with the role's exact scope string and deletes it again. This matters most on
// DO, the one cloud whose minters must be replaced by hand: nothing else in the
// plugin would notice that a hand-pasted replacement PAT is under-scoped.

// capabilityChecks builds the probes proving each active minter in the set can
// mint what one stored role asks for. The dedup key is the minter plus the role's
// scope string, which is the whole of what reaches DO's mint call.
func (b *backend) capabilityChecks(set *cloudconfig.MinterSet, roleJSON []byte) []capability.Check {
	var role doRole
	if err := json.Unmarshal(roleJSON, &role); err != nil {
		return nil
	}
	apiURL := b.apiURLLocked()
	return capability.ChecksPerMinter(set, role.Name, role.Scopes, func(minter cloudconfig.Minter) func(context.Context) error {
		return b.probeMint(apiURL, minter, role.Name, role.Scopes)
	})
}

// probeMint returns a probe that mints a token with the role's scopes and
// deletes it. A failed delete does not fail the probe — minting is what was
// being proved, and the probe token carries the owner prefix so the reconciler
// reclaims it.
func (b *backend) probeMint(apiURL string, minter cloudconfig.Minter, roleName, scopes string) func(context.Context) error {
	return func(ctx context.Context) error {
		client := newDOClient(apiURL, minter.Token)
		resp, status, err := client.CreateToken(ctx, capability.ProbeName(roleName), strings.Split(scopes, ","))
		if err != nil {
			return fmt.Errorf("probe mint returned %d: %w", status, err)
		}
		if delStatus, delErr := client.DeleteToken(ctx, resp.Token.ID); delErr != nil && delStatus != http.StatusNotFound {
			b.Logger().Warn("capability probe token could not be deleted; left for the owner-tag reconciler",
				fieldCloud, cloudName, "token_id", resp.Token.ID, "status", delStatus, "error", delErr)
		}
		return nil
	}
}

// verifySetCapability gates a minter-set write on every active minter being able
// to mint for every role already bound to the set.
func (b *backend) verifySetCapability(ctx context.Context, storage logical.Storage, set *cloudconfig.MinterSet) *logical.Response {
	return b.gate().VerifySet(ctx, storage, set, b.capabilityChecks)
}

// verifyRoleCapability gates a role write on the minters of the set it binds to
// being able to mint what it asks for.
func (b *backend) verifyRoleCapability(ctx context.Context, storage logical.Storage, role *doRole) *logical.Response {
	return b.gate().VerifyRole(ctx, storage, role.MinterSet, capability.RoleJSON(role), b.capabilityChecks)
}

// gate snapshots the operator's verification setting for this backend.
func (b *backend) gate() capability.Gate {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return capability.Gate{Cloud: cloudName, Logger: b.Logger(), Enabled: b.config.CapabilityVerificationEnabled()}
}

// apiURLLocked returns the configured API base URL, taking the read lock itself.
// doAPIURL requires the caller to already hold b.mu; probe construction does not.
func (b *backend) apiURLLocked() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.doAPIURL()
}
