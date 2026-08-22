package credentialupcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Capability verification for UpCloud.
//
// An UpCloud API token can authenticate — CheckHealth reads /1.3/account
// successfully — without being able to create further tokens: minting requires
// the token itself to have been created with can_create_tokens. CheckHealth
// cannot see that flag, so a minter (or a rotation successor, or a hand-pasted
// replacement) that lacks it looks healthy and fails at the first issuance. The
// probe creates a token and deletes it, which is the only way to establish the
// mint right.
//
// UpCloud tokens carry no per-role scoping upstream (a role's `scopes` field is
// reported in the envelope, not sent to UpCloud), so the mint request is the same
// for every role and dedupes to one probe per minter.

// probeExpiresIn is the lifetime given to a probe token. It is deleted
// immediately; the value only has to be short enough to be harmless if the
// delete fails.
const probeExpiresIn = 10 * time.Minute

// capabilityChecks builds the probes proving each active minter in the set can
// create tokens. The mint shape is empty: UpCloud takes no role-specific input.
func (b *backend) capabilityChecks(set *cloudconfig.MinterSet, roleJSON []byte) []capability.Check {
	var role upcloudRole
	if err := json.Unmarshal(roleJSON, &role); err != nil {
		return nil
	}
	return capability.ChecksPerMinter(set, role.Name, "", func(minter cloudconfig.Minter) func(context.Context) error {
		return b.probeMint(minter, role.Name)
	})
}

// probeMint returns a probe that creates a token and deletes it. A failed delete
// does not fail the probe — minting is what was being proved, and the probe token
// carries the owner prefix in its name so the reconciler reclaims it.
func (b *backend) probeMint(minter cloudconfig.Minter, roleName string) func(context.Context) error {
	return func(ctx context.Context) error {
		client := b.newClientForMinter(minter)
		tok, status, err := client.CreateToken(ctx, capability.ProbeName(ownertag.Prefix(b.ownerInstance()), roleName), probeExpiresIn.String())
		if err != nil {
			return fmt.Errorf("probe token creation returned %d: %w", status, err)
		}
		if delStatus, delErr := client.DeleteToken(ctx, tok.ID); delErr != nil && delStatus != http.StatusNotFound {
			b.Logger().Warn("capability probe token could not be deleted; left for the owner-tag reconciler",
				fieldCloud, cloudName, "token_id", tok.ID, "status", delStatus, "error", delErr)
		}
		return nil
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
func (b *backend) verifyRoleCapability(ctx context.Context, storage logical.Storage, role *upcloudRole) *logical.Response {
	// Resolve the owner instance while we still have storage: the probe closure
	// runs later and only has a context, and its credential name must carry THIS
	// mount's prefix so a failed delete is reclaimable by us and nobody else (A19).
	if _, err := b.ownerInstanceID(ctx, storage); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err)
	}
	return b.gate().VerifyRole(ctx, storage, role.MinterSet, capability.RoleJSON(role), b.capabilityChecks)
}

// verifySuccessorCapability gates a rotation commit on the successor being able
// to mint — not merely on it being live. On UpCloud that is the difference
// between a successor created with can_create_tokens and one without.
func (b *backend) verifySuccessorCapability(ctx context.Context, storage logical.Storage, setName string, successor cloudconfig.Minter) *logical.Response {
	// Resolve the owner instance while we still have storage: the probe closure
	// runs later and only has a context, and its credential name must carry THIS
	// mount's prefix so a failed delete is reclaimable by us and nobody else (A19).
	if _, err := b.ownerInstanceID(ctx, storage); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err)
	}
	return b.gate().VerifySuccessor(ctx, storage, setName, successor, b.capabilityChecks)
}

// gate snapshots the operator's verification setting for this backend.
func (b *backend) gate() capability.Gate {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return capability.Gate{Cloud: cloudName, Logger: b.Logger(), Enabled: b.config.CapabilityVerificationEnabled()}
}
