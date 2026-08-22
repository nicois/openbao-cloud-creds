package credentialdo

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

// Capability verification for DigitalOcean.
//
// A DO PAT that authenticates is not necessarily a PAT that can mint: scopes are
// fixed at creation, DO refuses to let a token confer privileges its creator
// lacks, and there is no scope-introspection API — so the only way to learn
// whether a minter can serve a role is to ask it to. Each probe creates a token
// with the role's exact scope string and deletes it again.
//
// On real DigitalOcean the answer is now known to be "no, for every PAT" (KI-009):
// token management is fenced off at DO's edge gateway. That makes this probe the
// plugin's most useful part against real DO rather than its least — it refuses the
// minter set at WRITE time, with an explanation, instead of letting an operator
// discover at first issue that the cloud will never cooperate.

// forbiddenMintHint is the one diagnosis an operator cannot reach from DO's own
// error, which is a bare "You are not authorized to perform this operation".
//
// Verified against a real account on 2026-08-21 (KI-009): POST /v2/tokens is
// refused 403 for a granular PAT *and* for a full-access one, and the refusal
// comes from DigitalOcean's edge gateway (X-Response-From: Edge-Gateway) rather
// than from a service weighing the token's privileges — while ordinary endpoints
// on the very same token are served normally (X-Response-From: service). Token
// management is therefore closed to bearer-PAT auth as a matter of routing, not
// of authorization, so no PAT and no scope string can pass this probe. DO's own
// message invites an operator to go hunting for the missing privilege; this says
// there isn't one.
const forbiddenMintHint = "the minter PAT is live but token management is refused at DigitalOcean's " +
	"edge gateway, which no privilege changes: a full-access PAT is refused here exactly as a scoped " +
	"one is, and DO's scope catalog has no PAT-management scope to grant. No PAT can mint on DO " +
	"(KI-009 in docs/known-issues.md); credential-do cannot issue against real DigitalOcean"

// capabilityChecks builds the probes proving each active minter in the set can
// mint what one stored role asks for. The dedup key is the minter plus the role's
// scope string, which is the whole of what reaches DO's mint call.
func (b *backend) capabilityChecks(set *cloudconfig.MinterSet, roleJSON []byte) []capability.Check {
	var role doRole
	if err := json.Unmarshal(roleJSON, &role); err != nil {
		return nil
	}
	apiURL := b.apiURLLocked()
	return capability.ChecksPerMinter(set, role.Name, strings.Join(role.Scopes, ","), func(minter cloudconfig.Minter) func(context.Context) (int, error) {
		return b.probeMint(apiURL, minter, role.Name, role.Scopes)
	})
}

// probeMint returns a probe that mints a token with the role's scopes and
// deletes it. A failed delete does not fail the probe — minting is what was
// being proved, and the probe token carries the owner prefix so the reconciler
// reclaims it.
func (b *backend) probeMint(apiURL string, minter cloudconfig.Minter, roleName string, scopes []string) func(context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		client := newDOClient(apiURL, minter.Token)
		resp, status, err := client.CreateToken(ctx, capability.ProbeName(ownertag.Prefix(b.ownerInstance()), roleName), scopes)
		if err != nil {
			if status == http.StatusForbidden {
				return status, fmt.Errorf("probe mint returned %d (%w): %s", status, err, forbiddenMintHint)
			}
			return status, fmt.Errorf("probe mint returned %d: %w", status, err)
		}
		if delStatus, delErr := client.DeleteToken(ctx, resp.Token.ID); delErr != nil && delStatus != http.StatusNotFound {
			b.Logger().Warn("capability probe token could not be deleted; left for the owner-tag reconciler",
				fieldCloud, cloudName, "token_id", resp.Token.ID, "status", delStatus, "error", delErr)
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
func (b *backend) verifyRoleCapability(ctx context.Context, storage logical.Storage, role *doRole) *logical.Response {
	// Resolve the owner instance while we still have storage: the probe closure
	// runs later and only has a context, and its credential name must carry THIS
	// mount's prefix so a failed delete is reclaimable by us and nobody else (A19).
	if _, err := b.ownerInstanceID(ctx, storage); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err)
	}
	return b.gate().VerifyRole(ctx, storage, role.MinterSet, capability.RoleJSON(role), b.capabilityChecks)
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

// apiURLLocked returns the configured API base URL, taking the read lock itself.
// doAPIURL requires the caller to already hold b.mu; probe construction does not.
func (b *backend) apiURLLocked() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.doAPIURL()
}
