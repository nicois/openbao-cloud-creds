package credentialgcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Capability verification for GCP.
//
// The health check (TestConnection) exchanges the minter service account's own
// self-signed JWT for an access token. Every enabled SA with a valid key can do
// that: it proves the key is live and the SA exists, nothing more. Impersonation
// is a separate grant — the minter needs
// roles/iam.serviceAccountTokenCreator ON THE TARGET service account, per target,
// and generateAccessToken also fails when a requested scope is not permitted or
// the target SA is disabled. All of those are per-role facts a healthy minter can
// fail, surfacing only as a 403 on a caller's credential read.
//
// The probe is a generateAccessToken for the role's own target SA and scopes,
// with the shortest lifetime worth asking for. Nothing is deleted afterwards:
// GCP access tokens cannot be revoked, so the probe deliberately leaves a token
// that expires by itself. It is never returned to a caller and never recorded in
// a lease.

// probeTokenLifetime is the lifetime a probe access token asks for. It is not
// returned to anyone, so it only has to be long enough for GCP to accept the
// request.
const probeTokenLifetime = 60 * time.Second

// capabilityChecks builds the probes proving each active minter in the set can
// impersonate the target service account one stored role names. The dedup key is
// the minter plus the target SA and its scopes: both reach generateAccessToken
// and either can be refused on its own.
func (b *backend) capabilityChecks(set *cloudconfig.MinterSet, roleJSON []byte) []capability.Check {
	var role gcpRole
	if err := json.Unmarshal(roleJSON, &role); err != nil {
		return nil
	}
	shape := role.ServiceAccountEmail + "|" + strings.Join(role.Scopes, " ")
	return capability.ChecksPerMinter(set, role.Name, shape, func(minter cloudconfig.Minter) func(context.Context) (int, error) {
		return b.probeMint(minter, &role)
	})
}

// probeMint returns a probe that mints an impersonated access token for the
// role's target service account. There is nothing to clean up: GCP has no token
// revocation, which is why the lifetime asked for is the shortest useful one
// rather than the role's TTL.
func (b *backend) probeMint(minter cloudconfig.Minter, role *gcpRole) func(context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		b.mu.RLock()
		client := b.buildIAMClient(minter)
		b.mu.RUnlock()

		if _, _, err := client.GenerateAccessToken(ctx, role.ServiceAccountEmail, role.Scopes, probeTokenLifetime); err != nil {
			return classifyGCPError(err), fmt.Errorf("probe generateAccessToken for %s failed: %w", role.ServiceAccountEmail, err)
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
// being able to impersonate what it names.
func (b *backend) verifyRoleCapability(ctx context.Context, storage logical.Storage, role *gcpRole) *logical.Response {
	return b.gate().VerifyRole(ctx, storage, role.MinterSet, capability.RoleJSON(role), b.capabilityChecks)
}

// verifySuccessorCapability gates a rotation commit on the successor being able
// to mint for every role bound to the set. A rotated key belongs to the same
// service account and so normally carries the same grants, but TestConnection
// only proves the new key authenticates — it cannot see a tokenCreator binding
// that has since been removed from a target SA, which would leave the set with a
// healthy minter that no role can use.
func (b *backend) verifySuccessorCapability(ctx context.Context, storage logical.Storage, setName string, successor cloudconfig.Minter) *logical.Response {
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
