package credentialoci

import (
	"context"
	"encoding/json"

	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Capability verification for OCI: not performed, deliberately.
//
// Every other plugin proves a minter can mint by minting a throwaway credential
// and deleting it. On OCI that probe is the very thing the phased-rotation
// strategy exists to avoid: OCI caps a user at TWO auth tokens, which is why this
// plugin pre-provisions N=2 slots and rotates them on a schedule instead of
// minting per read. A probe would have to consume one of those two tokens, so it
// would either fail (both slots already provisioned — the steady state) or, worse,
// succeed by displacing a slot a live lease is drawing from. Verifying capability
// would therefore break issuance to prove issuance works.
//
// OCI does not need it as urgently either: slot provisioning is itself a real
// create-auth-token call made at role write / rotation time, so an incapable
// minter surfaces as a failed provision to the operator who configured it —
// which is the outcome probes buy elsewhere. The checks below return
// capability.ErrUnsupported, which Verify counts as skipped rather than failed,
// so the set/role write proceeds and the operator-facing log records the skip.

// capabilityChecks reports one skipped check per active minter: OCI cannot be
// probed (see the package comment above), so its capability is taken on trust.
func (b *backend) capabilityChecks(set *cloudconfig.MinterSet, roleJSON []byte) []capability.Check {
	var role ociRole
	if err := json.Unmarshal(roleJSON, &role); err != nil {
		return nil
	}
	return capability.ChecksPerMinter(set, role.Name, "", func(_ cloudconfig.Minter) func(context.Context) error {
		return func(_ context.Context) error { return capability.ErrUnsupported }
	})
}

// verifySetCapability is the uniform minter-set-write hook. On OCI it only
// records the skip.
func (b *backend) verifySetCapability(ctx context.Context, storage logical.Storage, set *cloudconfig.MinterSet) *logical.Response {
	return b.gate().VerifySet(ctx, storage, set, b.capabilityChecks)
}

// verifyRoleCapability is the uniform role-write hook. On OCI it only records the
// skip — but it still enforces the shared precondition that the named minter set
// exists before a role may bind to it.
func (b *backend) verifyRoleCapability(ctx context.Context, storage logical.Storage, role *ociRole) *logical.Response {
	return b.gate().VerifyRole(ctx, storage, role.MinterSet, capability.RoleJSON(role), b.capabilityChecks)
}

// gate snapshots the operator's verification setting for this backend.
func (b *backend) gate() capability.Gate {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return capability.Gate{Cloud: cloudName, Logger: b.Logger(), Enabled: b.config.CapabilityVerificationEnabled()}
}
