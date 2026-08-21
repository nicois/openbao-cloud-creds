package credentialazure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Capability verification for Azure.
//
// A service principal that can fetch a Graph token is not necessarily one that
// can add a password to a given app registration: addPassword needs
// Application.ReadWrite.OwnedBy plus ownership of *that* application (or
// Application.ReadWrite.All). CheckHealth only reads the application, so a
// minter with read-but-not-write rights — or one owning a different app than the
// role names — passes it and still cannot mint. The probe adds a short-lived
// password with the role's own app_object_id and removes it again, which is the
// only way to establish the write right for that specific application.
//
// This is also what makes a rotation successor trustworthy: the successor secret
// is minted on one app registration, but the set's roles may name several. See
// pathMinterSetRotate.

// probePasswordLifetime is the endDateTime given to a probe password. It is
// deleted immediately; the lifetime only has to be in the future for Graph to
// accept it, and short enough to be harmless if the delete fails.
const probePasswordLifetime = 10 * time.Minute

// capabilityChecks builds the probes proving each active minter in the set can
// add a password to the app registration one stored role names. The dedup key is
// the minter plus that app object ID: it is the whole of what varies at mint.
func (b *backend) capabilityChecks(set *cloudconfig.MinterSet, roleJSON []byte) []capability.Check {
	var role azureRole
	if err := json.Unmarshal(roleJSON, &role); err != nil {
		return nil
	}
	return capability.ChecksPerMinter(set, role.Name, role.AppObjectID, func(minter cloudconfig.Minter) func(context.Context) error {
		return b.probeMint(minter, role.Name, role.AppObjectID)
	})
}

// probeMint returns a probe that adds a password to the role's app registration
// and removes it. A failed removal does not fail the probe — minting is what was
// being proved, and the probe password carries the owner prefix in its display
// name so the reconciler reclaims it.
func (b *backend) probeMint(minter cloudconfig.Minter, roleName, appObjectID string) func(context.Context) error {
	return func(ctx context.Context) error {
		b.mu.RLock()
		client := b.newClientForMinter(minter)
		b.mu.RUnlock()

		pw, status, err := client.AddPassword(ctx, appObjectID,
			capability.ProbeName(roleName), time.Now().Add(probePasswordLifetime))
		if err != nil {
			return fmt.Errorf("probe addPassword on app %s returned %d: %w", appObjectID, status, err)
		}
		if delStatus, delErr := client.RemovePassword(ctx, appObjectID, pw.KeyID); delErr != nil && delStatus != http.StatusNotFound {
			b.Logger().Warn("capability probe password could not be removed; left for the owner-tag reconciler",
				fieldCloud, cloudName, fieldKeyID, pw.KeyID, "status", delStatus, "error", delErr)
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
func (b *backend) verifyRoleCapability(ctx context.Context, storage logical.Storage, role *azureRole) *logical.Response {
	return b.gate().VerifyRole(ctx, storage, role.MinterSet, capability.RoleJSON(role), b.capabilityChecks)
}

// verifySuccessorCapability gates a rotation commit on the successor being able
// to mint for every role bound to the set — not merely on it being live.
func (b *backend) verifySuccessorCapability(ctx context.Context, storage logical.Storage, setName string, successor cloudconfig.Minter) *logical.Response {
	return b.gate().VerifySuccessor(ctx, storage, setName, successor, b.capabilityChecks)
}

// gate snapshots the operator's verification setting for this backend.
func (b *backend) gate() capability.Gate {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return capability.Gate{Cloud: cloudName, Logger: b.Logger(), Enabled: b.config.CapabilityVerificationEnabled()}
}
