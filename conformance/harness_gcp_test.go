package conformance

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialgcp "github.com/nicois/openbao-cloud-creds/plugins/credential-gcp"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// GCP mirrors AWS: an in-process IAMCredentialsClient injected per backend, no
// upstream entity to revoke. Impersonation is a per-target-SA grant, so refusing
// generateAccessToken while TestConnection keeps succeeding is exactly the
// "authenticates but cannot mint" shape.
const (
	gcpProjectField = "project"
	gcpProject      = "test-project"
	gcpSAField      = "service_account_email"
	gcpTargetSA     = "target-sa@test-project.iam.gserviceaccount.com"
	gcpScope        = "https://www.googleapis.com/auth/devstorage.read_only"
	// gcpCredentialsJSON is a minter service-account key. The fake client never
	// parses it; it only needs to be present and distinct per minter.
	gcpCredentialsJSONField = "credentials_json"
	gcpCredentialsJSON      = `{"type":"service_account","project_id":"test-project",` +
		`"private_key_id":"key123","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n` +
		`-----END RSA PRIVATE KEY-----\n","client_email":"minter@test-project.iam.gserviceaccount.com",` +
		`"client_id":"123456789"}`
)

func gcpMinter(id string) map[string]interface{} {
	return map[string]interface{}{
		fieldID: id, gcpCredentialsJSONField: gcpCredentialsJSON, fieldNeverExpires: true,
	}
}

func gcpRoleFields() map[string]interface{} {
	return map[string]interface{}{
		fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
		gcpSAField: gcpTargetSA, fieldScopes: []string{gcpScope},
		fieldMinterSet: defaultSet,
	}
}

func gcpHarness(t *testing.T) plugintest.Harness {
	var denied atomic.Bool
	var minted atomic.Int64

	generate := func(_ context.Context, serviceAccount string, _ []string, lifetime time.Duration) (string, time.Time, error) {
		if denied.Load() {
			return "", time.Time{}, fmt.Errorf(
				"PERMISSION_DENIED: the caller does not have permission to impersonate %s", serviceAccount)
		}
		minted.Add(1)
		return "ya29.conformance-token", time.Now().Add(lifetime), nil
	}

	return plugintest.Harness{
		Cloud:   "gcp",
		Factory: credentialgcp.Factory,
		Inject: func(b logical.Backend) {
			credentialgcp.SetIAMClientFactory(b, func(_ string) credentialgcp.IAMCredentialsClient {
				return credentialgcp.NewFakeIAMClient(generate, nil)
			})
		},
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{gcpProjectField: gcpProject})
			plugintest.Write(t, b, storage, setPath, minterSet(gcpMinter(liveMinterID)))
			plugintest.Write(t, b, storage, rolePath, gcpRoleFields())
		},
		IssuePath:             issuePath,
		SecretType:            "gcp_access_token",
		LeaseInternalDataKeys: []string{"credential_id", "role", "minter_set", "minter_id"},
		RolePath:              rolePath,
		WorkersRunning:        credentialgcp.WorkersRunning,
		SetPath:               setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath, minterSet(gcpMinter(replacementMinterID)))
		},
		ProvisionedCount:  func() int { return int(minted.Load()) },
		ExpectsHardRevoke: false,

		ConfigureProbe: func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				gcpProjectField: gcpProject, fieldVerifyCapability: verify,
			})
			plugintest.Write(t, b, storage, setPath, minterSet(gcpMinter(liveMinterID)))
		},
		ProbeRolePath: probeRolePath,
		WriteProbeRole: func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
			return plugintest.TryWrite(t, b, storage, probeRolePath, gcpRoleFields())
		},
		RewriteSet: func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response {
			return plugintest.TryWrite(t, b, storage, setPath, minterSet(gcpMinter(minterID)))
		},
		PlantDisabledProbeRole: plantDisabledRole,
		DenyMint:               func() { denied.Store(true) },
		AllowMint:              func() { denied.Store(false) },
		LiveMinterID:           liveMinterID,
		ReplacementMinterID:    replacementMinterID,

		Skips: map[plugintest.Category]string{
			plugintest.CategoryReconcilerSafety: "GCP reconcile prunes local tracking entries only " +
				"(pkg/localexpiry): impersonation access tokens are not upstream entities, so there is " +
				"nothing to list and nothing the reconciler could delete",
		},
	}
}
