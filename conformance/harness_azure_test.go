package conformance

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialazure "github.com/nicois/openbao-cloud-creds/plugins/credential-azure"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Azure mints a password on an existing app registration, so capability is
// per-app: SetAddPasswordForbidden refuses addPassword on ONE app while the
// service principal still authenticates and can even read that application.
const (
	azureTenantField   = "tenant_id"
	azureGraphField    = "graph_endpoint"
	azureLoginField    = "login_endpoint"
	azureAppObjIDField = "app_object_id"
	azureClientIDField = "client_id"
	azureTenant        = "test-tenant-id"
	azureAppObjectID   = "fake-app-object-id"
	azureAppClientID   = "fake-app-client-id"
	azureMinterToken   = "fake-client-id:fake-client-secret"
)

func azureRoleFields() map[string]interface{} {
	return map[string]interface{}{
		fieldDefaultTTL: hourTTL, fieldMaxTTL: dayTTL,
		azureAppObjIDField: azureAppObjectID, azureClientIDField: azureAppClientID,
		fieldMinterSet: defaultSet,
	}
}

func azureHarness(t *testing.T) plugintest.Harness {
	srv := fakes.NewAzureServer()
	t.Cleanup(srv.Close)

	config := func(verify bool) map[string]interface{} {
		return map[string]interface{}{
			azureTenantField: azureTenant, azureGraphField: srv.URL, azureLoginField: srv.URL,
			fieldVerifyCapability: verify,
		}
	}

	return plugintest.Harness{
		Cloud:   "azure",
		Factory: credentialazure.Factory,
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				azureTenantField: azureTenant, azureGraphField: srv.URL, azureLoginField: srv.URL,
			})
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, azureMinterToken)))
			plugintest.Write(t, b, storage, rolePath, azureRoleFields())
		},
		IssuePath:              issuePath,
		CredentialKeys:         []string{"client_id", "client_secret", "tenant_id"},
		CredentialKind:         "azure_client_secret",
		OptionalCredentialKeys: []string{"subscription_id"},
		ScopeKind:              "identity",
		SecretType:             "azure_client_secret",
		LeaseInternalDataKeys:  []string{"upstream_key_id", "app_object_id", "role", "minter_set", "minter_id"},
		RolePath:               rolePath,
		WorkersRunning:         credentialazure.WorkersRunning,
		SetPath:                setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath,
				minterSet(tokenMinter(replacementMinterID, azureMinterToken)))
		},
		ProvisionedCount:         srv.ProvisionedCount,
		ExpectsHardRevoke:        true,
		DeletesIssuedCredentials: true,
		TrackingPrefix:           "active-tokens/",

		ConfigureProbe: func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool) {
			plugintest.Write(t, b, storage, configPath, config(verify))
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, azureMinterToken)))
		},
		ProbeRolePath: probeRolePath,
		WriteProbeRole: func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
			return plugintest.TryWrite(t, b, storage, probeRolePath, azureRoleFields())
		},
		RewriteSet: func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response {
			return plugintest.TryWrite(t, b, storage, setPath,
				minterSet(tokenMinter(minterID, azureMinterToken)))
		},
		WriteSetWithMinters: func(t *testing.T, b logical.Backend, storage logical.Storage, ids ...string) *logical.Response {
			minters := make([]map[string]interface{}, 0, len(ids))
			for _, id := range ids {
				// The same credential under different ids. Affinity is about WHICH minter is
				// chosen, not about the credentials differing, so one token keeps the fake simple
				// while the selection under test is unchanged.
				minters = append(minters, tokenMinter(id, azureMinterToken))
			}
			return plugintest.TryWrite(t, b, storage, setPath, minterSet(minters...))
		},
		DenyMint:  func() { srv.SetAddPasswordForbidden(azureAppObjectID, true) },
		AllowMint: func() { srv.SetAddPasswordForbidden(azureAppObjectID, false) },
		FailNextMintWithStatus: func(_ *testing.T, status int) string {
			srv.SetNextStatus(status)
			return ""
		},
		LiveMinterID:        liveMinterID,
		ReplacementMinterID: replacementMinterID,

		SeedForeignEntity: func() string {
			srv.AddRawPassword(foreignEntityID, foreignEntityName)
			return foreignEntityID
		},
		SeedAgedOrphans: func(t *testing.T, storage logical.Storage) (string, string) {
			srv.AddRawPasswordWithStartDateTime(agedForeignID, agedForeignName, agedTimestamp)
			srv.AddRawPasswordWithStartDateTime(agedOwnedID, agedOwnedName(t, storage), agedTimestamp)
			return agedForeignID, agedOwnedID
		},
		HasEntity: srv.HasPassword,
	}
}
