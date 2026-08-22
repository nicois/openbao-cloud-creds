package conformance

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// DigitalOcean is the reference plugin: an HTTP fake reached through a config
// field, hard revoke, and a mint refusal (SetForbidCreate) that leaves
// GET /v2/account — the health check — succeeding.
const (
	doAPIURLField = "do_api_url"
	doScopes      = "read,write"
	doMinterToken = "dop_v1_test"
)

func doRoleFields() map[string]interface{} {
	return map[string]interface{}{
		fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
		fieldScopes: doScopes, fieldMinterSet: defaultSet,
	}
}

func doHarness(t *testing.T) plugintest.Harness {
	srv := fakes.NewDOServer()
	t.Cleanup(srv.Close)

	config := func(verify bool) map[string]interface{} {
		return map[string]interface{}{doAPIURLField: srv.URL, fieldVerifyCapability: verify}
	}

	return plugintest.Harness{
		Cloud:   "do",
		Factory: credentialdo.Factory,
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{doAPIURLField: srv.URL})
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, doMinterToken)))
			plugintest.Write(t, b, storage, rolePath, doRoleFields())
		},
		IssuePath:             issuePath,
		CredentialKeys:        []string{"token", "scopes"},
		CredentialKind:        "scoped_token",
		ScopeKind:             "scopes",
		SecretType:            "do_token",
		LeaseInternalDataKeys: []string{"upstream_token_id", "role", "minter_set", "minter_id"},
		RolePath:              rolePath,
		WorkersRunning:        credentialdo.WorkersRunning,
		SetPath:               setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath,
				minterSet(tokenMinter(replacementMinterID, "dop_v1_reseeded")))
		},
		ProvisionedCount:  srv.ProvisionedCount,
		ExpectsHardRevoke: true,

		ConfigureProbe: func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool) {
			plugintest.Write(t, b, storage, configPath, config(verify))
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, doMinterToken)))
		},
		ProbeRolePath: probeRolePath,
		WriteProbeRole: func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
			return plugintest.TryWrite(t, b, storage, probeRolePath, doRoleFields())
		},
		RewriteSet: func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response {
			return plugintest.TryWrite(t, b, storage, setPath,
				minterSet(tokenMinter(minterID, doMinterToken)))
		},
		PlantDisabledProbeRole: plantDisabledRole,
		DenyMint:               func() { srv.SetForbidCreate(true) },
		AllowMint:              func() { srv.SetForbidCreate(false) },
		FailNextMintWithStatus: func(_ *testing.T, status int) string {
			srv.SetNextStatus(status)
			return ""
		},
		LiveMinterID:        liveMinterID,
		ReplacementMinterID: replacementMinterID,

		SeedForeignEntity: func() string {
			srv.AddRawToken(foreignEntityID, foreignEntityName)
			return foreignEntityID
		},
		SeedAgedOrphans: func(t *testing.T, storage logical.Storage) (string, string) {
			srv.AddRawTokenWithCreatedAt(agedForeignID, agedForeignName, agedTimestamp)
			srv.AddRawTokenWithCreatedAt(agedOwnedID, agedOwnedName(t, storage), agedTimestamp)
			return agedForeignID, agedOwnedID
		},
		HasEntity: srv.HasToken,
	}
}
