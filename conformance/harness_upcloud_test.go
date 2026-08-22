package conformance

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialupcloud "github.com/nicois/openbao-cloud-creds/plugins/credential-upcloud"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// UpCloud tokens carry can_create_tokens, which the account endpoint does not
// report — so a minter without it reads /1.3/account happily and only fails when
// asked to mint. The fake refuses minting by calling-token prefix.
const (
	upcloudUsernameField = "username"
	upcloudAPIURLField   = "upcloud_api_url"
	upcloudUsername      = "testuser"
	// upcloudMinterPrefix is shared by every minter the harness writes, so one
	// prefix refusal denies minting to all of them.
	upcloudMinterPrefix = "ucat_v1_"
	upcloudLiveToken    = upcloudMinterPrefix + "test"
	upcloudOtherToken   = upcloudMinterPrefix + "reseeded"
	upcloudScopes       = "read,write"
)

func upcloudRoleFields() map[string]interface{} {
	return map[string]interface{}{
		fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
		fieldScopes: upcloudScopes, fieldMinterSet: defaultSet,
	}
}

func upcloudHarness(t *testing.T) plugintest.Harness {
	srv := fakes.NewUpCloudServer()
	t.Cleanup(srv.Close)

	return plugintest.Harness{
		Cloud:   "upcloud",
		Factory: credentialupcloud.Factory,
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				upcloudUsernameField: upcloudUsername, upcloudAPIURLField: srv.URL,
			})
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, upcloudLiveToken)))
			plugintest.Write(t, b, storage, rolePath, upcloudRoleFields())
		},
		IssuePath:             issuePath,
		CredentialKeys:        []string{"username", "password"},
		ScopeKind:             "account",
		SecretType:            "upcloud_token",
		LeaseInternalDataKeys: []string{"upstream_token_id", "role", "minter_set", "minter_id"},
		RolePath:              rolePath,
		WorkersRunning:        credentialupcloud.WorkersRunning,
		SetPath:               setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath,
				minterSet(tokenMinter(replacementMinterID, upcloudOtherToken)))
		},
		ProvisionedCount:  srv.ProvisionedCount,
		ExpectsHardRevoke: true,

		ConfigureProbe: func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				upcloudUsernameField: upcloudUsername, upcloudAPIURLField: srv.URL,
				fieldVerifyCapability: verify,
			})
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, upcloudLiveToken)))
		},
		ProbeRolePath: probeRolePath,
		WriteProbeRole: func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
			return plugintest.TryWrite(t, b, storage, probeRolePath, upcloudRoleFields())
		},
		RewriteSet: func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response {
			return plugintest.TryWrite(t, b, storage, setPath,
				minterSet(tokenMinter(minterID, upcloudLiveToken)))
		},
		PlantDisabledProbeRole: plantDisabledRole,
		DenyMint:               func() { srv.SetForbidMintForTokenPrefix(upcloudMinterPrefix) },
		AllowMint:              func() { srv.SetForbidMintForTokenPrefix("") },
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
