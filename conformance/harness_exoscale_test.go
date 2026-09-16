package conformance

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/mintledger"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialexoscale "github.com/nicois/openbao-cloud-creds/plugins/credential-exoscale"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Exoscale scopes each minted api-key to an IAM role. Whether the CALLING key's
// own role may create api-keys is invisible to the health check (GET /v2/zone
// succeeds for any live key), so the fake refuses creation by calling-key prefix.
const (
	exoscaleAPIURLField = "exoscale_api_url"
	exoscaleKeyField    = "key"
	exoscaleRoleIDField = "role_id"
	exoscaleRoleID      = "11111111-1111-1111-1111-111111111111"
	// exoscaleMinterKeyPrefix is shared by every minter the harness writes, so
	// one prefix refusal denies minting to all of them.
	exoscaleMinterKeyPrefix = "EXO_key_"
	exoscaleLiveKey         = exoscaleMinterKeyPrefix + "1"
	exoscaleOtherKey        = exoscaleMinterKeyPrefix + "2"
)

func exoscaleMinter(id, key string) map[string]interface{} {
	return map[string]interface{}{fieldID: id, exoscaleKeyField: key, fieldNeverExpires: true}
}

func exoscaleRoleFields() map[string]interface{} {
	return map[string]interface{}{
		fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
		exoscaleRoleIDField: exoscaleRoleID, fieldMinterSet: defaultSet,
	}
}

func exoscaleHarness(t *testing.T) plugintest.Harness {
	srv := fakes.NewExoscaleServer()
	t.Cleanup(srv.Close)

	return plugintest.Harness{
		Cloud:   "exoscale",
		Factory: credentialexoscale.Factory,
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath,
				map[string]interface{}{exoscaleAPIURLField: srv.URL})
			plugintest.Write(t, b, storage, setPath,
				minterSet(exoscaleMinter(liveMinterID, exoscaleLiveKey)))
			plugintest.Write(t, b, storage, rolePath, exoscaleRoleFields())
		},
		IssuePath:             issuePath,
		CredentialKeys:        []string{"key", "secret"},
		CredentialKind:        "key_secret",
		ScopeKind:             "role",
		SecretType:            "exoscale_api_key",
		LeaseInternalDataKeys: []string{"upstream_key_id", "role", "minter_set", "minter_id"},
		RolePath:              rolePath,
		WorkersRunning:        credentialexoscale.WorkersRunning,
		SetPath:               setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath,
				minterSet(exoscaleMinter(replacementMinterID, exoscaleOtherKey)))
		},
		ProvisionedCount:         srv.ProvisionedCount,
		ExpectsHardRevoke:        true,
		DeletesIssuedCredentials: true,
		TrackingPrefix:           "active-tokens/",

		ConfigureProbe: func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				exoscaleAPIURLField: srv.URL, fieldVerifyCapability: verify,
			})
			plugintest.Write(t, b, storage, setPath,
				minterSet(exoscaleMinter(liveMinterID, exoscaleLiveKey)))
		},
		ProbeRolePath: probeRolePath,
		WriteProbeRole: func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
			return plugintest.TryWrite(t, b, storage, probeRolePath, exoscaleRoleFields())
		},
		RewriteSet: func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response {
			return plugintest.TryWrite(t, b, storage, setPath,
				minterSet(exoscaleMinter(minterID, exoscaleLiveKey)))
		},
		DenyMint:  func() { srv.SetForbidCreateForKeyPrefix(exoscaleMinterKeyPrefix) },
		AllowMint: func() { srv.SetForbidCreateForKeyPrefix("") },
		FailNextMintWithStatus: func(_ *testing.T, status int) string {
			srv.SetNextStatus(status)
			return ""
		},
		LiveMinterID:        liveMinterID,
		ReplacementMinterID: replacementMinterID,

		SeedForeignEntity: func() string {
			srv.AddRawAPIKey(foreignEntityID, foreignEntityName)
			return foreignEntityID
		},
		// This cloud's list API reports no creation time, so the confirmable age comes
		// from the mint ledger (A5). The foreign entity gets NO ledger entry, which is
		// exactly why it must survive.
		SeedAgedOrphans: func(t *testing.T, storage logical.Storage) (string, string) {
			srv.AddRawAPIKey(agedForeignID, agedForeignName)
			srv.AddRawAPIKey(agedOwnedID, agedOwnedName(t, storage))
			if err := mintledger.Record(t.Context(), storage, agedOwnedID, agedLedgerTime()); err != nil {
				t.Fatalf("seeding the mint ledger: %v", err)
			}
			return agedForeignID, agedOwnedID
		},
		HasEntity: srv.HasAPIKey,
	}
}
