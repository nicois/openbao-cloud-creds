package conformance

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/mintledger"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialvultr "github.com/nicois/openbao-cloud-creds/plugins/credential-vultr"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Vultr creates a sub-user per credential and refuses to delegate an ACL the
// creating key does not itself hold — which the account health check cannot see.
// SetUngrantableACL models exactly that.
const (
	vultrAPIURLField    = "vultr_api_url"
	vultrACLsField      = "acls"
	vultrEmailDomainKey = "email_domain"
	vultrEmailDomain    = "managed.local"
	vultrACLs           = "manage_users,subscriptions"
	vultrUngrantableACL = "manage_users"
	vultrMinterToken    = "vultr_test_key"
	vultrOtherMintToken = "vultr_reseeded_key"
)

func vultrRoleFields() map[string]interface{} {
	return map[string]interface{}{
		fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
		vultrACLsField: vultrACLs, vultrEmailDomainKey: vultrEmailDomain,
		fieldMinterSet: defaultSet,
	}
}

func vultrHarness(t *testing.T) plugintest.Harness {
	srv := fakes.NewVultrServer()
	t.Cleanup(srv.Close)

	return plugintest.Harness{
		Cloud:   "vultr",
		Factory: credentialvultr.Factory,
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{vultrAPIURLField: srv.URL})
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, vultrMinterToken)))
			plugintest.Write(t, b, storage, rolePath, vultrRoleFields())
		},
		IssuePath:      issuePath,
		RolePath:       rolePath,
		WorkersRunning: credentialvultr.WorkersRunning,
		SetPath:        setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath,
				minterSet(tokenMinter(replacementMinterID, vultrOtherMintToken)))
		},
		ProvisionedCount:  srv.ProvisionedCount,
		ExpectsHardRevoke: true,

		ConfigureProbe: func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				vultrAPIURLField: srv.URL, fieldVerifyCapability: verify,
			})
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, vultrMinterToken)))
		},
		ProbeRolePath: probeRolePath,
		WriteProbeRole: func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
			return plugintest.TryWrite(t, b, storage, probeRolePath, vultrRoleFields())
		},
		RewriteSet: func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response {
			return plugintest.TryWrite(t, b, storage, setPath,
				minterSet(tokenMinter(minterID, vultrMinterToken)))
		},
		PlantDisabledProbeRole: plantDisabledRole,
		DenyMint:               func() { srv.SetUngrantableACL(vultrUngrantableACL) },
		AllowMint:              func() { srv.SetUngrantableACL("") },
		FailNextMintWithStatus: func(_ *testing.T, status int) string {
			srv.SetNextStatus(status)
			return ""
		},
		LiveMinterID:        liveMinterID,
		ReplacementMinterID: replacementMinterID,

		SeedForeignEntity: func() string {
			srv.AddRawUser(foreignEntityID, foreignEntityName)
			return foreignEntityID
		},
		// This cloud's list API reports no creation time, so the confirmable age comes
		// from the mint ledger (A5). The foreign entity gets NO ledger entry, which is
		// exactly why it must survive.
		SeedAgedOrphans: func(t *testing.T, storage logical.Storage) (string, string) {
			srv.AddRawUser(agedForeignID, agedForeignName)
			srv.AddRawUser(agedOwnedID, agedOwnedName)
			if err := mintledger.Record(t.Context(), storage, agedOwnedID, agedLedgerTime()); err != nil {
				t.Fatalf("seeding the mint ledger: %v", err)
			}
			return agedForeignID, agedOwnedID
		},
		HasEntity: srv.HasUser,
	}
}
