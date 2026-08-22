package conformance

import (
	"fmt"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialakamai "github.com/nicois/openbao-cloud-creds/plugins/credential-akamai"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Akamai will not let an api client grant access it does not itself hold, while
// GET /api-clients/self answers for any live EdgeGrid credential — so the mint
// refusal is per apiId (SetUngrantableAPIID), not per credential.
const (
	akamaiHostField     = "host"
	akamaiAPIURLField   = "akamai_api_url"
	akamaiGroupIDField  = "group_id"
	akamaiAPIAccessKey  = "api_access"
	akamaiHost          = "akab-test.luna.akamaiapis.net"
	akamaiGroupID       = 100
	akamaiRoleAPIID     = 9901
	akamaiMinterToken   = "ct-test:at-test:cs-test"
	akamaiOtherToken    = "ct-other:at-other:cs-other"
	akamaiAllowedAPIKey = 0
)

// akamaiAPIAccess names the api the fake can be told is ungrantable, so the same
// role shape serves both the succeeding and the refused probe.
var akamaiAPIAccess = fmt.Sprintf(`{"apis":[{"apiId":%d,"accessLevel":"READ-WRITE"}]}`, akamaiRoleAPIID)

func akamaiRoleFields() map[string]interface{} {
	return map[string]interface{}{
		fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
		akamaiGroupIDField: akamaiGroupID, akamaiAPIAccessKey: akamaiAPIAccess,
		fieldMinterSet: defaultSet,
	}
}

func akamaiHarness(t *testing.T) plugintest.Harness {
	srv := fakes.NewAkamaiServer()
	t.Cleanup(srv.Close)

	return plugintest.Harness{
		Cloud:   "akamai",
		Factory: credentialakamai.Factory,
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				akamaiHostField: akamaiHost, akamaiAPIURLField: srv.URL,
			})
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, akamaiMinterToken)))
			plugintest.Write(t, b, storage, rolePath, akamaiRoleFields())
		},
		IssuePath:      issuePath,
		RolePath:       rolePath,
		WorkersRunning: credentialakamai.WorkersRunning,
		SetPath:        setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath,
				minterSet(tokenMinter(replacementMinterID, akamaiOtherToken)))
		},
		ProvisionedCount:  srv.ProvisionedCount,
		ExpectsHardRevoke: true,

		ConfigureProbe: func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				akamaiHostField: akamaiHost, akamaiAPIURLField: srv.URL,
				fieldVerifyCapability: verify,
			})
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, akamaiMinterToken)))
		},
		ProbeRolePath: probeRolePath,
		WriteProbeRole: func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
			return plugintest.TryWrite(t, b, storage, probeRolePath, akamaiRoleFields())
		},
		RewriteSet: func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response {
			return plugintest.TryWrite(t, b, storage, setPath,
				minterSet(tokenMinter(minterID, akamaiMinterToken)))
		},
		PlantDisabledProbeRole: plantDisabledRole,
		DenyMint:               func() { srv.SetUngrantableAPIID(akamaiRoleAPIID) },
		AllowMint:              func() { srv.SetUngrantableAPIID(akamaiAllowedAPIKey) },
		FailNextMintWithStatus: func(_ *testing.T, status int) string {
			srv.SetNextStatus(status)
			return ""
		},
		LiveMinterID:        liveMinterID,
		ReplacementMinterID: replacementMinterID,

		SeedForeignEntity: func() string {
			srv.AddRawClient(foreignEntityID, foreignEntityName)
			return foreignEntityID
		},
		SeedAgedOrphans: func(t *testing.T, storage logical.Storage) (string, string) {
			srv.AddRawClientWithCreatedDate(agedForeignID, agedForeignName, agedTimestamp)
			srv.AddRawClientWithCreatedDate(agedOwnedID, agedOwnedName(t, storage), agedTimestamp)
			return agedForeignID, agedOwnedID
		},
		HasEntity: srv.HasClient,
	}
}
