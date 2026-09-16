//go:build e2e

package e2e

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// UpCloud mints a token with a fixed expires_in, so the lease must not be
// renewable — renewal would hand back validity the credential no longer has
// (KI-005). The username is the basic-auth user and lives in config, which made
// it the original KI-001 victim; the reload step re-proves that through core.
const (
	upcloudUsernameField = "username"
	upcloudAPIURLField   = "upcloud_api_url"
	upcloudUsername      = "e2e-user"
	upcloudMinterToken   = "ucat_v1_e2e"
	upcloudScopes        = "read,write"
)

func upcloudCase(t *testing.T) e2eCase {
	srv := fakes.NewUpCloudServer()
	t.Cleanup(srv.Close)

	return e2eCase{
		Cloud: "upcloud",
		Config: map[string]interface{}{
			upcloudUsernameField: upcloudUsername,
			upcloudAPIURLField:   srv.URL,
		},
		MinterSet: minterSet(tokenMinter(upcloudMinterToken)),
		Role: map[string]interface{}{
			fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
			fieldScopes: upcloudScopes, fieldMinterSet: defaultSet,
		},
		TTLSeconds: shortTTL,
		Renewable:  false,
		HardRevoke: true,
		// Every hard-revoke cloud can also be purged: the same delete call serves both.
		DeletesIssuedCredentials: true,
		Upstream:                 srv.ProvisionedCount,
	}
}
