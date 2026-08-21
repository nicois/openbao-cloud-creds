//go:build e2e

package e2e

import (
	"fmt"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// Akamai signs every request with EdgeGrid, so this case also proves the
// signature is computed correctly by a plugin process reading its credentials
// back out of storage. The client name is a TRUNCATED req.ID (leaseShortID), so
// distinct issuance here depends on core's ids differing early in the string.
const (
	akamaiHostField    = "host"
	akamaiAPIURLField  = "akamai_api_url"
	akamaiGroupIDField = "group_id"
	akamaiAPIAccessKey = "api_access"
	akamaiHost         = "akab-e2e.luna.akamaiapis.net"
	akamaiGroupID      = 100
	akamaiRoleAPIID    = 9901
	akamaiMinterToken  = "ct-e2e:at-e2e:cs-e2e"
)

func akamaiCase(t *testing.T) e2eCase {
	srv := fakes.NewAkamaiServer()
	t.Cleanup(srv.Close)

	apiAccess := fmt.Sprintf(`{"apis":[{"apiId":%d,"accessLevel":"READ-WRITE"}]}`, akamaiRoleAPIID)

	return e2eCase{
		Cloud: "akamai",
		Config: map[string]interface{}{
			akamaiHostField:   akamaiHost,
			akamaiAPIURLField: srv.URL,
		},
		MinterSet: minterSet(tokenMinter(akamaiMinterToken)),
		Role: map[string]interface{}{
			fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
			akamaiGroupIDField: akamaiGroupID, akamaiAPIAccessKey: apiAccess,
			fieldMinterSet: defaultSet,
		},
		TTLSeconds: shortTTL,
		Renewable:  true,
		HardRevoke: true,
		Upstream:   srv.ProvisionedCount,
	}
}
