//go:build e2e

package e2e

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// Vultr issues a sub-user per credential, named from req.ID as an email address
// under the role's domain — so this case is also the one that proves core's
// request id survives the plugin's identity construction.
const (
	vultrAPIURLField    = "vultr_api_url"
	vultrACLsField      = "acls"
	vultrEmailDomainKey = "email_domain"
	vultrEmailDomain    = "managed.local"
	vultrACLs           = "manage_users,subscriptions"
	vultrMinterToken    = "vultr_e2e_key"
)

func vultrCase(t *testing.T) e2eCase {
	srv := fakes.NewVultrServer()
	t.Cleanup(srv.Close)

	return e2eCase{
		Cloud:     "vultr",
		Config:    map[string]any{vultrAPIURLField: srv.URL},
		MinterSet: minterSet(tokenMinter(vultrMinterToken)),
		Role: map[string]any{
			fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
			vultrACLsField: vultrACLs, vultrEmailDomainKey: vultrEmailDomain,
			fieldMinterSet: defaultSet,
		},
		TTLSeconds:              shortTTL,
		Renewable:               true,
		HardRevoke:              true,
		TracksIssuedCredentials: true,
		// Every hard-revoke cloud can also be purged: the same delete call serves both.
		DeletesIssuedCredentials: true,
		Upstream:                 srv.ProvisionedCount,
	}
}
