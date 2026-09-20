//go:build e2e

package e2e

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// DigitalOcean is the reference plugin: an HTTP fake reached through a config
// field, a PAT with no upstream expiry, and therefore a hard revoke and a
// renewable lease (renewal just defers the revoke).
const (
	doAPIURLField = "do_api_url"
	doScopes      = "droplet:read,droplet:create"
	doMinterToken = "dop_v1_e2e"
)

func doCase(t *testing.T) e2eCase {
	srv := fakes.NewDOServer()
	t.Cleanup(srv.Close)

	return e2eCase{
		Cloud:     "do",
		Config:    map[string]interface{}{doAPIURLField: srv.URL},
		MinterSet: minterSet(tokenMinter(doMinterToken)),
		Role: map[string]interface{}{
			fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
			fieldScopes: doScopes, fieldMinterSet: defaultSet,
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
