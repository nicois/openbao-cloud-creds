//go:build e2e

package e2e

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// Exoscale api-keys carry no upstream expiry and are scoped to an IAM role-id,
// so the lease is renewable and revocation must delete the key. The minter
// carries a `key` rather than a `token`.
const (
	exoscaleAPIURLField = "exoscale_api_url"
	exoscaleKeyField    = "key"
	exoscaleRoleIDField = "role_id"
	exoscaleRoleID      = "11111111-1111-1111-1111-111111111111"
	exoscaleMinterKey   = "EXO_key_e2e"
)

func exoscaleCase(t *testing.T) e2eCase {
	srv := fakes.NewExoscaleServer()
	t.Cleanup(srv.Close)

	minter := map[string]interface{}{
		fieldID: liveMinterID, exoscaleKeyField: exoscaleMinterKey, fieldNeverExpires: true,
	}

	return e2eCase{
		Cloud:     "exoscale",
		Config:    map[string]interface{}{exoscaleAPIURLField: srv.URL},
		MinterSet: minterSet(minter),
		Role: map[string]interface{}{
			fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
			exoscaleRoleIDField: exoscaleRoleID, fieldMinterSet: defaultSet,
		},
		TTLSeconds: shortTTL,
		Renewable:  true,
		HardRevoke: true,
		// Every hard-revoke cloud can also be purged: the same delete call serves both.
		DeletesIssuedCredentials: true,
		Upstream:                 srv.ProvisionedCount,
	}
}
