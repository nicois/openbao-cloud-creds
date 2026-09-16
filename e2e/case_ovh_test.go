//go:build e2e

package e2e

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// OVH tokens are a fixed 1h with no revoke API, so the role TTL is pinned to
// exactly 3600s, the lease must not be renewable, and revocation makes no
// upstream call (docs/ttl-semantics.md).
//
// Upstream is deliberately nil: OVH's minter health check IS a token mint (the
// same endpoint answers both), so the fake's counter moves on the health-check
// worker's cadence, not only on issuance. A count expectation here would assert
// the worker's timing rather than the plugin's behaviour.
const (
	ovhRegionField        = "region"
	ovhTokenEndpointField = "token_endpoint"
	ovhClientIDField      = "client_id"
	ovhClientSecretField  = "client_secret"
	ovhRegion             = "eu"
	ovhClientID           = "test-client-id"
	ovhClientSecret       = "test-client-secret"
)

func ovhCase(t *testing.T) e2eCase {
	srv := fakes.NewOVHServer()
	t.Cleanup(srv.Close)

	minter := map[string]interface{}{
		fieldID: liveMinterID, ovhClientIDField: ovhClientID,
		ovhClientSecretField: ovhClientSecret, fieldNeverExpires: true,
	}

	return e2eCase{
		Cloud: "ovh",
		Config: map[string]interface{}{
			ovhRegionField:        ovhRegion,
			ovhTokenEndpointField: srv.TokenEndpointURL(),
		},
		MinterSet: minterSet(minter),
		Role: map[string]interface{}{
			fieldDefaultTTL: hourTTL, fieldMaxTTL: hourTTL, fieldMinterSet: defaultSet,
		},
		TTLSeconds: hourTTL,
		Renewable:  false,
		HardRevoke: false,
		// Nothing deletes an OVH OAuth2 token, so the purge lever must refuse rather than
		// report a contained incident. Stated, not left to the zero value, so the row says
		// which of the two facts about deletion it is claiming.
		DeletesIssuedCredentials: false,
		Upstream:                 nil,
	}
}
