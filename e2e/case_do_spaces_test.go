//go:build e2e

package e2e

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// DigitalOcean Spaces keys: the same plugin binary and the same mount as doCase, driven through a
// role that issues the OTHER credential type.
//
// Worth its own row rather than folded into doCase, because everything this layer uniquely proves
// is per-credential-type and crosses the plugin RPC boundary separately: a second framework.Secret
// registered under its own type must actually be reachable from core's expiration manager (a
// revoke dispatched to the wrong callback is invisible in-process, where nothing serialises the
// secret type), and the S3 credential block has to survive JSON round-tripping with all four keys.
// It is also the type real DigitalOcean will issue, so this is the row that matters most here.
//
// A distinct RoleName rather than reusing the default: both roles then exist on ONE mount at the
// same time, which is the deployment shape an operator gets, and it means neither case's writes can
// quietly overwrite the other's.
const (
	doSpacesRoleName = "spaces-role"
	doSpacesGrants   = "backups:read"
	doSpacesRegion   = "nyc3"
)

func doSpacesCase(t *testing.T) e2eCase {
	srv := fakes.NewDOServer()
	t.Cleanup(srv.Close)

	return e2eCase{
		Cloud:     "do",
		Config:    map[string]interface{}{doAPIURLField: srv.URL},
		MinterSet: minterSet(tokenMinter(doMinterToken)),
		RoleName:  doSpacesRoleName,
		Role: map[string]interface{}{
			fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
			fieldCredentialType: doSpacesCredentialType,
			fieldGrants:         doSpacesGrants,
			fieldRegion:         doSpacesRegion,
			fieldMinterSet:      defaultSet,
		},
		TTLSeconds: shortTTL,
		// Renewable for the same reason the token role is: a Spaces key has no upstream expiry,
		// so renewal only defers the revoke that is the credential's whole bound.
		Renewable:  true,
		HardRevoke: true,
		// The Spaces-key count, not the token count: a summed count would let this row pass on
		// the other type's numbers.
		Upstream: srv.ProvisionedSpacesKeyCount,
		// Pinned rather than inferred: the point of this row is that this role serves the S3
		// shape, so reading whatever the envelope declares and pinning that would assert nothing
		// about which type was issued.
		CredentialKind: credenvelope.KindS3Credentials,
	}
}
