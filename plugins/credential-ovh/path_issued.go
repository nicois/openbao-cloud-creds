package credentialovh

import (
	"github.com/nicois/openbao-cloud-creds/pkg/issuedlist"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// issuedPaths exposes the inventory of outstanding credentials. This cloud's entry is the one an
// operator has the least other recourse on: an OVH OAuth2 token cannot be revoked and carries no
// upstream name, so the tracking record under activeTrackingPrefix is the only place the mount
// knows who holds a live token, and for how much longer.
func (b *backend) issuedPaths() []*framework.Path {
	return []*framework.Path{
		issuedlist.Endpoint{Prefixes: []string{activeTrackingPrefix}}.FrameworkPath(),
	}
}
