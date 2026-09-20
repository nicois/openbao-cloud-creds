package credentialaws

import (
	"github.com/nicois/openbao-cloud-creds/pkg/issuedlist"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// issuedPaths exposes the inventory of outstanding credentials. On AWS an entry is an STS session
// that cannot be revoked, so the inventory is the only handle an incident has on it: the response
// names who obtained each still-valid session and when it expires, which is the whole of the
// available containment story here.
func (b *backend) issuedPaths() []*framework.Path {
	return []*framework.Path{
		issuedlist.Endpoint{Prefixes: []string{activeTrackingPrefix}}.FrameworkPath(),
	}
}
