package credentialakamai

import (
	"github.com/nicois/openbao-cloud-creds/pkg/issuedlist"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// issuedPaths exposes the inventory of outstanding credentials. On Akamai one issued credential is
// one upstream API client, so the key is the client id an operator can name to Akamai support or
// delete through roles/<name>/revoke-upstream.
func (b *backend) issuedPaths() []*framework.Path {
	return []*framework.Path{
		issuedlist.Endpoint{Prefixes: []string{activeTrackingPrefix}}.FrameworkPath(),
	}
}
