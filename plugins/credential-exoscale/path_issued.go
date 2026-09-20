package credentialexoscale

import (
	"github.com/nicois/openbao-cloud-creds/pkg/issuedlist"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// issuedPaths exposes the inventory of outstanding credentials. On this cloud that is one IAM API
// key per issued credential, tracked under activeTrackingPrefix — the same records the reconciler
// and roles/<name>/revoke-upstream walk, now readable over the API.
//
// The path, the paging and the published-field allowlist all live in pkg/issuedlist, so this plugin
// supplies only where its records are: an operator's inventory query is the same on every cloud.
func (b *backend) issuedPaths() []*framework.Path {
	return []*framework.Path{
		issuedlist.Endpoint{Prefixes: []string{activeTrackingPrefix}}.FrameworkPath(),
	}
}
