package credentialupcloud

import (
	"github.com/nicois/openbao-cloud-creds/pkg/issuedlist"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// issuedPaths exposes the inventory of outstanding credentials. On UpCloud that is one API
// sub-account token per lease, which carries the whole account's authority — so "what is
// outstanding, and who asked for it" is the only bound on a leak here.
//
// Everything about the response — the paging, the published-field allowlist, the help text —
// lives in pkg/issuedlist, exactly as purgePaths defers to pkg/upstreampurge: this plugin
// supplies only where its tracking records are.
func (b *backend) issuedPaths() []*framework.Path {
	return []*framework.Path{
		issuedlist.Endpoint{Prefixes: []string{activeTrackingPrefix}}.FrameworkPath(),
	}
}
