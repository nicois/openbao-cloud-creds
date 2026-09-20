package credentialazure

import (
	"github.com/nicois/openbao-cloud-creds/pkg/issuedlist"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// issuedPaths exposes the inventory of outstanding credentials. On Azure that is one record per
// application password this mount has added and not yet removed, so an entry also names the
// application object holding it — the only cloud here where the credential's id does not address it
// on its own.
//
// The path, the paging and the published fields all live in pkg/issuedlist; this plugin supplies
// only where its records are, exactly as purgePaths does.
func (b *backend) issuedPaths() []*framework.Path {
	return []*framework.Path{
		issuedlist.Endpoint{Prefixes: []string{activeTrackingPrefix}}.FrameworkPath(),
	}
}
