package credentialgcp

import (
	"github.com/nicois/openbao-cloud-creds/pkg/issuedlist"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// issuedPaths exposes the inventory of outstanding credentials. On this cloud an entry is an
// impersonation access token: nothing exists upstream to enumerate, so the mount's own tracking
// records are the only account of what it has handed out — and, since those tokens are valid for
// the lifetime they were minted with and cannot be revoked (see purgePaths), this listing is the
// containment report. It names who holds a token that will remain live until it expires.
func (b *backend) issuedPaths() []*framework.Path {
	return []*framework.Path{
		issuedlist.Endpoint{Prefixes: []string{activeTrackingPrefix}}.FrameworkPath(),
	}
}
