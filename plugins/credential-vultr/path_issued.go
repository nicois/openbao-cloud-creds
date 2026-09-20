package credentialvultr

import (
	"github.com/nicois/openbao-cloud-creds/pkg/issuedlist"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// issuedPaths exposes the inventory of outstanding credentials. On this cloud a credential is a
// sub-user of the account, so an entry's key is the sub-user id that must be deleted to revoke it.
//
// The prefix is this plugin's own activeTrackingPrefix — active-users/, not the active-tokens/ that
// several sibling clouds use — because a listing that names a different prefix than the writer is a
// permanently empty inventory that looks like a working endpoint.
func (b *backend) issuedPaths() []*framework.Path {
	return []*framework.Path{
		issuedlist.Endpoint{Prefixes: []string{activeTrackingPrefix}}.FrameworkPath(),
	}
}
