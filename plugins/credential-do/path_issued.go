package credentialdo

import (
	"github.com/nicois/openbao-cloud-creds/pkg/issuedlist"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// issuedPaths exposes the inventory of outstanding credentials: on DigitalOcean, the mount's issued
// personal access tokens AND its Spaces access keys.
//
// # Why two prefixes
//
// This plugin serves three credential types across TWO tracking prefixes: activeTrackingPrefix for
// credential_type=token, and spacesTrackingPrefix for both Spaces types. They are deliberately
// separate because the two upstream quotas are separate (see the comment on spacesTrackingPrefix).
// One `issued/` path covers both, in that order — an inventory that reported the tokens and silently
// omitted the Spaces keys would be the short answer this endpoint exists to avoid, and it would look
// like a working listing.
//
// # What must never be listed here
//
// Not sharedSpacesPrefix. That record is the shared key ITSELF — its struct carries SecretKey — and
// it happens to be keyed by role, so it would superficially "work" as a listing. The `active-*/`
// tracking records are the listable ones precisely because they hold no credential material; the
// allowlist in pkg/issuedlist is a second line of defence, not a licence to point this at a record
// that holds a secret.
func (b *backend) issuedPaths() []*framework.Path {
	return []*framework.Path{
		issuedlist.Endpoint{
			Prefixes: []string{activeTrackingPrefix, spacesTrackingPrefix},
		}.FrameworkPath(),
	}
}
