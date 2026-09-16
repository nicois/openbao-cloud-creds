package credentialaws

import (
	"github.com/nicois/openbao-cloud-creds/pkg/upstreampurge"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// purgePaths is roles/<name>/revoke-upstream, which this cloud refuses.
//
// The endpoint exists here so that an operator following the incident runbook gets an answer
// rather than a 404 they have to interpret: "unsupported, and here is what containment you do
// have" is actionable, while an unrouted path leaves them wondering whether they typed the
// mount wrong. It is also why the refusal is not a success reporting zero deletions — that
// would read as containment on the one cloud where nothing at all can be contained.
func (b *backend) purgePaths() []*framework.Path {
	return []*framework.Path{upstreampurge.UnsupportedPath(
		"an STS session credential has no upstream record to delete and no revoke API — it is "+
			"valid until the DurationSeconds it was minted with elapses",
		upstreampurge.RemedyExpiryOnly)}
}
