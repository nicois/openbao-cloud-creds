package credentialoci

import (
	"github.com/nicois/openbao-cloud-creds/pkg/issuedlist"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// issuedPaths is issued/, which phased rotation refuses for the same reason it refuses
// revoke-upstream: there is no one-per-credential record here to enumerate.
//
// A read does not mint a credential; it serves the freshest of the role's pre-provisioned
// slots, and every client that has read that slot holds the same auth token. An inventory
// keyed by credential would therefore have nothing to key on — and pointing it at slots/
// instead would publish the slot record, which carries the token value itself.
//
// What the operator has instead is the slot state on the role and rotate-slot, so the
// refusal names those: the question "who holds this credential" is answered per slot, and
// acted on by replacing the slot.
func (b *backend) issuedPaths() []*framework.Path {
	return []*framework.Path{issuedlist.UnsupportedPath(
		"this cloud uses phased rotation, so a credential is one of the role's pre-provisioned "+
			"slots and is shared by every client that has read it, not a record per issuance",
		"read the role — roles/<name> reports each slot's index, state and next rotation, which is "+
			"the whole of what this mount has outstanding — and write rotate-slot/<role>/<slot_index> "+
			"to replace the credential a reader is holding")}
}
