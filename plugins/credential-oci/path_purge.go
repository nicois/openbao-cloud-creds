package credentialoci

import (
	"github.com/nicois/openbao-cloud-creds/pkg/upstreampurge"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// purgePaths is roles/<name>/revoke-upstream, which phased rotation refuses — and it is the
// one refusal that hands the operator a lever rather than a ceiling.
//
// This plugin does not issue a credential per read: it hands out the freshest of the role's
// pre-provisioned slots, so many clients share one auth token and "delete what this role
// issued" would destroy the credential every one of them is using. Rotating the slot replaces
// that token immediately, which is the same containment by a different route — every holder of
// the old one loses it at once, and the next read serves the new one.
//
// The endpoint exists here rather than being absent so that an operator following the incident
// runbook is sent to rotate-slot instead of concluding this mount has no containment at all.
func (b *backend) purgePaths() []*framework.Path {
	return []*framework.Path{upstreampurge.UnsupportedPath(
		"this cloud uses phased rotation, so a credential belongs to one of the role's slots and "+
			"is shared by every client that has read it, not to a single lease",
		"rotate the slot holding it — write rotate-slot/<role>/<slot_index> — which replaces that "+
			"credential now and invalidates it for every holder; set disabled=true on the role to "+
			"stop it serving more")}
}
