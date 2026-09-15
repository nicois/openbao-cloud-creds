package credentialdo

import (
	"fmt"
	"strings"
)

// grantAllBuckets is how an account-wide grant is WRITTEN in a role and rendered in
// metadata.scope. On the wire DigitalOcean expresses account-wide as an empty bucket
// name, which would read as a missing field in a role definition or an audit record —
// so `*` is used everywhere a human or a client sees it, and the empty string only
// where DO requires it.
const grantAllBuckets = "*"

// grantSeparator splits a role's `bucket:permission` grant spec. The same rendering is
// used in metadata.scope, which is what credenvelope.ScopeKindGrants describes.
const grantSeparator = ":"

// parseGrants turns a role's grant specs (`backups:read`, `*:fullaccess`) into the wire
// form DigitalOcean accepts, refusing anything whose privilege would not be what the
// role says.
//
// Grants are PARSED rather than passed through, unlike this plugin's token `scopes`, for
// one reason: a list mixing `fullaccess` with per-bucket grants has no established
// meaning. DO's spec asserts both halves of a contradiction — it documents a 400 whose
// description is "Cannot mix fullaccess permission with scoped permissions", and it also
// says a fullaccess permission "will be prioritized if fullaccess and scoped permissions
// are both added". Nothing available here settles which the API does.
//
// That is what makes the check worth having rather than a reason to wait: refusing the
// combination is correct under EITHER reading. If DO refuses the mix, an operator learns
// at role write instead of at every issuance; if DO prioritises fullaccess, a role that
// reads as least-privilege would have issued an account-wide key, silently, with nothing
// downstream able to notice. Refusing requires recognising the permission values.
//
// The cost of validating is that a permission DigitalOcean adds later needs a one-line
// change, which is a deliberate trade: an unrecognised permission cannot be checked
// against the escalation rule, and a typo (`readwite`) would otherwise mint a key whose
// privilege nobody has established.
func parseGrants(specs []string) ([]spacesGrant, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("%s is required for a %s role: they are this credential type's "+
			"privilege boundary, so there is no default (e.g. %s, or %s for the whole account)",
			fieldGrants, credentialTypeSpacesKey, "backups:read", grantAllBuckets+grantSeparator+permissionFullAccess)
	}

	grants := make([]spacesGrant, 0, len(specs))
	for _, spec := range specs {
		bucket, permission, found := strings.Cut(strings.TrimSpace(spec), grantSeparator)
		if !found {
			return nil, fmt.Errorf("grant %q is not %s: use bucket%spermission, e.g. %s",
				spec, "bucket"+grantSeparator+"permission", grantSeparator, "backups:read")
		}
		bucket, permission = strings.TrimSpace(bucket), strings.TrimSpace(permission)
		if bucket == "" {
			return nil, fmt.Errorf("grant %q names no bucket: use %s to grant across the whole "+
				"account, so that an account-wide grant is written deliberately rather than by "+
				"leaving a field blank", spec, grantAllBuckets)
		}
		if permission == "" {
			return nil, fmt.Errorf("grant %q names no permission; expected one of %s, %s or %s",
				spec, permissionRead, permissionReadWrite, permissionFullAccess)
		}

		if err := checkGrantPrivilege(spec, bucket, permission, len(specs)); err != nil {
			return nil, err
		}

		// Account-wide is the empty bucket on the wire; `*` exists only in the role and in
		// what a client is shown.
		wireBucket := bucket
		if bucket == grantAllBuckets {
			wireBucket = ""
		}
		grants = append(grants, spacesGrant{Bucket: wireBucket, Permission: permission})
	}
	return grants, nil
}

// checkGrantPrivilege decides whether one well-formed grant would give the credential the
// privilege the role's text claims. It is separate from the parsing above because it is the
// part that has to be reasoned about: the syntax is a `bucket:permission` split, while these
// are DigitalOcean's own widening behaviours, each of which lets a role read as
// least-privilege while issuing more.
//
// grantCount is the number of grants in the whole role, which the fullaccess rule needs:
// fullaccess is only honest when it is the entire role, because what DigitalOcean does
// with it beside a scoped grant is undetermined — see parseGrants.
func checkGrantPrivilege(spec, bucket, permission string, grantCount int) error {
	switch permission {
	case permissionRead, permissionReadWrite:
		if bucket == grantAllBuckets {
			// DigitalOcean's own account-wide grant is fullaccess; whether it honours a
			// narrower one across every bucket is not established, and a grant that is
			// silently widened is exactly what this check exists to prevent.
			return fmt.Errorf("grant %q asks for %s across the whole account, which "+
				"DigitalOcean does not express: name the buckets, or use %s",
				spec, permission, grantAllBuckets+grantSeparator+permissionFullAccess)
		}
	case permissionFullAccess:
		if bucket != grantAllBuckets {
			return fmt.Errorf("grant %q attaches %s to a single bucket, which DigitalOcean's "+
				"spec never shows: its only example of that permission pairs it with an empty "+
				"bucket — the whole account — and says nothing about what naming a bucket "+
				"beside it does; write %s to grant across the account, or %s to stay in one",
				spec, permissionFullAccess,
				grantAllBuckets+grantSeparator+permissionFullAccess, permissionReadWrite)
		}
		if grantCount > 1 {
			return fmt.Errorf("%s cannot be combined with per-bucket grants: DigitalOcean's "+
				"spec says both that the mix is refused (a documented 400) and that %s is "+
				"PRIORITISED when both are sent, so the request either fails or silently "+
				"yields an account-wide key while this role reads as least-privilege; "+
				"write %s alone, or drop it",
				permissionFullAccess, permissionFullAccess,
				grantAllBuckets+grantSeparator+permissionFullAccess)
		}
	default:
		return fmt.Errorf("grant %q uses an unknown permission %q; expected %s, %s or %s",
			spec, permission, permissionRead, permissionReadWrite, permissionFullAccess)
	}
	return nil
}

// renderGrants turns wire-form grants back into role/scope specs, so a role read and
// metadata.scope report what was written rather than DO's blank-means-everything form.
func renderGrants(grants []spacesGrant) []string {
	specs := make([]string, 0, len(grants))
	for _, g := range grants {
		bucket := g.Bucket
		if bucket == "" {
			bucket = grantAllBuckets
		}
		specs = append(specs, bucket+grantSeparator+g.Permission)
	}
	return specs
}

// spacesEndpointForRegion derives the S3 endpoint from a Spaces region. Derived rather
// than required of an operator because getting it wrong yields a credential that
// authenticates and then addresses the wrong datacentre; an operator whose Spaces sit
// behind a different host overrides it explicitly with the role's `endpoint` field.
func spacesEndpointForRegion(region string) string {
	return "https://" + region + ".digitaloceanspaces.com"
}
