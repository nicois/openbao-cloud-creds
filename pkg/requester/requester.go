// Package requester records WHICH caller obtained an issued credential, so a credential found
// upstream can be traced back to the identity that asked for it.
//
// This exists because the tracking record every plugin writes at mint time says what was issued and
// by which minter, but not to whom — so a leaked cloud credential could be traced to a mount and a
// role, and no further. The question an incident actually asks is "which unit is compromised", and
// that answer was being discarded: `logical.Request` carries it, and every plugin dropped it.
//
// # Why this is not pkg/minteraffinity, which already binds the same fields
//
// Affinity derives a shard key from the same request, and deliberately lets a caller override it with
// `shard_key` — spreading work across minters is the caller's business, so naming its own shard is a
// feature.
//
// Provenance must do the OPPOSITE. A caller-supplied value here would let one unit record another
// unit's identity against a credential it obtained, which is worse than recording nothing: an
// incident responder would chase the wrong service while the real one kept its access. So this reads
// only fields OpenBao core populates from the token presenting the request, and there is no override.
//
// The two therefore share the request fields and differ on the override, which is why the derivation
// lives here rather than being reused from Key().
package requester

import (
	"fmt"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Field names for the provenance stamped onto a tracking record. Named here so all plugins agree:
// a report joining credentials to identities cannot do it if one cloud spells the key differently.
const (
	// FieldTokenAccessor is the accessor of the token that requested the credential. The accessor
	// rather than the token: it identifies the token without being usable as it, so a tracking
	// record is not a credential. It is also what `auth/token/lookup-accessor` takes, which is how a
	// report resolves it back to an identity.
	FieldTokenAccessor = "requested_by_token_accessor"

	// FieldEntityID is the identity entity the request resolved to, when there is one. Recorded
	// alongside rather than instead: an entity outlives the tokens that belong to it, so it answers
	// "which service" after the token is gone, while the accessor answers "which session".
	FieldEntityID = "requested_by_entity_id"
)

// Identity returns the provenance fields for a request, omitting what core did not populate.
//
// Both can legitimately be absent — a root token has no entity, and an internal call may present no
// token at all — so this returns what is known rather than failing. A record with neither field is
// still honest: it says the credential was issued without a resolvable caller, which is itself worth
// seeing in a report.
func Identity(req *logical.Request) map[string]interface{} {
	out := map[string]interface{}{}
	if req == nil {
		return out
	}
	if req.ClientTokenAccessor != "" {
		out[FieldTokenAccessor] = req.ClientTokenAccessor
	}
	if req.EntityID != "" {
		out[FieldEntityID] = req.EntityID
	}
	return out
}

// Stamp copies the provenance fields into an existing tracking record.
//
// Takes the record rather than returning a new map so a plugin cannot accidentally build its record
// from provenance alone and lose its own fields, and so the call reads as one line at the site where
// the record is assembled.
func Stamp(record map[string]interface{}, req *logical.Request) map[string]interface{} {
	for key, value := range Identity(req) {
		record[key] = value
	}
	return record
}

// FieldRequireCallerIdentity is the ROLE field an operator sets to demand that a credential is
// only issued to a caller this mount can name. Spelled once here so ten plugins agree on it.
const FieldRequireCallerIdentity = "require_caller_identity"

// Requirement is how much of a caller's identity a role insists on before it will issue.
//
// Three values rather than a bool, because the two absences are different and an operator needs
// to say which one they will not accept. See the token-type findings in docs/decisions.md: a BATCH
// token has no accessor at all, while a root or otherwise entity-less service token has an
// accessor and no entity. So "somebody is there" and "I can tell which session it was" are
// separate demands, and only the second excludes a batch caller.
type Requirement string

const (
	// RequireNone issues to anyone, recording whatever provenance is resolvable. The default,
	// because every role written before this field existed must keep issuing what it issued.
	RequireNone Requirement = "none"
	// RequireAny refuses a caller core resolved neither an entity nor a token accessor for —
	// an unauthenticated internal call.
	RequireAny Requirement = "any"
	// RequireTokenAccessor additionally refuses a caller with no token accessor, which in
	// practice means a batch token. Its entity is shared with the service token that created
	// it, so on a batch caller the accessor is the only field that distinguishes one unit from
	// another — and a credential traced to a shared entity names a fleet, not a compromise.
	RequireTokenAccessor Requirement = "token_accessor"
)

// Requirements is the accepted vocabulary, for a field description and for validation.
func Requirements() []Requirement {
	return []Requirement{RequireNone, RequireAny, RequireTokenAccessor}
}

// ParseRequirement validates a stored or submitted value. An empty string is RequireNone, so a
// role persisted before the field existed parses rather than failing closed on every read.
func ParseRequirement(value string) (Requirement, error) {
	if value == "" {
		return RequireNone, nil
	}
	for _, known := range Requirements() {
		if Requirement(value) == known {
			return known, nil
		}
	}
	return RequireNone, fmt.Errorf("%s must be one of %s, %s or %s, not %q",
		FieldRequireCallerIdentity, RequireNone, RequireAny, RequireTokenAccessor, value)
}

// Enforce returns the refusal a role's stored requirement demands, or nil to proceed.
//
// Takes the raw stored string and parses it here, so an unrecognised value fails closed at the
// one site that matters rather than at ten call sites that each decided for themselves.
//
// Returning the RESPONSE rather than a bool keeps the code and the wording in one place: ten
// plugins calling this cannot drift into ten different messages, and none of them can reach for
// a code of its own. It is deliberately checked BEFORE a minter is selected, so a refused request
// costs the upstream nothing.
func Enforce(req *logical.Request, value string) *logical.Response {
	requirement, err := ParseRequirement(value)
	if err != nil {
		// Fail CLOSED on a value this binary does not understand. The alternative — treat an
		// unknown requirement as RequireNone — would turn a role written by a newer binary into
		// one that issues to anybody, which is the opposite of what its operator asked for.
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error())
	}
	switch requirement {
	case RequireTokenAccessor:
		if req == nil || req.ClientTokenAccessor == "" {
			return credenvelope.ErrorResponse(credenvelope.ErrCallerUnidentified,
				"this role requires %s=%s and the presented token has no accessor, so the "+
					"credential could not be attributed to one caller (a batch token has no "+
					"accessor; present a service token)",
				FieldRequireCallerIdentity, RequireTokenAccessor)
		}
	case RequireAny:
		if req == nil || (req.ClientTokenAccessor == "" && req.EntityID == "") {
			return credenvelope.ErrorResponse(credenvelope.ErrCallerUnidentified,
				"this role requires %s=%s and core resolved neither an entity nor a token "+
					"accessor for this request", FieldRequireCallerIdentity, RequireAny)
		}
	case RequireNone:
	}
	return nil
}

// RoleFieldDescription is the help text for the role field, so an operator reads the same
// explanation on every cloud.
func RoleFieldDescription() string {
	return "Who this role will issue to: " + string(RequireNone) +
		" (anyone; provenance is still recorded when resolvable), " + string(RequireAny) +
		" (refuse a request core resolved no caller for at all), or " +
		string(RequireTokenAccessor) + " (additionally refuse a caller with no token accessor, " +
		"which is what a batch token is — its entity is shared with the token that created it, " +
		"so the accessor is the only field naming one unit). Defaults to " + string(RequireNone)
}
