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

import "github.com/openbao/openbao/sdk/v2/logical"

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
