// Package lineage records and enforces WHICH PARENT the caller of a credential belongs to, so an
// issued credential names a unit's service and not merely the token that asked.
//
// # Why this is not pkg/requester, which already records the caller
//
// Provenance records what core hands every backend: the token accessor and the entity id. That names
// a SESSION and an ENTITY, and on the commonest auth method an entity is not a unit — approle sets
// Alias.Name to the RoleID, so every unit sharing a role resolves to one entity (see the 2026-09-21
// notes in docs/decisions.md). So provenance answers "which role logged in", and the question an
// incident asks — "which unit, and whose is it" — needs one more hop.
//
// # Where lineage may come from, and why nowhere else
//
// Only from fields the requesting client cannot write: an alias's custom_metadata (written by an
// operator or provisioner, never touched by a login), an alias's metadata (written by the auth method
// at login), or the entity's own metadata. There is NO request parameter, for the reason pkg/requester
// gives: a forgeable value here would let one unit record another's lineage against a credential it
// obtained, which is worse than recording nothing.
//
// The identity store is also the only substrate available: mount storage is barrier-isolated, so a
// registry kept by another mount is unreadable here, while SystemView.EntityInfo is readable by every
// plugin.
package lineage

import (
	"fmt"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Metadata keys a provisioner writes and every plugin reads. Fixed here rather than configurable: ten
// mounts with a spelling knob each is ten places a typo reads as "this unit has no parent", and
// accepting a second spelling later is additive.
const (
	// MetaParentEntityID is the ENTITY ID of the parent, not a name: it is what EntityInfo takes,
	// which is what lets a role check that the parent is still present and enabled.
	MetaParentEntityID = "cloud_creds_parent_entity_id"
	// MetaUnitID is the provisioner's own stable name for this unit, recorded but never checked —
	// it is for a human reading a report, and an entity can be renamed while this cannot.
	MetaUnitID = "cloud_creds_unit_id"
)

// Source names where a resolved lineage came from. Recorded because the three differ in who could
// have written them: a login rewrites alias metadata on every use, so on a SHARED alias that value is
// whichever unit logged in last, while custom_metadata is written deliberately and stays put.
type Source string

const (
	SourceAliasCustomMetadata Source = "alias_custom_metadata"
	SourceAliasMetadata       Source = "alias_metadata"
	SourceEntityMetadata      Source = "entity_metadata"
)

// Field names stamped onto a tracking record, spelled `requested_by_*` to match pkg/requester so one
// report reads one vocabulary.
const (
	FieldParentEntityID = "requested_by_parent_entity_id"
	FieldUnitID         = "requested_by_unit_id"
	FieldSource         = "requested_by_lineage_source"
)

// Lineage is what this mount could establish about the caller's parent. A zero value means nothing
// was established, which is a legitimate answer and not an error.
type Lineage struct {
	ParentEntityID string
	UnitID         string
	Source         Source
}

// Resolve reads the caller's lineage from the identity store, or returns a zero Lineage.
//
// Returns rather than errors on every absence: a root token has no entity, a mount may serve callers
// nobody has adopted, and a role that does not demand lineage must keep issuing to them. Enforce is
// where absence becomes a refusal.
//
// Two aliases naming DIFFERENT parents resolve to nothing. Picking one would be a coin flip between
// two services, and a credential attributed to the wrong service is worse than one attributed to
// none — a responder chases the wrong unit while the real one keeps its access.
func Resolve(req *logical.Request, view logical.SystemView) Lineage {
	if req == nil || req.EntityID == "" || view == nil {
		return Lineage{}
	}
	entity, err := view.EntityInfo(req.EntityID)
	if err != nil || entity == nil {
		return Lineage{}
	}

	// First pass: check all aliases. Within one alias, custom_metadata wins over metadata; conflict
	// detection applies only ACROSS aliases (if two different aliases answer with different parent
	// entity ids).
	var found Lineage
	for _, alias := range entity.Aliases {
		if alias == nil {
			continue
		}
		// Within this alias, take custom_metadata if it has the key, else metadata.
		next := fromMetadata(alias.CustomMetadata, SourceAliasCustomMetadata)
		if next.ParentEntityID == "" {
			next = fromMetadata(alias.Metadata, SourceAliasMetadata)
		}
		if next.ParentEntityID == "" {
			continue
		}
		// Conflict detection: if two different aliases answer with DIFFERENT parents, return zero.
		if found.ParentEntityID != "" && found.ParentEntityID != next.ParentEntityID {
			return Lineage{}
		}
		if found.ParentEntityID == "" {
			found = next
		}
	}
	if found.ParentEntityID != "" {
		return found
	}
	// Fallback: entity metadata when no alias carried it.
	return fromMetadata(entity.Metadata, SourceEntityMetadata)
}

func fromMetadata(meta map[string]string, source Source) Lineage {
	if meta[MetaParentEntityID] == "" {
		return Lineage{}
	}
	return Lineage{
		ParentEntityID: meta[MetaParentEntityID],
		UnitID:         meta[MetaUnitID],
		Source:         source,
	}
}

// FieldRequireCallerLineage is the ROLE field demanding that this mount can say whose unit the caller
// is. Spelled once here so ten plugins agree on it.
const FieldRequireCallerLineage = "require_caller_lineage"

// Requirement is how much of a caller's lineage a role insists on.
//
// Separate from pkg/requester's require_caller_identity rather than a fourth value on it, because the
// two are ORTHOGONAL, not a ladder: a batch-token caller has no accessor and may still have a
// perfectly good parent, while a service token with an accessor may have none. Folding them into one
// field would force an operator to choose between two unrelated demands.
type Requirement string

const (
	// RequireNone issues to anyone, recording lineage when it resolves. The default, because every
	// role written before this field existed must keep issuing what it issued.
	RequireNone Requirement = "none"
	// RequireParent refuses a caller this mount can establish no parent for. It costs one
	// EntityInfo — the one Resolve already makes — and says nothing about whether that parent
	// still exists.
	RequireParent Requirement = "parent"
	// RequireLiveParent additionally re-reads the parent's own entity and refuses when it is
	// absent or disabled. This is the containment value: disabling one service's entity stops
	// every unit beneath it from obtaining new credentials on every cloud at once, with no sweep
	// and no worker. It costs one additional EntityInfo per issuance, which is a MemDB read in
	// the core process, not an upstream call.
	RequireLiveParent Requirement = "live_parent"
)

// Requirements is the accepted vocabulary, for a field description and for validation.
func Requirements() []Requirement {
	return []Requirement{RequireNone, RequireParent, RequireLiveParent}
}

// ParseRequirement validates a stored or submitted value. An empty string is RequireNone, so a role
// persisted before this field existed parses rather than failing closed on every read.
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
		FieldRequireCallerLineage, RequireNone, RequireParent, RequireLiveParent, value)
}

// Enforce returns the refusal a role's stored requirement demands, or nil to proceed.
//
// Shaped exactly like requester.Enforce — it takes the raw stored string, parses it here so an
// unrecognised value fails closed at one site, and returns the RESPONSE so ten plugins cannot drift
// into ten wordings. Called BEFORE a minter is selected, so a refused request costs the upstream
// nothing.
func Enforce(req *logical.Request, view logical.SystemView, value string) *logical.Response {
	requirement, err := ParseRequirement(value)
	if err != nil {
		// Fail CLOSED on a value this binary does not understand: treating it as RequireNone would
		// turn a role written by a newer binary into one that issues to anybody.
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error())
	}
	if requirement == RequireNone {
		return nil
	}

	found := Resolve(req, view)
	if found.ParentEntityID == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and no parent is recorded against this caller's identity "+
				"(expected %s in an entity alias's custom_metadata or metadata, or on the entity); "+
				"the unit's provisioner records it",
			FieldRequireCallerLineage, requirement, MetaParentEntityID)
	}
	if requirement == RequireParent {
		return nil
	}

	if found.ParentEntityID == req.EntityID {
		// A unit that named itself is its own parent, which is a lineage of one and no lineage at
		// all. Refused here rather than in Resolve so `parent` stays the cheap "is anything
		// recorded" check and the cycle rule lives with the liveness rule it belongs to.
		return credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and the caller names ITSELF as its parent",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	parent, err := view.EntityInfo(found.ParentEntityID)
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrEntityUnavailable,
			"this role requires %s=%s and the caller's parent entity could not be read",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	if parent == nil {
		return credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and the caller's parent entity no longer exists",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	if parent.Disabled {
		return credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and the caller's parent entity is disabled",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	return nil
}

// RoleFieldDescription is the help text for the role field, so an operator reads the same explanation
// on every cloud.
func RoleFieldDescription() string {
	return "Whose unit this role will issue to: " + string(RequireNone) +
		" (anyone; lineage is still recorded when it resolves), " + string(RequireParent) +
		" (refuse a caller no parent is recorded for), or " + string(RequireLiveParent) +
		" (additionally refuse when that parent's entity is absent or disabled, which is what " +
		"makes disabling a service stop its units from obtaining new credentials). Lineage is " +
		"read from " + MetaParentEntityID + " on the caller's entity alias (custom_metadata, " +
		"then metadata) or the entity itself, and there is no request parameter for it. " +
		"Defaults to " + string(RequireNone)
}

// Stamp copies the resolvable lineage fields into an existing tracking record.
//
// Takes the record rather than returning a new map, for the reason requester.Stamp does: a plugin
// must not be able to build its record from lineage alone and lose its own fields. Writes nothing
// when nothing resolved — an empty parent recorded as a field would read, in a report, as a unit
// whose service is the empty string rather than as a unit nobody has claimed.
func Stamp(record map[string]any, req *logical.Request, view logical.SystemView) map[string]any {
	found := Resolve(req, view)
	if found.ParentEntityID == "" {
		return record
	}
	record[FieldParentEntityID] = found.ParentEntityID
	record[FieldSource] = string(found.Source)
	if found.UnitID != "" {
		record[FieldUnitID] = found.UnitID
	}
	return record
}
