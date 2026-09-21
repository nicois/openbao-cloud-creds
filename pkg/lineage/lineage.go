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
