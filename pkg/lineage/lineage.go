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
// Only from the identity store: an alias's custom_metadata (written deliberately, through the
// identity endpoints, and never touched by a login), an alias's metadata (written by the auth method
// at login), or the entity's own metadata. There is NO request parameter, for the reason
// pkg/requester gives: a forgeable value here would let one unit record another's lineage against a
// credential it obtained, which is worse than recording nothing.
//
// # What that does and does not rule out
//
// None of the three is writable through THIS mount's request path, and custom_metadata is not
// writable by a login either — so a client presenting a token cannot change what it resolves to.
// That is the whole guarantee, and it is narrower than "a client cannot write it".
//
// Alias metadata is the gap, on the auth method this package exists for. OpenBao's approle login
// sets Alias{Name: role.RoleID, Metadata: metadata} from the presenting SecretID's OWN metadata,
// which is arbitrary key/value supplied when the SecretID was created. So wherever a unit may create
// its own SecretIDs — self-rotation, or a CI job that both issues and consumes them — that unit can
// write cloud_creds_parent_entity_id naming any live service, and live_parent will accept it. The
// same fact stated from the other side is in docs/decisions.md: the value is self-asserted, approle
// validates nothing, and authenticity needs a wrapper in front of the credential's CREATION rather
// than a check at the mint.
//
// Source is recorded on every record for exactly this reason, so a report can tell a deliberate
// claim from a login-supplied one rather than having to trust both equally. Restricting live_parent
// to custom_metadata is deliberately NOT done here: it would make the requirement unusable on any
// substrate that publishes the parent at login, which is a design decision with its own trade-off —
// noted as a possible follow-up in docs/decisions.md.
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
// none — a responder chases the wrong unit while the real one keeps its access. The same rule applies
// to the unit name, scoped to it: two aliases that agree on the parent and disagree on the unit keep
// the parent and report no unit.
func Resolve(req *logical.Request, view logical.SystemView) Lineage {
	// The identity store's own failure is dropped here rather than surfaced: a caller that only
	// wants to RECORD lineage has nothing to do with it, and "no lineage established" is the honest
	// answer whether the store said so or failed to answer. Enforce uses the form that keeps it,
	// because there the two absences deserve different error codes.
	found, _ := resolveCaller(req, view)
	return found
}

// resolveCaller is Resolve with the identity-store read's failure kept, so Enforce can tell a caller
// nobody has CLAIMED (the provisioner must fix it) from an identity store that did not ANSWER
// (retry, and page someone). Only the caller's own read is reported: an absent entity is not an
// error, it is a caller with no lineage.
func resolveCaller(req *logical.Request, view logical.SystemView) (Lineage, error) {
	if req == nil || req.EntityID == "" || view == nil {
		return Lineage{}, nil
	}
	entity, err := view.EntityInfo(req.EntityID)
	if err != nil {
		return Lineage{}, fmt.Errorf("reading the caller's entity %q: %w", req.EntityID, err)
	}
	if entity == nil {
		return Lineage{}, nil
	}
	if found, agreed := fromAliases(entity.Aliases); agreed {
		if found.ParentEntityID != "" {
			return found, nil
		}
		// Fallback: entity metadata when no alias carried a parent at all.
		return fromMetadata(entity.Metadata, SourceEntityMetadata), nil
	}
	// The aliases DISAGREED, which is a refusal to guess rather than an absence — so the entity's
	// own metadata is deliberately not consulted as a tie-break. A third opinion cannot turn two
	// contradictory claims into one true one, and treating it as one would make the attribution
	// depend on which alias the caller happened to log in through.
	return Lineage{}, nil
}

// fromAliases resolves the lineage an entity's aliases agree on. agreed is false when two aliases
// name DIFFERENT parents.
//
// Within one alias, custom_metadata wins over metadata; conflict detection applies only ACROSS
// aliases, because one alias carrying both is a provisioner's deliberate claim overriding what a
// login wrote, not a disagreement between two claimants.
func fromAliases(aliases []*logical.Alias) (Lineage, bool) {
	var found Lineage
	// Tracked apart from found.UnitID so that a third alias agreeing with the first cannot refill a
	// unit name two earlier aliases already contradicted each other about.
	unitDisputed := false
	for _, alias := range aliases {
		if alias == nil {
			continue
		}
		next := fromMetadata(alias.CustomMetadata, SourceAliasCustomMetadata)
		if next.ParentEntityID == "" {
			next = fromMetadata(alias.Metadata, SourceAliasMetadata)
		}
		if next.ParentEntityID == "" {
			continue
		}
		if found.ParentEntityID == "" {
			found = next
			continue
		}
		if found.ParentEntityID != next.ParentEntityID {
			return Lineage{}, false
		}
		// Same parent, and the unit names may still differ. An alias that named no unit is not a
		// competing claim, so it fills a gap rather than creating one — which is also what makes
		// the answer independent of the order the aliases happen to arrive in.
		switch {
		case next.UnitID == "" || next.UnitID == found.UnitID:
			// Nothing said, or the same thing said twice.
		case found.UnitID == "":
			found.UnitID = next.UnitID
		default:
			unitDisputed = true
		}
	}
	if unitDisputed {
		// The same rule the parent conflict above applies, scoped to the field actually in dispute:
		// a gap beats a misattribution, and a report naming the wrong unit sends a responder to the
		// wrong host. The parent is kept because two aliases CORROBORATED it, and discarding a claim
		// nothing contradicts would lose the answer this package exists to give.
		found.UnitID = ""
	}
	return found, true
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

// Enforce returns the refusal a role's stored requirement demands (or nil to proceed) together with
// the lineage it resolved.
//
// The Lineage comes back so Stamp can record exactly what was enforced. Resolving again at the
// tracking site would read the identity store a second time and leave a window in which the parent a
// role approved and the parent its record names could differ — and a record that disagrees with the
// decision is worse than either, because it is the record an incident is read from. It is returned
// even when the requirement is RequireNone, because recording is not conditional on enforcing.
//
// Shaped like requester.Enforce otherwise — it takes the raw stored string, parses it here so an
// unrecognised value fails closed at one site, and returns the RESPONSE so ten plugins cannot drift
// into ten wordings. Called BEFORE a minter is selected, so a refused request costs the upstream
// nothing.
func Enforce(req *logical.Request, view logical.SystemView, value string,
) (Lineage, *logical.Response) {
	requirement, err := ParseRequirement(value)
	if err != nil {
		// Fail CLOSED on a value this binary does not understand: treating it as RequireNone would
		// turn a role written by a newer binary into one that issues to anybody.
		return Lineage{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error())
	}

	found, resolveErr := resolveCaller(req, view)
	if requirement == RequireNone {
		// resolveErr is deliberately not refused on here: a role that demands nothing must keep
		// issuing exactly what it issued before this field existed, and an identity store that did
		// not answer means only that this one credential is recorded without a parent. Recording is
		// best-effort; enforcing is not.
		return found, nil
	}
	if resolveErr != nil {
		// A different code from the unparented one below, because the two send an operator to
		// different places and tell the client different things. A caller with no parent is a
		// provisioner that never claimed its unit — do not retry, fix it. An identity store that did
		// not answer is nobody's configuration: reporting it as caller_unparented would tell the
		// client not to retry a request that would succeed, and send a responder to chase a
		// provisioner that is fine.
		return found, credenvelope.ErrorResponse(credenvelope.ErrEntityUnavailable,
			"this role requires %s=%s and the caller's own entity could not be read",
			FieldRequireCallerLineage, requirement)
	}
	if found.ParentEntityID == "" {
		return found, credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and no parent is recorded against this caller's identity "+
				"(expected %s in an entity alias's custom_metadata or metadata, or on the entity); "+
				"the unit's provisioner records it",
			FieldRequireCallerLineage, requirement, MetaParentEntityID)
	}
	if requirement == RequireParent {
		return found, nil
	}

	if found.ParentEntityID == req.EntityID {
		// A unit that named itself is its own parent, which is a lineage of one and no lineage at
		// all. Refused here rather than in Resolve so `parent` stays the cheap "is anything
		// recorded" check and the cycle rule lives with the liveness rule it belongs to.
		return found, credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and the caller names ITSELF as its parent",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	parent, err := view.EntityInfo(found.ParentEntityID)
	if err != nil {
		return found, credenvelope.ErrorResponse(credenvelope.ErrEntityUnavailable,
			"this role requires %s=%s and the caller's parent entity could not be read",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	if parent == nil {
		return found, credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and the caller's parent entity no longer exists",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	if parent.Disabled {
		return found, credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and the caller's parent entity is disabled",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	return found, nil
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

// Stamp copies an already-resolved lineage into an existing tracking record.
//
// Takes the Lineage rather than resolving one of its own, so the record names exactly the parent
// Enforce weighed (see Enforce) and one issuance reads the identity store once. A caller with no
// lineage to hand passes the zero value and nothing is written — which is what the rotation of a
// credential the whole ROLE shares does, since no single reader obtained it.
//
// Takes the record rather than returning a new map, for the reason requester.Stamp does: a plugin
// must not be able to build its record from lineage alone and lose its own fields. Writes nothing
// when nothing resolved — an empty parent recorded as a field would read, in a report, as a unit
// whose service is the empty string rather than as a unit nobody has claimed.
func Stamp(record map[string]any, found Lineage) map[string]any {
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
