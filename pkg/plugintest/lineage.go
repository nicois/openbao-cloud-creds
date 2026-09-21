package plugintest

import (
	"sync/atomic"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/lineage"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The lineage the suite presents, beside provenance's suiteEntityID/suiteTokenAccessor.
const (
	suiteParentEntityID = "conformance-parent-entity-id"
	suiteUnitID         = "conformance-unit-7"
	// suiteUnparentedEntityID is a caller core resolved an entity for, against which no parent
	// is recorded — a unit nobody has claimed, which is the shape a role refuses.
	suiteUnparentedEntityID = "conformance-unparented-entity-id"
)

// lineageView is the identity a lineage case builds its subject over: the suite's caller carries a
// parent in its alias custom_metadata, and that parent is a SECOND entity the case can disable.
//
// It exists because logical.StaticSystemView answers EntityInfo with one entity for every id, which
// cannot express "the caller's parent is a different entity" — the whole relationship under test.
type lineageView struct {
	logical.StaticSystemView
	parentDisabled atomic.Bool
}

// EntityInfo answers for the caller and its parent, and nil for every other id — an unknown id must
// read as "no such entity", which is what a DELETED parent looks like from inside a plugin.
func (v *lineageView) EntityInfo(entityID string) (*logical.Entity, error) {
	switch entityID {
	case suiteEntityID:
		return &logical.Entity{ID: suiteEntityID, Aliases: []*logical.Alias{{
			Name: suiteEntityID,
			CustomMetadata: map[string]string{
				lineage.MetaParentEntityID: suiteParentEntityID,
				lineage.MetaUnitID:         suiteUnitID,
			},
		}}}, nil
	case suiteParentEntityID:
		return &logical.Entity{ID: suiteParentEntityID, Disabled: v.parentDisabled.Load()}, nil
	case suiteUnparentedEntityID:
		return &logical.Entity{ID: suiteUnparentedEntityID, Aliases: []*logical.Alias{{
			Name: suiteUnparentedEntityID,
		}}}, nil
	}
	return nil, nil
}

// withLineageIdentity copies the harness onto a fresh identity, so one case disabling a parent
// cannot leak into another case or another category.
func withLineageIdentity(h Harness) (Harness, *lineageView) {
	view := &lineageView{}
	h.SystemView = view
	return h, view
}

// requireLiveParent sets the role's requirement to live_parent through the role's own write path —
// which is also an assertion, for the reason requireCaller gives: a requirement an operator can only
// set by rewriting the whole role is not one they can add to a role that is already live.
//
// live_parent rather than a parameter, because it is the only value these cases want: `none` is the
// default a role already has, and `parent` is the strictly weaker half that pkg/lineage's own
// TestEnforce covers, branch by branch. A knob with one setting is a knob nobody turns.
func requireLiveParent(t *testing.T, b logical.Backend, storage logical.Storage, rolePath string) {
	t.Helper()
	resp := TryWrite(t, b, storage, rolePath, map[string]any{
		lineage.FieldRequireCallerLineage: string(lineage.RequireLiveParent),
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("writing %s=%s to %s was refused: %v", lineage.FieldRequireCallerLineage,
			lineage.RequireLiveParent, rolePath, resp.Error())
	}
}

// issueAsUnparented reads the issue path as a caller with an entity and an accessor but no recorded
// parent — so a refusal can only be about lineage, not about pkg/requester's requirement.
func issueAsUnparented(t *testing.T, b logical.Backend, storage logical.Storage,
	path string, data map[string]any,
) *logical.Response {
	t.Helper()
	return issueWith(t, b, storage, path, &logical.Request{
		ClientTokenAccessor: suiteTokenAccessor,
		EntityID:            suiteUnparentedEntityID,
		Data:                data,
	})
}

// RunLineageSuite covers WHOSE unit obtained a credential: that a role can demand the caller's
// parent, that an operator can read that demand back, that the demand is checked before anything is
// minted, that a parent an operator has disabled stops issuance at once, that the caller cannot
// supply its own lineage — neither to satisfy the demand nor to land in the record — and that the
// record names it.
//
// Five of the seven cases apply to every subject, because refusing to issue to an unclaimed unit is
// not a question about a cloud. Only the two that read a record need a per-read tracking record, and
// they gate on the same helper the provenance suite uses so there is ONE way to say "this subject
// records nothing per read".
func RunLineageSuite(t *testing.T, h Harness) {
	for _, c := range []struct {
		name string
		run  func(*testing.T, Harness)
	}{
		{"ARoleCanRequireTheCallersParent", lineageRequireParent},
		{"ARoleReportsWhatLineageItRequires", lineageRequirementIsVisible},
		{"ADisabledParentStopsIssuanceAtOnce", lineageDisabledParentStopsIssuance},
		{"LineageCannotBeForgedByTheCaller", lineageCannotBeForged},
		{"AForgedLineageDoesNotLandInTheRecord", lineageRecordCannotBeForged},
		{"RefusingAnUnparentedCallerCostsTheUpstreamNothing", lineageRefusalMintsNothing},
		{"AnIssuedCredentialRecordsWhoseUnitObtainedIt", lineageRecordsTheParent},
	} {
		t.Run(c.name, func(t *testing.T) { c.run(t, h) })
	}
}

// lineageRequirementIsVisible: an operator can read back what lineage the role demands.
//
// The same reasoning as the provenance suite's case — a requirement nobody can read is one nobody can
// audit — plus a hazard specific to how roles are written here. cloudconfig.PrefillRoleWrite fills a
// PARTIAL role write from the plugin's own role-read output, so a plugin that reported everything
// except this field would turn any later partial write (disabled=true, a TTL change) into a silent
// ERASE of an operator's containment requirement. requireLiveParent's own write cannot catch that:
// the field is in the request either way.
func lineageRequirementIsVisible(t *testing.T, h Harness) {
	h, _ = withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)
	requireLiveParent(t, b, storage, h.RolePath)

	role := roleDefinition(t, b, storage, h.RolePath)
	got, present := role[lineage.FieldRequireCallerLineage]
	if !present {
		t.Fatalf("the role read reports no %q field, so an operator cannot audit whose units it "+
			"issues to — and a later partial write would silently erase the requirement, because "+
			"a prefilled write can only carry back what the read reported",
			lineage.FieldRequireCallerLineage)
	}
	if got != string(lineage.RequireLiveParent) {
		t.Errorf("the role reports %s=%v, want %q",
			lineage.FieldRequireCallerLineage, got, lineage.RequireLiveParent)
	}
}

// lineageRequireParent: live_parent refuses an unclaimed unit and issues to a claimed one.
func lineageRequireParent(t *testing.T, h Harness) {
	h, _ = withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)
	requireLiveParent(t, b, storage, h.RolePath)

	resp := issueAsUnparented(t, b, storage, h.IssuePath, nil)
	assertCode(t, resp, credenvelope.ErrCallerUnparented,
		"issuing to a caller no parent is recorded for, from a role requiring one")

	if resp := issueAsCaller(t, b, storage, h.IssuePath, nil); resp == nil || resp.IsError() {
		t.Fatalf("a role requiring %s refused a caller whose parent is present and enabled: %v",
			lineage.RequireLiveParent, resp)
	}
}

// lineageDisabledParentStopsIssuance: disabling the PARENT's entity stops the child at once.
//
// This case is why the requirement has a live_parent value at all. Nothing else changes between the
// two reads — no role write, no config write, no worker tick, no revocation — so what it pins is
// that one operator action against one identity stops issuance to every unit beneath it, on every
// cloud, without this mount being told.
func lineageDisabledParentStopsIssuance(t *testing.T, h Harness) {
	h, view := withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)
	requireLiveParent(t, b, storage, h.RolePath)

	if resp := issueAsCaller(t, b, storage, h.IssuePath, nil); resp == nil || resp.IsError() {
		t.Fatalf("the first read failed, so this case would prove nothing: %v", resp)
	}

	view.parentDisabled.Store(true)

	resp := issueAsCaller(t, b, storage, h.IssuePath, nil)
	assertCode(t, resp, credenvelope.ErrCallerUnparented,
		"issuing to a caller whose parent entity has been disabled")
}

// lineageCannotBeForged: a caller supplying its own lineage does not satisfy the requirement.
//
// The same reasoning as the provenance suite's forgery case, and the reason pkg/lineage has no
// request parameter: a forgeable parent would let any unit claim a live service and be served,
// which is worse than being refused — the credential would then be recorded against a service that
// never asked for it.
func lineageCannotBeForged(t *testing.T, h Harness) {
	h, _ = withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)
	requireLiveParent(t, b, storage, h.RolePath)

	forged := map[string]any{
		lineage.FieldParentEntityID:       suiteParentEntityID,
		lineage.MetaParentEntityID:        suiteParentEntityID,
		lineage.FieldRequireCallerLineage: string(lineage.RequireNone),
	}
	resp := issueAsUnparented(t, b, storage, h.IssuePath, forged)
	assertCode(t, resp, credenvelope.ErrCallerUnparented,
		"issuing to an unparented caller that supplied a parent of its own in the request")
}

// lineageRecordCannotBeForged: what the caller supplied does not reach the record either.
//
// A different property from the case above, and the one that matters on day one. That case proves a
// forged parent cannot SATISFY a requirement; this proves it cannot be RECORDED — on a role with the
// default requirement, which is every role until an operator decides to refuse anyone, and the
// configuration the feature's "recording is not conditional on enforcing" argument is about.
//
// Without it, the forgery is only fenced where pkg/lineage reads the identity store. A plugin that
// merged req.Data into its tracking map would keep every enforcement case green while writing
// whatever the caller asked for — and a record naming a service that never asked for the credential
// is worse than one naming nobody, because a responder chases it.
func lineageRecordCannotBeForged(t *testing.T, h Harness) {
	requireTrackingRecords(t, h, "lineage")
	h, _ = withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)

	// No requireLiveParent call: this runs on the role's DEFAULT requirement.
	forged := map[string]any{
		lineage.FieldParentEntityID: "forged-parent-entity",
		lineage.FieldUnitID:         "forged-unit",
		lineage.FieldSource:         "forged-source",
		lineage.MetaParentEntityID:  "forged-parent-entity",
		lineage.MetaUnitID:          "forged-unit",
	}
	if resp := issueAsCaller(t, b, storage, h.IssuePath, forged); resp == nil || resp.IsError() {
		t.Fatalf("the role could not issue, so this case would prove nothing: %v", resp)
	}

	record := soleTrackingRecord(t, storage, h.TrackingPrefix)
	assertRecordField(t, record, lineage.FieldParentEntityID, suiteParentEntityID)
	assertRecordField(t, record, lineage.FieldUnitID, suiteUnitID)
	assertRecordField(t, record, lineage.FieldSource, string(lineage.SourceAliasCustomMetadata))
}

// lineageRefusalMintsNothing: the check happens before a minter is selected.
//
// Placement is the whole assertion, exactly as it is for provenance: a requirement checked after the
// mint leaves a credential upstream that no lease, no tracking record and no reconciler pass knows
// about — an orphan created by a security control.
func lineageRefusalMintsNothing(t *testing.T, h Harness) {
	h, _ = withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)
	requireLiveParent(t, b, storage, h.RolePath)

	before := h.ProvisionedCount()
	resp := issueAsUnparented(t, b, storage, h.IssuePath, nil)
	assertCode(t, resp, credenvelope.ErrCallerUnparented, "the refused read")

	if after := h.ProvisionedCount(); after != before {
		t.Errorf("a refused read moved the upstream credential count from %d to %d: the "+
			"requirement is being checked after the mint, so every refusal leaves an orphan",
			before, after)
	}
	if h.TrackingPrefix != "" {
		if n := trackingRecords(t, storage, h.TrackingPrefix); n != 0 {
			t.Errorf("a refused read left %d tracking record(s) under %s", n, h.TrackingPrefix)
		}
	}
}

// lineageRecordsTheParent: the record names the parent even when the role demands nothing.
//
// Deliberately run on a role with the DEFAULT requirement: recording is not conditional on
// enforcing. An operator who has not yet decided to refuse anyone still gets a report that answers
// whose unit holds each credential, which is the half of this feature that is useful on day one.
func lineageRecordsTheParent(t *testing.T, h Harness) {
	requireTrackingRecords(t, h, "lineage")
	h, _ = withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)

	if resp := issueAsCaller(t, b, storage, h.IssuePath, nil); resp == nil || resp.IsError() {
		t.Fatalf("the role could not issue, so this case would prove nothing: %v", resp)
	}

	record := soleTrackingRecord(t, storage, h.TrackingPrefix)
	assertRecordField(t, record, lineage.FieldParentEntityID, suiteParentEntityID)
	assertRecordField(t, record, lineage.FieldUnitID, suiteUnitID)
	assertRecordField(t, record, lineage.FieldSource, string(lineage.SourceAliasCustomMetadata))
}
