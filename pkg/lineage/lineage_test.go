package lineage

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestResolveReadsTheParentFromAliasCustomMetadata(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{
		"child": aliasWithCustom("child", map[string]string{
			MetaParentEntityID: "service", MetaUnitID: "unit-7",
		}),
		"service": {ID: "service"},
	}}

	got := Resolve(&logical.Request{EntityID: "child"}, view)

	if got.ParentEntityID != "service" {
		t.Errorf("ParentEntityID = %q, want %q", got.ParentEntityID, "service")
	}
	if got.UnitID != "unit-7" {
		t.Errorf("UnitID = %q, want %q", got.UnitID, "unit-7")
	}
	if got.Source != SourceAliasCustomMetadata {
		t.Errorf("Source = %q, want %q", got.Source, SourceAliasCustomMetadata)
	}
}

func TestResolveIsEmptyWithoutAnEntity(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{}}

	got := Resolve(&logical.Request{}, view)

	if got.ParentEntityID != "" || got.Source != "" {
		t.Errorf("Resolve on an entity-less request = %+v, want zero", got)
	}
}

func TestResolveFallsBackThroughTheSources(t *testing.T) {
	for _, tc := range []struct {
		name   string
		entity *logical.Entity
		want   Source
	}{
		{
			name: "alias metadata when custom is empty",
			entity: &logical.Entity{ID: "child", Aliases: []*logical.Alias{{
				Name: "child", Metadata: map[string]string{MetaParentEntityID: "service"},
			}}},
			want: SourceAliasMetadata,
		},
		{
			name: "entity metadata when no alias carries it",
			entity: &logical.Entity{
				ID:       "child",
				Metadata: map[string]string{MetaParentEntityID: "service"},
				Aliases:  []*logical.Alias{{Name: "child"}},
			},
			want: SourceEntityMetadata,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := &mapSystemView{entities: map[string]*logical.Entity{"child": tc.entity}}
			got := Resolve(&logical.Request{EntityID: "child"}, view)
			if got.ParentEntityID != "service" || got.Source != tc.want {
				t.Errorf("Resolve = %+v, want parent %q from %q", got, "service", tc.want)
			}
		})
	}
}

func TestResolveRefusesToChooseBetweenTwoParents(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{"child": {
		ID: "child",
		Aliases: []*logical.Alias{
			{Name: "a", CustomMetadata: map[string]string{MetaParentEntityID: "service-a"}},
			{Name: "b", CustomMetadata: map[string]string{MetaParentEntityID: "service-b"}},
		},
	}}}

	if got := Resolve(&logical.Request{EntityID: "child"}, view); got.ParentEntityID != "" {
		t.Errorf("Resolve with conflicting aliases = %+v, want zero: naming one of two "+
			"services is misattribution", got)
	}
}

func TestResolveCustomMetadataWinsOverMetadataInTheSameAlias(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{"child": {
		ID: "child",
		Aliases: []*logical.Alias{{
			Name: "child",
			CustomMetadata: map[string]string{
				MetaParentEntityID: "service-custom",
				MetaUnitID:         "unit-custom",
			},
			Metadata: map[string]string{
				MetaParentEntityID: "service-metadata",
				MetaUnitID:         "unit-metadata",
			},
		}},
	}}}

	got := Resolve(&logical.Request{EntityID: "child"}, view)

	if got.ParentEntityID != "service-custom" {
		t.Errorf("ParentEntityID = %q, want %q (custom_metadata should win over metadata)",
			got.ParentEntityID, "service-custom")
	}
	if got.UnitID != "unit-custom" {
		t.Errorf("UnitID = %q, want %q", got.UnitID, "unit-custom")
	}
	if got.Source != SourceAliasCustomMetadata {
		t.Errorf("Source = %q, want %q", got.Source, SourceAliasCustomMetadata)
	}
}

func TestResolveWillNotChooseBetweenTwoUnitsOfOneService(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{"child": {
		ID: "child",
		Aliases: []*logical.Alias{
			{Name: "a", CustomMetadata: map[string]string{
				MetaParentEntityID: "service", MetaUnitID: "unit-a",
			}},
			{Name: "b", CustomMetadata: map[string]string{
				MetaParentEntityID: "service", MetaUnitID: "unit-b",
			}},
		},
	}}}

	got := Resolve(&logical.Request{EntityID: "child"}, view)

	if got.UnitID != "" {
		t.Errorf("UnitID = %q, want empty: naming one of two units is the same misattribution "+
			"as naming one of two services, and a report naming the wrong unit sends a responder "+
			"to the wrong host", got.UnitID)
	}
	if got.ParentEntityID != "service" {
		t.Errorf("ParentEntityID = %q, want %q: both aliases agreed on it, so the disputed unit "+
			"must not cost the corroborated service", got.ParentEntityID, "service")
	}
}

func TestResolveFillsAUnitNameNoAliasContradicts(t *testing.T) {
	// Order-independence is the property: alias iteration is not ordered by anything a caller
	// controls, so an alias that named no unit must not be able to hide one that did.
	for _, order := range [][]*logical.Alias{
		{
			{Name: "a", CustomMetadata: map[string]string{MetaParentEntityID: "service"}},
			{Name: "b", CustomMetadata: map[string]string{
				MetaParentEntityID: "service", MetaUnitID: "unit-7",
			}},
		},
		{
			{Name: "b", CustomMetadata: map[string]string{
				MetaParentEntityID: "service", MetaUnitID: "unit-7",
			}},
			{Name: "a", CustomMetadata: map[string]string{MetaParentEntityID: "service"}},
		},
	} {
		view := &mapSystemView{entities: map[string]*logical.Entity{
			"child": {ID: "child", Aliases: order},
		}}
		if got := Resolve(&logical.Request{EntityID: "child"}, view); got.UnitID != "unit-7" {
			t.Errorf("UnitID = %q, want %q: an alias that named no unit is not a competing claim",
				got.UnitID, "unit-7")
		}
	}
}

func TestStampAddsOnlyWhatResolved(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{
		"child": aliasWithCustom("child", map[string]string{
			MetaParentEntityID: "service", MetaUnitID: "unit-7",
		}),
	}}

	record := map[string]any{"role": "reader"}
	req := &logical.Request{EntityID: "child"}
	Stamp(record, Resolve(req, view))

	for key, want := range map[string]any{
		"role": "reader", FieldParentEntityID: "service", FieldUnitID: "unit-7",
		FieldSource: string(SourceAliasCustomMetadata),
	} {
		if record[key] != want {
			t.Errorf("record[%q] = %v, want %v", key, record[key], want)
		}
	}
}

// TestStampAddsNothingWhenNothingResolved uses a caller the view KNOWS, whose identity simply
// carries no parent. An entity-less request would short-circuit Resolve before it read the view, so
// the case would pass with the metadata lookup entirely broken — which is the shape of an assertion
// that proves nothing.
func TestStampAddsNothingWhenNothingResolved(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{
		"unclaimed": aliasWithCustom("unclaimed", map[string]string{"unrelated": "value"}),
	}}

	record := map[string]any{"role": "reader"}
	Stamp(record, Resolve(&logical.Request{EntityID: "unclaimed"}, view))

	if len(record) != 1 {
		t.Errorf("record = %v, want only its original key: an absent parent must not be "+
			"recorded as an empty one, which a report would read as a unit with no service",
			record)
	}
}

// TestEnforce is the table for the decision every plugin delegates to this package. It asserts the
// error CODE rather than merely that a refusal happened, because the code is the whole client-facing
// contract here: some of these refusals mean "fix the provisioner and do not retry" and others mean
// "the identity store did not answer, retry", and a test that only counted refusals would let the
// two swap places silently.
func TestEnforce(t *testing.T) {
	child := aliasWithCustom("child", map[string]string{MetaParentEntityID: "service"})
	orphan := aliasWithCustom("orphan", map[string]string{MetaParentEntityID: "gone"})
	bare := map[string]*logical.Entity{"bare": {ID: "bare"}}
	live := map[string]*logical.Entity{"child": child, "service": {ID: "service"}}

	for _, tc := range []struct {
		name       string
		entities   map[string]*logical.Entity
		unreadable map[string]bool
		entityID   string
		value      string
		// wantCode is the error_code the refusal must carry; empty means the read must be allowed.
		wantCode credenvelope.ErrorCode
	}{
		{
			// The backward-compatibility guarantee: every role written before this field existed
			// stores an empty value and must keep issuing to exactly the callers it did.
			name:     "none issues to a caller with no lineage at all",
			entities: bare, entityID: "bare", value: string(RequireNone),
		},
		{
			// Recording is best-effort where enforcing is not: a role that demands nothing must not
			// start refusing its fleet because the identity store hiccuped.
			name:     "none issues even when the identity store cannot be read",
			entities: bare, unreadable: map[string]bool{"bare": true},
			entityID: "bare", value: string(RequireNone),
		},
		{
			name:     "parent refuses a caller with no lineage",
			entities: bare, entityID: "bare", value: string(RequireParent),
			wantCode: credenvelope.ErrCallerUnparented,
		},
		{
			// What makes `parent` the cheaper half: the named parent does not exist in this view at
			// all, and `parent` still issues, because it asks only whether anything is recorded.
			// `live_parent` is the value that refuses this same caller, two cases below.
			name:     "parent accepts a recorded parent without checking it",
			entities: map[string]*logical.Entity{"orphan": orphan},
			entityID: "orphan", value: string(RequireParent),
		},
		{
			// A store that did not ANSWER is not a caller that has no parent: caller_unparented
			// would tell the client not to retry a request that would succeed, and send a responder
			// to chase a provisioner that is fine.
			name:     "parent reports an unreadable caller entity as unavailable, not unparented",
			entities: live, unreadable: map[string]bool{"child": true},
			entityID: "child", value: string(RequireParent),
			wantCode: credenvelope.ErrEntityUnavailable,
		},
		{
			name:     "live_parent refuses a parent that has been deleted",
			entities: map[string]*logical.Entity{"orphan": orphan},
			entityID: "orphan", value: string(RequireLiveParent),
			wantCode: credenvelope.ErrCallerUnparented,
		},
		{
			name: "live_parent refuses a parent that is disabled",
			entities: map[string]*logical.Entity{
				"child": child, "service": {ID: "service", Disabled: true},
			},
			entityID: "child", value: string(RequireLiveParent),
			wantCode: credenvelope.ErrCallerUnparented,
		},
		{
			name:     "live_parent accepts a present enabled parent",
			entities: live, entityID: "child", value: string(RequireLiveParent),
		},
		{
			// A lineage of one is no lineage: it would satisfy the requirement while naming nobody
			// above the caller, which is the only thing the requirement is asking for.
			name: "live_parent refuses a unit that named itself",
			entities: map[string]*logical.Entity{
				"self": aliasWithCustom("self", map[string]string{MetaParentEntityID: "self"}),
			},
			entityID: "self", value: string(RequireLiveParent),
			wantCode: credenvelope.ErrCallerUnparented,
		},
		{
			name:     "live_parent reports an unreadable parent entity as unavailable",
			entities: live, unreadable: map[string]bool{"service": true},
			entityID: "child", value: string(RequireLiveParent),
			wantCode: credenvelope.ErrEntityUnavailable,
		},
		{
			// A role written by a NEWER binary must not read as "issue to anybody" on this one,
			// which is what treating an unrecognised value as RequireNone would do.
			name:     "an unreadable requirement fails closed",
			entities: live, entityID: "child", value: "whatever-a-newer-binary-wrote",
			wantCode: credenvelope.ErrConfigInvalid,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := &mapSystemView{entities: tc.entities, unreadable: tc.unreadable}

			_, resp := Enforce(&logical.Request{EntityID: tc.entityID}, view, tc.value)

			if tc.wantCode == "" {
				if resp != nil {
					t.Fatalf("Enforce refused with %v, want it to proceed", resp.Error())
				}
				return
			}
			if resp == nil {
				t.Fatalf("Enforce allowed the read, want a refusal carrying %q", tc.wantCode)
			}
			got, known := credenvelope.CodeOf(resp.Error().Error())
			if !known {
				t.Fatalf("the refusal carries no recognised error_code: %q", resp.Error())
			}
			if got != tc.wantCode {
				t.Errorf("error_code is %q, want %q (message: %q)", got, tc.wantCode, resp.Error())
			}
		})
	}
}

// TestEnforceReturnsWhatItResolved pins the half of Enforce's contract the tracking record depends
// on. A record is stamped from this value rather than from a second lookup, so an Enforce that
// allowed the read and reported nothing would leave every credential unattributed while every
// refusal case above stayed green — and on a `none` role, which records without enforcing, there is
// no refusal to notice the loss by either.
func TestEnforceReturnsWhatItResolved(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{
		"child": aliasWithCustom("child", map[string]string{
			MetaParentEntityID: "service", MetaUnitID: "unit-7",
		}),
		"service": {ID: "service"},
	}}

	for _, value := range Requirements() {
		t.Run(string(value), func(t *testing.T) {
			found, resp := Enforce(&logical.Request{EntityID: "child"}, view, string(value))
			if resp != nil {
				t.Fatalf("Enforce refused a claimed caller: %v", resp.Error())
			}
			if found.ParentEntityID != "service" || found.UnitID != "unit-7" {
				t.Errorf("Enforce returned %+v, want the resolved parent and unit: Stamp records "+
					"this value, so losing it here records nothing anywhere", found)
			}
		})
	}
}

func TestParseRequirementTreatsEmptyAsNone(t *testing.T) {
	got, err := ParseRequirement("")
	if err != nil || got != RequireNone {
		t.Errorf("ParseRequirement(%q) = %q, %v; want %q, nil — a role persisted before this "+
			"field existed must still load", "", got, err, RequireNone)
	}
}

func TestParseRequirementAcceptsEveryPublishedValueAndNothingElse(t *testing.T) {
	for _, known := range Requirements() {
		if got, err := ParseRequirement(string(known)); err != nil || got != known {
			t.Errorf("ParseRequirement(%q) = %q, %v; want it accepted — Requirements() is what the "+
				"role field's own help text offers an operator", known, got, err)
		}
	}
	// `any` and `token_accessor` belong to require_caller_identity, a SEPARATE and orthogonal
	// field: accepting one here would turn an operator's confusion between the two into a
	// requirement they did not write.
	for _, unknown := range []string{"any", "token_accessor", "live-parent", "NONE", " none"} {
		if _, err := ParseRequirement(unknown); err == nil {
			t.Errorf("ParseRequirement(%q) was accepted, want rejected", unknown)
		}
	}
}
