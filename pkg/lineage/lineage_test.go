package lineage

import (
	"testing"

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
