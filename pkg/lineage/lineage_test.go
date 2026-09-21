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

func TestStampAddsOnlyWhatResolved(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{
		"child": aliasWithCustom("child", map[string]string{
			MetaParentEntityID: "service", MetaUnitID: "unit-7",
		}),
	}}

	record := map[string]any{"role": "reader"}
	Stamp(record, &logical.Request{EntityID: "child"}, view)

	for key, want := range map[string]any{
		"role": "reader", FieldParentEntityID: "service", FieldUnitID: "unit-7",
		FieldSource: string(SourceAliasCustomMetadata),
	} {
		if record[key] != want {
			t.Errorf("record[%q] = %v, want %v", key, record[key], want)
		}
	}
}

func TestStampAddsNothingWhenNothingResolved(t *testing.T) {
	record := map[string]any{"role": "reader"}
	Stamp(record, &logical.Request{}, &mapSystemView{})

	if len(record) != 1 {
		t.Errorf("record = %v, want only its original key: an absent parent must not be "+
			"recorded as an empty one, which a report would read as a unit with no service",
			record)
	}
}
