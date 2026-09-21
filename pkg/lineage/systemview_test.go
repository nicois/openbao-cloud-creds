package lineage

import "github.com/openbao/openbao/sdk/v2/logical"

// mapSystemView answers EntityInfo per entity id. The SDK's StaticSystemView returns the
// same entity for every id, which cannot express "the parent is a different entity" — the
// one relationship these tests exist to cover.
type mapSystemView struct {
	logical.StaticSystemView
	entities map[string]*logical.Entity
}

func (m *mapSystemView) EntityInfo(entityID string) (*logical.Entity, error) {
	return m.entities[entityID], nil
}

// aliasWithCustom builds an entity whose single alias carries custom_metadata.
func aliasWithCustom(id string, custom map[string]string) *logical.Entity {
	return &logical.Entity{ID: id, Aliases: []*logical.Alias{{Name: id, CustomMetadata: custom}}}
}
