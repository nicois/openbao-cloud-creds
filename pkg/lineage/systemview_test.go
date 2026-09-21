package lineage

import (
	"errors"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// mapSystemView answers EntityInfo per entity id. The SDK's StaticSystemView returns the
// same entity for every id, which cannot express "the parent is a different entity" — the
// one relationship these tests exist to cover.
type mapSystemView struct {
	logical.StaticSystemView
	entities map[string]*logical.Entity
	// unreadable names ids the identity store FAILS on rather than answering nil for. The two are
	// different incidents and carry different error codes, so a view that can only answer nil
	// cannot exercise the distinction.
	unreadable map[string]bool
}

// errIdentityStore stands in for whatever a real EntityInfo returns when the identity store cannot
// be read — the tests care only that an error came back, never which one.
var errIdentityStore = errors.New("identity store unavailable")

func (m *mapSystemView) EntityInfo(entityID string) (*logical.Entity, error) {
	if m.unreadable[entityID] {
		return nil, errIdentityStore
	}
	return m.entities[entityID], nil
}

// aliasWithCustom builds an entity whose single alias carries custom_metadata.
func aliasWithCustom(id string, custom map[string]string) *logical.Entity {
	return &logical.Entity{ID: id, Aliases: []*logical.Alias{{Name: id, CustomMetadata: custom}}}
}
