// Package plugintest provides shared resilience-test scaffolding for the
// cloud credential plugins. It is parameterized by a Harness so it never
// imports a specific plugin (which would create an import cycle).
package plugintest

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Harness is supplied by each plugin's resilience_test.go.
type Harness struct {
	Factory                  logical.Factory
	Configure                func(t *testing.T, b logical.Backend, storage logical.Storage)
	IssuePath                string
	RewriteDefaultSetWithout func(t *testing.T, b logical.Backend, storage logical.Storage)
	ProvisionedCount         func() int
	ExpectsHardRevoke        bool
}

func newConfiguredBackend(t *testing.T, h Harness) (logical.Backend, logical.Storage) {
	t.Helper()
	cfg := logical.TestBackendConfig()
	cfg.StorageView = &logical.InmemStorage{}
	b, err := h.Factory(context.Background(), cfg)
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	h.Configure(t, b, cfg.StorageView)
	return b, cfg.StorageView
}

// ReloadBackend calls the factory again against the same storage, with no
// intervening config write — simulating a raft failover / plugin reload /
// process restart where only persisted state is available.
func ReloadBackend(t *testing.T, factory logical.Factory, storage logical.Storage) logical.Backend {
	t.Helper()
	cfg := logical.TestBackendConfig()
	cfg.StorageView = storage
	b, err := factory(context.Background(), cfg)
	if err != nil {
		t.Fatalf("reload factory failed: %v", err)
	}
	return b
}

func issue(t *testing.T, b logical.Backend, storage logical.Storage, path string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   storage,
	})
}
