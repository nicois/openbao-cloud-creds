package plugintest

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// RunReloadSuite verifies a backend rehydrated from persisted storage (no
// config write) can still issue credentials, and that the persisted role keeps
// its minter-set binding. Catches KI-001: a config field set only in
// pathConfigWrite and never reloaded in Factory.
func RunReloadSuite(t *testing.T, h Harness) {
	t.Run("ReloadFromStorageThenIssue", func(t *testing.T) {
		_, storage := newConfiguredBackend(t, h)
		b2 := Reload(t, h, storage)
		resp, err := issue(t, b2, storage, h.IssuePath)
		if err != nil {
			t.Fatalf("issue after reload errored: %v", err)
		}
		if resp == nil || resp.IsError() {
			t.Fatalf("issue after reload failed (KI-001): %v", resp)
		}
		if resp.Data["credential"] == nil {
			t.Fatalf("issue after reload returned no credential: %v", resp.Data)
		}
	})

	t.Run("InitializeRehydratesAndIssues", func(t *testing.T) { assertInitializeRehydrates(t, h) })

	t.Run("ReloadPreservesRoleAndSet", func(t *testing.T) {
		_, storage := newConfiguredBackend(t, h)
		b2 := Reload(t, h, storage)
		resp := Read(t, b2, storage, h.RolePath)
		if resp == nil || resp.IsError() {
			t.Fatalf("role read after reload failed: %v", resp)
		}
		if resp.Data["minter_set"] != "default" {
			t.Fatalf("reloaded role lost minter_set binding: %v", resp.Data["minter_set"])
		}
	})
}

// assertInitializeRehydrates drives Initialize the way core does. Core calls it on
// a backend it has just built — after mount setup, an unseal, or a plugin reload —
// and that is where the background workers start (KI-007): a plugin with no
// InitializeFunc silently has no health checks, no metrics flush and no reconciler
// on a failed-over node. It is called twice here because an unseal after a reload
// does exactly that, and a plugin whose Initialize errors makes the mount unusable.
func assertInitializeRehydrates(t *testing.T, h Harness) {
	t.Helper()
	_, storage := newConfiguredBackend(t, h)
	b2 := Reload(t, h, storage)
	ctx := context.Background()
	t.Cleanup(func() { b2.Cleanup(ctx) })
	for pass := range 2 {
		if err := b2.Initialize(ctx, &logical.InitializationRequest{Storage: storage}); err != nil {
			t.Fatalf("Initialize (pass %d) failed, which would fail the mount: %v", pass, err)
		}
	}
	mustIssue(t, b2, storage, h.IssuePath)
}
