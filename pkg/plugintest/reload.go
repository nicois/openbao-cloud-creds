package plugintest

import (
	"testing"
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
