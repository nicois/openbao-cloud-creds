package plugintest

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// RunReloadSuite verifies a backend rehydrated from persisted storage (no
// config write) can still issue credentials. Catches KI-001.
func RunReloadSuite(t *testing.T, h Harness) {
	t.Run("ReloadFromStorageThenIssue", func(t *testing.T) {
		_, storage := newConfiguredBackend(t, h)
		b2 := ReloadBackend(t, h.Factory, storage)
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
		b2 := ReloadBackend(t, h.Factory, storage)
		resp, err := b2.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation, Path: "roles/test-role", Storage: storage,
		})
		if err != nil || resp == nil || resp.IsError() {
			t.Fatalf("role read after reload failed: err=%v resp=%v", err, resp)
		}
		if resp.Data["minter_set"] != "default" {
			t.Fatalf("reloaded role lost minter_set binding: %v", resp.Data["minter_set"])
		}
	})
}
