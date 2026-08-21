package plugintest

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// reconcilePath and its modes are uniform across every plugin's API surface.
const (
	reconcilePath = "reconcile"
	fieldMode     = "mode"
	modeNormal    = "normal"
	modeDryRun    = "dry_run"
)

// RunReconcilerSafetySuite covers the load-bearing safety invariant: the
// reconciler may only ever delete entities matching the owner-tag scheme
// (`cloud-creds-<role>-` / `owner=cloud-creds`). Everything upstream that the
// plugin did not create must survive a pass, including a pass that deletes real
// orphans.
//
// This is asserted here rather than per plugin because the invariant is identical
// on every cloud while the entity being planted is not — the harness plants it,
// the suite decides what may happen to it.
func RunReconcilerSafetySuite(t *testing.T, h Harness) {
	t.Run("NeverDeletesForeignEntity", func(t *testing.T) {
		b, storage := newConfiguredBackend(t, h)

		// Issue once so the fake also holds an entity the plugin DOES own: a
		// reconciler that deleted everything it saw would otherwise pass by
		// finding nothing to delete.
		if resp, err := issue(t, b, storage, h.IssuePath); err != nil || resp == nil || resp.IsError() {
			t.Fatalf("issue failed: err=%v resp=%v", err, resp)
		}

		id := h.SeedForeignEntity()
		resp := reconcile(t, b, storage, modeNormal)
		if !h.HasEntity(id) {
			t.Fatalf("reconciler deleted foreign entity %q — the owner-tag invariant is broken", id)
		}
		if orphans, ok := resp.Data["orphans_found"].(int); ok && orphans != 0 {
			t.Fatalf("foreign entity counted as an orphan: orphans_found=%d", orphans)
		}
	})

	t.Run("DryRunDeletesNothing", func(t *testing.T) {
		b, storage := newConfiguredBackend(t, h)
		if resp, err := issue(t, b, storage, h.IssuePath); err != nil || resp == nil || resp.IsError() {
			t.Fatalf("issue failed: err=%v resp=%v", err, resp)
		}

		id := h.SeedForeignEntity()
		before := h.ProvisionedCount()
		resp := reconcile(t, b, storage, modeDryRun)
		if dry, ok := resp.Data["dry_run"].(bool); ok && !dry {
			t.Fatalf("reconcile with mode=dry_run reported dry_run=false: %v", resp.Data)
		}
		if !h.HasEntity(id) {
			t.Fatalf("dry-run reconcile deleted foreign entity %q", id)
		}
		if after := h.ProvisionedCount(); after != before {
			t.Fatalf("dry-run reconcile changed the upstream entity count: %d -> %d", before, after)
		}
	})
}

func reconcile(t *testing.T, b logical.Backend, storage logical.Storage, mode string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: reconcilePath, Storage: storage,
		Data: map[string]interface{}{fieldMode: mode},
	})
	if err != nil {
		t.Fatalf("reconcile (%s) errored: %v", mode, err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("reconcile (%s) failed: %v", mode, resp)
	}
	return resp
}
