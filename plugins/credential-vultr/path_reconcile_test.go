package credentialvultr_test

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestReconcile_NeverDeletesForeignEntity pins the owner-tag delete-safety
// boundary: an upstream sub-user whose name does not carry the cloud-creds-
// prefix must never be deleted or reported as an orphan, even in a normal
// (deleting) reconcile pass.
func TestReconcile_NeverDeletesForeignEntity(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	}); err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	srv.AddRawUser("foreign-1", "someone-elses-user")

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: storage,
		Data: map[string]any{"mode": "normal"},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("reconcile error: %v", resp)
	}

	if !srv.HasUser("foreign-1") {
		t.Fatal("foreign sub-user was deleted by reconciler")
	}
	if got := resp.Data["found"].(int); got != 0 {
		t.Fatalf("foreign sub-user counted as orphan: orphans_found=%d", got)
	}
}

// TestPathReconcile_FloorsSubMinHold proves two things at once: an
// operator-requested confirmation_hold below the 5m floor is raised to the
// floor (surfaced in the response), and that because Vultr's list API carries
// no creation timestamp (KI-004), a cloud-creds-prefixed orphan has a zero
// CreatedAt and is therefore skipped by the fail-closed reconciler whenever
// the hold is > 0. So a floored manual reconcile deletes nothing here.
func TestPathReconcile_FloorsSubMinHold(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// Plant a cloud-creds-prefixed upstream orphan NOT tracked in active-users/.
	srv.AddRawUser("orphan-1", ownertag.CredentialName(ownerInstanceForTest(t, storage), "test-role", "orphan"))

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: storage,
		Data: map[string]any{"mode": "normal", "confirmation_hold": 0},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("reconcile error: %v", resp)
	}

	if got := resp.Data["confirmation_hold"].(string); got != "5m0s" {
		t.Fatalf("confirmation_hold not floored: got %q want %q", got, "5m0s")
	}
	if got := resp.Data["deleted"].(int); got != 0 {
		t.Fatalf("zero-CreatedAt orphan should be skipped under floor: deleted=%d", got)
	}
	if !srv.HasUser("orphan-1") {
		t.Fatal("orphan with zero CreatedAt was deleted despite the floor (KI-004 fail-closed violated)")
	}
}

// TestPathReconcile_DefaultHoldSurfaced proves that when no confirmation_hold
// field is supplied, the 1h worker default flows through to the response.
func TestPathReconcile_DefaultHoldSurfaced(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: storage,
		Data: map[string]any{"mode": "normal"},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("reconcile error: %v", resp)
	}

	if got := resp.Data["confirmation_hold"].(string); got != "1h0m0s" {
		t.Fatalf("default confirmation_hold not surfaced: got %q want %q", got, "1h0m0s")
	}
	if got := resp.Data["deleted"].(int); got != 0 {
		t.Fatalf("expected no deletions: deleted=%d", got)
	}
}

func TestReconcileEndpoint_DryRun(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data: map[string]any{
			"mode": "dry_run",
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("reconcile error: %v", resp)
	}
}

// ownerInstanceForTest resolves (and on first call mints) the mount's owner instance id
// from the same storage the backend reads it from, so a seeded orphan carries the prefix
// the reconciler will actually match (A19).
func ownerInstanceForTest(t *testing.T, storage logical.Storage) string {
	t.Helper()
	id, err := ownertag.InstanceID(t.Context(), storage)
	if err != nil {
		t.Fatalf("resolving the owner instance id: %v", err)
	}
	return id
}
