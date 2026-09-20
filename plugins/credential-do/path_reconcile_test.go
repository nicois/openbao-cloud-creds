package credentialdo_test

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// runReconcile drives the manual reconcile path and returns the response.
func runReconcile(t *testing.T, b logical.Backend, storage logical.Storage, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: storage, Data: data,
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("reconcile error: %v", resp)
	}
	return resp
}

// TestPathReconcile_FloorsSubMinHold proves a manual reconcile with
// confirmation_hold=0 is floored to MinConfirmationHold (5m): a 1-minute-old
// orphan is inside the floor and must NOT be deleted, and the response surfaces
// the effective 5m hold. Post-F1, ConfirmationHold:0 would have deleted it.
func TestPathReconcile_FloorsSubMinHold(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)
	srv.AddRawTokenWithCreatedAt("orphan-1", ownertag.CredentialName(ownerInstanceForTest(t, storage), "role-x", "seed"), time.Now().Add(-1*time.Minute).UTC().Format(time.RFC3339))

	resp := runReconcile(t, b, storage, map[string]any{"mode": "normal", "confirmation_hold": 0})

	if got := resp.Data["deleted"].(int); got != 0 {
		t.Fatalf("expected 0 deleted (floored hold protects recent orphan), got %d", got)
	}
	if got := resp.Data["confirmation_hold"].(string); got != "5m0s" {
		t.Fatalf("expected effective confirmation_hold=5m0s, got %q", got)
	}
	if !srv.HasToken("orphan-1") {
		t.Fatal("recent orphan was deleted despite the 5m floor")
	}
}

// TestPathReconcile_DeletesOldOrphanAboveFloor proves cleanup still works: a
// 10-minute-old orphan is older than the 5m floor, so confirmation_hold=0
// (floored to 5m) still deletes it.
func TestPathReconcile_DeletesOldOrphanAboveFloor(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)
	srv.AddRawTokenWithCreatedAt("orphan-1", ownertag.CredentialName(ownerInstanceForTest(t, storage), "role-x", "seed"), time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339))

	resp := runReconcile(t, b, storage, map[string]any{"mode": "normal", "confirmation_hold": 0})

	if got := resp.Data["deleted"].(int); got != 1 {
		t.Fatalf("expected 1 deleted (orphan older than 5m floor), got %d", got)
	}
	if srv.HasToken("orphan-1") {
		t.Fatal("orphan older than the floor was not deleted")
	}
}

// TestPathReconcile_DefaultHoldIsOneHour proves that omitting confirmation_hold
// applies the worker default (1h): a 10-minute-old orphan is inside the 1h hold
// and must NOT be deleted, and the response reports the 1h hold.
func TestPathReconcile_DefaultHoldIsOneHour(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)
	srv.AddRawTokenWithCreatedAt("orphan-1", ownertag.CredentialName(ownerInstanceForTest(t, storage), "role-x", "seed"), time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339))

	resp := runReconcile(t, b, storage, map[string]any{"mode": "normal"})

	if got := resp.Data["deleted"].(int); got != 0 {
		t.Fatalf("expected 0 deleted (default 1h hold protects 10m orphan), got %d", got)
	}
	if got := resp.Data["confirmation_hold"].(string); got != "1h0m0s" {
		t.Fatalf("expected default confirmation_hold=1h0m0s, got %q", got)
	}
	if !srv.HasToken("orphan-1") {
		t.Fatal("10m orphan was deleted despite the default 1h hold")
	}
}

// TestReconcile_NeverDeletesForeignEntity pins the owner-tag delete-safety
// boundary: an upstream token whose name does not carry the cloud-creds- prefix
// must never be deleted or reported as an orphan, even in a normal (deleting)
// reconcile pass.
func TestReconcile_NeverDeletesForeignEntity(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// Issue one credential so the fake holds a cloud-creds- named token.
	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	}); err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	// Plant a foreign-named token that the reconciler must never touch.
	srv.AddRawToken("foreign-1", "someone-elses-token")

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

	if !srv.HasToken("foreign-1") {
		t.Fatal("foreign token was deleted by reconciler")
	}
	if got := resp.Data["found"].(int); got != 0 {
		t.Fatalf("foreign token counted as orphan: orphans_found=%d", got)
	}
}

func TestReconcileEndpoint_DryRun(t *testing.T) {
	srv := fakes.NewDOServer()
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
