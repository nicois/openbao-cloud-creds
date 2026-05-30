package credentialakamai_test

import (
	"context"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestReconcile_NeverDeletesForeignEntity pins the owner-tag delete-safety
// boundary: an upstream API client whose name does not carry the cloud-creds-
// prefix must never be deleted or reported as an orphan, even in a normal
// (deleting) reconcile pass.
func TestReconcile_NeverDeletesForeignEntity(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	if resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	}); err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	srv.AddRawClient("foreign-1", "someone-elses-client")

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: storage,
		Data: map[string]interface{}{"mode": "normal"},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("reconcile error: %v", resp)
	}

	if !srv.HasClient("foreign-1") {
		t.Fatal("foreign API client was deleted by reconciler")
	}
	if got := resp.Data["orphans_found"].(int); got != 0 {
		t.Fatalf("foreign API client counted as orphan: orphans_found=%d", got)
	}
}

func TestReconcileEndpoint_DryRun(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data: map[string]interface{}{
			"mode": "dry_run",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("reconcile error: %v", resp)
	}
}
