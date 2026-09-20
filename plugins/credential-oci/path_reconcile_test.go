package credentialoci_test

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestReconcile_DryRun(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data:      map[string]any{"mode": "dry_run"},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("reconcile error: %v", resp)
	}

	if resp.Data["dry_run"] != true {
		t.Fatalf("expected dry_run=true, got %v", resp.Data["dry_run"])
	}
	if resp.Data["found"] == nil {
		t.Fatal("expected orphans_found field")
	}
}

func TestReconcile_Normal(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data:      map[string]any{"mode": "normal"},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("reconcile error: %v", resp)
	}

	if resp.Data["dry_run"] != false {
		t.Fatalf("expected dry_run=false, got %v", resp.Data["dry_run"])
	}
}

func TestReconcile_NoClient(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data:      map[string]any{"mode": "normal"},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error when client not configured")
	}
}
