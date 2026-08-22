package credentialaws_test

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestReconcileEndpoint_DryRun(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data: map[string]interface{}{
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
	if resp.Data["dry_run"] != true {
		t.Fatalf("expected dry_run=true, got %v", resp.Data["dry_run"])
	}
}

func TestReconcileEndpoint_Normal(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// Issue a credential first so there's something to reconcile
	issueReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	_, err := b.HandleRequest(t.Context(), issueReq)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data: map[string]interface{}{
			"mode": "normal",
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("reconcile error: %v", resp)
	}
	// Active tokens haven't expired yet, so nothing should be cleaned
	if resp.Data["found"].(int) != 0 {
		t.Fatalf("expected found=0 (creds still active), got %v", resp.Data["found"])
	}
}
