package credentialoci_test

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestMinterSetCRUD(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write a set
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/primary",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "m1", "token": "tenancy:user:fingerprint:key", "never_expires": true},
			},
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("set write failed: err=%v resp=%v", err, resp)
	}

	// Read it back
	req = &logical.Request{Operation: logical.ReadOperation, Path: "minter-sets/primary", Storage: storage}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("set read failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["minter_count"] != 1 {
		t.Fatalf("expected minter_count=1, got %v", resp.Data["minter_count"])
	}

	// List
	req = &logical.Request{Operation: logical.ListOperation, Path: "minter-sets/", Storage: storage}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || resp == nil {
		t.Fatalf("set list failed: err=%v resp=%v", err, resp)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "primary" {
		t.Fatalf("unexpected keys: %v", keys)
	}

	// Delete
	req = &logical.Request{Operation: logical.DeleteOperation, Path: "minter-sets/primary", Storage: storage}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("set delete failed: err=%v resp=%v", err, resp)
	}

	// Verify gone
	req = &logical.Request{Operation: logical.ReadOperation, Path: "minter-sets/primary", Storage: storage}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatal("expected nil response for deleted minter set")
	}
}

func TestMinterSetValidationRejectsSingleExpiring(t *testing.T) {
	b, storage := getTestBackend(t)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/bad",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "m1", "token": "tenancy:user:fingerprint:key", "expires_at": "2027-01-01T00:00:00Z"},
			},
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for single expiring minter in a set")
	}
}
