package credentialdo_test

import (
	"fmt"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestRoleCRUD(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create the minter set the role binds to
	setReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
		Data: map[string]any{
			"minters": []any{
				map[string]any{"id": "minter-1", "token": "dop_v1_test", "never_expires": true},
			},
		},
	}
	if resp, err := b.HandleRequest(t.Context(), setReq); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Create role
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/snapshot-rw",
		Storage:   storage,
		Data: map[string]any{
			"default_ttl": 900,
			"max_ttl":     3600,
			"scopes":      "read,write",
			"minter_set":  "default",
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role create failed: err=%v resp=%v", err, resp)
	}

	// Read role
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/snapshot-rw",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role read failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["name"] != "snapshot-rw" {
		t.Fatalf("unexpected name: %v", resp.Data["name"])
	}
	// A list-valued role field reads back as a LIST on every cloud now, whatever form
	// it was written in (A28).
	if got := fmt.Sprint(resp.Data["scopes"]); got != "[read write]" {
		t.Fatalf("unexpected scopes: %v", resp.Data["scopes"])
	}
	if resp.Data["minter_set"] != "default" {
		t.Fatalf("unexpected minter_set: %v", resp.Data["minter_set"])
	}

	// List roles
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role list failed: err=%v resp=%v", err, resp)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "snapshot-rw" {
		t.Fatalf("unexpected keys: %v", keys)
	}

	// Delete role
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/snapshot-rw",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role delete failed: err=%v resp=%v", err, resp)
	}

	// Verify gone
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/snapshot-rw",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatal("expected nil response for deleted role")
	}
}

func TestRoleValidation_TTL(t *testing.T) {
	b, storage := getTestBackend(t)

	setReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
		Data: map[string]any{
			"minters": []any{
				map[string]any{"id": "minter-1", "token": "dop_v1_test", "never_expires": true},
			},
		},
	}
	if resp, err := b.HandleRequest(t.Context(), setReq); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]any{
			"default_ttl": 7200,
			"max_ttl":     3600,
			"scopes":      "read",
			"minter_set":  "default",
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for default_ttl > max_ttl")
	}
}

func TestRoleRequiresExistingMinterSet(t *testing.T) {
	b, storage := getTestBackend(t)
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/orphan", Storage: storage,
		Data: map[string]any{"default_ttl": 900, "max_ttl": 3600, "scopes": "read", "minter_set": "nonexistent"},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error binding role to nonexistent minter set")
	}
}
