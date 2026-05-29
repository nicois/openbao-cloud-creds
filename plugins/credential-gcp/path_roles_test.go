package credentialgcp_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestRoleCRUD(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create role
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/deploy-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":           3600,
			"max_ttl":               3600,
			"service_account_email": "deploy-sa@my-project.iam.gserviceaccount.com",
			"scopes":                "https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/compute",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role create failed: err=%v resp=%v", err, resp)
	}

	// Read role
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/deploy-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role read failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["name"] != "deploy-role" {
		t.Fatalf("unexpected name: %v", resp.Data["name"])
	}
	if resp.Data["service_account_email"] != "deploy-sa@my-project.iam.gserviceaccount.com" {
		t.Fatalf("unexpected service_account_email: %v", resp.Data["service_account_email"])
	}
	scopes, ok := resp.Data["scopes"].([]string)
	if !ok || len(scopes) != 2 {
		t.Fatalf("unexpected scopes: %v", resp.Data["scopes"])
	}

	// List roles
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role list failed: err=%v resp=%v", err, resp)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "deploy-role" {
		t.Fatalf("unexpected keys: %v", keys)
	}

	// Delete role
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/deploy-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role delete failed: err=%v resp=%v", err, resp)
	}

	// Verify gone
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/deploy-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatal("expected nil response for deleted role")
	}
}

func TestRoleValidation_MissingSAEmail(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl": 3600,
			"max_ttl":     3600,
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for missing service_account_email")
	}
}

func TestRoleValidation_InvalidSAEmail(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":           3600,
			"max_ttl":               3600,
			"service_account_email": "not-a-valid-email",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for invalid service_account_email")
	}
}

func TestRoleValidation_TTLTooHigh(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":           3600,
			"max_ttl":               86400, // above 43200s maximum
			"service_account_email": "sa@my-project.iam.gserviceaccount.com",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for max_ttl above 43200s")
	}
}

func TestRoleValidation_DefaultExceedsMax(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":           7200,
			"max_ttl":               3600,
			"service_account_email": "sa@my-project.iam.gserviceaccount.com",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for default_ttl > max_ttl")
	}
}
