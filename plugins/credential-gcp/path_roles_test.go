package credentialgcp_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// testRoleScope is a single narrow OAuth2 scope. Roles must state their scopes —
// there is no default, because on GCP the scope list is the whole privilege
// boundary and defaulting it meant defaulting to everything (A29).
const testRoleScope = "https://www.googleapis.com/auth/devstorage.read_only"

// writeDefaultMinterSet creates a "default" minter set so roles can bind to it.
func writeDefaultMinterSet(t *testing.T, b logical.Backend, storage logical.Storage) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "minter-1", "credentials_json": testCredentialsJSON, "never_expires": true},
			},
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}
}

func TestRoleCRUD(t *testing.T) {
	b, storage := getTestBackend(t)
	writeDefaultMinterSet(t, b, storage)

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
			"minter_set":            "default",
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role create failed: err=%v resp=%v", err, resp)
	}

	// Read role
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/deploy-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role read failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["name"] != "deploy-role" {
		t.Fatalf("unexpected name: %v", resp.Data["name"])
	}
	if resp.Data["service_account_email"] != "deploy-sa@my-project.iam.gserviceaccount.com" {
		t.Fatalf("unexpected service_account_email: %v", resp.Data["service_account_email"])
	}
	if resp.Data["minter_set"] != "default" {
		t.Fatalf("unexpected minter_set: %v", resp.Data["minter_set"])
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
	resp, err = b.HandleRequest(t.Context(), req)
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
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role delete failed: err=%v resp=%v", err, resp)
	}

	// Verify gone
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/deploy-role",
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
	resp, err := b.HandleRequest(t.Context(), req)
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
			"scopes":                testRoleScope,
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for invalid service_account_email")
	}
}

func TestRoleValidation_TTLTooHigh(t *testing.T) {
	b, storage := getTestBackend(t)
	writeDefaultMinterSet(t, b, storage)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":           3600,
			"max_ttl":               86400, // above 43200s maximum
			"service_account_email": "sa@my-project.iam.gserviceaccount.com",
			"scopes":                testRoleScope,
			"minter_set":            "default",
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for max_ttl above 43200s")
	}
}

func TestRoleValidation_DefaultExceedsMax(t *testing.T) {
	b, storage := getTestBackend(t)
	writeDefaultMinterSet(t, b, storage)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":           7200,
			"max_ttl":               3600,
			"service_account_email": "sa@my-project.iam.gserviceaccount.com",
			"scopes":                testRoleScope,
			"minter_set":            "default",
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

// TestRoleValidation_RequiresScopes: an impersonated access token carries no other
// privilege restriction, so a role's scope list IS the privilege boundary on this
// cloud. It used to default to cloud-platform, which meant an operator who said
// nothing about privilege silently got all of it (A29).
func TestRoleValidation_RequiresScopes(t *testing.T) {
	b, storage := getTestBackend(t)
	writeDefaultMinterSet(t, b, storage)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/unscoped",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":           3600,
			"max_ttl":               3600,
			"service_account_email": "deploy-sa@my-project.iam.gserviceaccount.com",
			"minter_set":            "default",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("a role with no scopes was accepted; it would issue tokens with full "+
			"cloud-platform access: %v", resp)
	}
	if msg := resp.Data["error"]; !strings.Contains(fmt.Sprint(msg), "cloud-platform") {
		t.Errorf("the rejection should name the scope an operator must ask for explicitly if they "+
			"really do want everything, got: %v", msg)
	}
}
