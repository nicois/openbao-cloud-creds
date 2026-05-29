package credentialaws_test

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
			"default_ttl":  900,
			"max_ttl":      3600,
			"iam_role_arn": "arn:aws:iam::123456789012:role/deploy",
			"session_tags": map[string]interface{}{
				"team": "platform",
			},
			"external_id": "ext-123",
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
	if resp.Data["iam_role_arn"] != "arn:aws:iam::123456789012:role/deploy" {
		t.Fatalf("unexpected iam_role_arn: %v", resp.Data["iam_role_arn"])
	}
	if resp.Data["external_id"] != "ext-123" {
		t.Fatalf("unexpected external_id: %v", resp.Data["external_id"])
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

func TestRoleValidation_MissingARN(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl": 900,
			"max_ttl":     3600,
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for missing iam_role_arn")
	}
}

func TestRoleValidation_TTLTooLow(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":  60, // below 900s minimum
			"max_ttl":      3600,
			"iam_role_arn": "arn:aws:iam::123456789012:role/test",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for default_ttl below 900s")
	}
}

func TestRoleValidation_TTLTooHigh(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":  900,
			"max_ttl":      86400, // above 43200s maximum
			"iam_role_arn": "arn:aws:iam::123456789012:role/test",
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
			"default_ttl":  7200,
			"max_ttl":      3600,
			"iam_role_arn": "arn:aws:iam::123456789012:role/test",
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
