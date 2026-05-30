package credentialoci_test

import (
	"context"
	"testing"

	credentialoci "github.com/nicois/openbao-cloud-creds/plugins/credential-oci"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// writeDefaultMinterSet creates a minter set named "default" that role-write
// tests bind their roles to.
func writeDefaultMinterSet(t *testing.T, b logical.Backend, storage logical.Storage) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "minter-1", "token": "tenancy:user:fingerprint:key", "never_expires": true},
			},
		},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}
}

func TestRoleCRUD(t *testing.T) {
	b, storage := getTestBackend(t)
	credentialoci.TestSetClient(b, credentialoci.NewTestFakeClient())
	writeDefaultMinterSet(t, b, storage)

	// Create role
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-user",
		Storage:   storage,
		Data: map[string]interface{}{
			"user_ocid":       "ocid1.user.oc1..testuser",
			"slot_count":      2,
			"rotation_period": 604800, // 7 days
			"default_ttl":     302400, // 3.5 days
			"max_ttl":         604800,
			"minter_set":      "default",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role create failed: err=%v resp=%v", err, resp)
	}

	// Read role
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/test-user",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role read failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["name"] != "test-user" {
		t.Fatalf("unexpected name: %v", resp.Data["name"])
	}
	if resp.Data["user_ocid"] != "ocid1.user.oc1..testuser" {
		t.Fatalf("unexpected user_ocid: %v", resp.Data["user_ocid"])
	}
	if resp.Data["slot_count"] != 2 {
		t.Fatalf("unexpected slot_count: %v", resp.Data["slot_count"])
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
	if len(keys) != 1 || keys[0] != "test-user" {
		t.Fatalf("unexpected keys: %v", keys)
	}

	// Delete role
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/test-user",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role delete failed: err=%v resp=%v", err, resp)
	}

	// Verify gone
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/test-user",
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

func TestRoleValidation_MissingUserOCID(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"slot_count":      2,
			"rotation_period": 604800,
			"default_ttl":     302400,
			"max_ttl":         604800,
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for missing user_ocid")
	}
}

func TestRoleRequiresExistingMinterSet(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/orphan",
		Storage:   storage,
		Data: map[string]interface{}{
			"user_ocid":       "ocid1.user.oc1..testuser",
			"slot_count":      2,
			"rotation_period": 604800,
			"default_ttl":     302400,
			"max_ttl":         604800,
			"minter_set":      "nonexistent",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error binding role to nonexistent minter set")
	}
}

func TestRoleValidation_TTLExceedsRotationInterval(t *testing.T) {
	b, storage := getTestBackend(t)
	writeDefaultMinterSet(t, b, storage)

	// default_ttl (4d) > rotation_period/slot_count (3.5d) should fail
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-ttl",
		Storage:   storage,
		Data: map[string]interface{}{
			"user_ocid":       "ocid1.user.oc1..testuser",
			"slot_count":      2,
			"rotation_period": 604800, // 7 days
			"default_ttl":     345600, // 4 days — exceeds 7d/2 = 3.5d
			"max_ttl":         604800,
			"minter_set":      "default",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for default_ttl > rotation_period/slot_count")
	}
}

func TestRoleValidation_SlotCountExceedsMax(t *testing.T) {
	b, storage := getTestBackend(t)
	writeDefaultMinterSet(t, b, storage)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-slots",
		Storage:   storage,
		Data: map[string]interface{}{
			"user_ocid":       "ocid1.user.oc1..testuser",
			"slot_count":      3,
			"rotation_period": 604800,
			"default_ttl":     100000,
			"max_ttl":         604800,
			"minter_set":      "default",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for slot_count > 2")
	}
}

func TestRoleValidation_DefaultTTLGtMaxTTL(t *testing.T) {
	b, storage := getTestBackend(t)
	writeDefaultMinterSet(t, b, storage)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-ttl2",
		Storage:   storage,
		Data: map[string]interface{}{
			"user_ocid":       "ocid1.user.oc1..testuser",
			"slot_count":      2,
			"rotation_period": 604800,
			"default_ttl":     700000,
			"max_ttl":         300000,
			"minter_set":      "default",
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
