package credentialupcloud_test

import (
	"strings"
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
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "minter-1", "token": "ucat_v1_test", "never_expires": true},
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
		Data: map[string]interface{}{
			"default_ttl": 900,
			"max_ttl":     3600,
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
	// UpCloud has no per-token scoping, so a role must not report a scope it cannot
	// enforce: `scopes` is not a field here and must not appear in a role read (A29).
	if _, present := resp.Data["scopes"]; present {
		t.Fatalf("role read reports a scopes field UpCloud cannot enforce: %v", resp.Data)
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
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "minter-1", "token": "ucat_v1_test", "never_expires": true},
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
		Data: map[string]interface{}{
			"default_ttl": 7200,
			"max_ttl":     3600,
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

// TestRoleValidation_TTLTooHigh covers UpCloud's documented expires_in ceiling
// (8760h/365d): the role TTL becomes the token's expires_in, so a longer TTL
// would be rejected upstream at mint time. Rejected at role write instead.
func TestRoleValidation_TTLTooHigh(t *testing.T) {
	const oneYearSeconds = 8760 * 3600

	for _, tc := range []struct {
		name       string
		defaultTTL int
		maxTTL     int
	}{
		{"max_ttl above 8760h", 900, oneYearSeconds + 3600},
		{"default_ttl above 8760h", oneYearSeconds + 3600, oneYearSeconds + 7200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getTestBackend(t)

			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "roles/long-role",
				Storage:   storage,
				Data: map[string]interface{}{
					"default_ttl": tc.defaultTTL,
					"max_ttl":     tc.maxTTL,
					"minter_set":  "default",
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp == nil || !resp.IsError() {
				t.Fatal("expected error for TTL above 8760h")
			}
			if msg := resp.Error().Error(); !strings.Contains(msg, "8760h") {
				t.Fatalf("expected expires_in ceiling rejection, got %q", msg)
			}
		})
	}
}

func TestRoleRequiresExistingMinterSet(t *testing.T) {
	b, storage := getTestBackend(t)
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/orphan", Storage: storage,
		Data: map[string]interface{}{"default_ttl": 900, "max_ttl": 3600, "minter_set": "nonexistent"},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error binding role to nonexistent minter set")
	}
}
