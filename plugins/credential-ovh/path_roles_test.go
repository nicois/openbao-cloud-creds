package credentialovh_test

import (
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// writeDefaultMinterSet creates a "default" minter set so roles can bind to it.
func writeDefaultMinterSet(t *testing.T, b logical.Backend, storage logical.Storage) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
		Data: map[string]any{
			"minters": []any{
				map[string]any{"id": "minter-1", "client_id": "cid", "client_secret": "csec", "never_expires": true},
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
		Data: map[string]any{
			"default_ttl": 3600,
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
	if resp.Data["default_ttl"] != 3600 {
		t.Fatalf("unexpected default_ttl: %v", resp.Data["default_ttl"])
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

func TestRoleValidation_TTLTooHigh(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]any{
			"default_ttl": 3600,
			"max_ttl":     7200, // exceeds 3600s OVH limit
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for max_ttl above 3600s")
	}
}

func TestRoleValidation_DefaultTTLTooHigh(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]any{
			"default_ttl": 7200, // exceeds 3600s OVH limit
			"max_ttl":     3600,
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for default_ttl above 3600s")
	}
}

// TestRoleValidation_TTLTooLow covers the TTL-honesty floor: OVH tokens live for
// exactly 1h (no mint-time lifetime parameter) and OVH has no token-revoke API,
// so a sub-1h role TTL would end the lease while the credential stayed valid
// upstream. Such roles are rejected at write time instead.
func TestRoleValidation_TTLTooLow(t *testing.T) {
	for _, tc := range []struct {
		name       string
		defaultTTL int
		maxTTL     int
	}{
		{"default_ttl below 1h", 900, 3600},
		{"both below 1h", 1800, 1800},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getTestBackend(t)
			writeDefaultMinterSet(t, b, storage)

			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "roles/short-role",
				Storage:   storage,
				Data: map[string]any{
					"default_ttl": tc.defaultTTL,
					"max_ttl":     tc.maxTTL,
					"minter_set":  "default",
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp == nil || !resp.IsError() {
				t.Fatal("expected error for TTL below 3600s")
			}
			if msg := resp.Error().Error(); !strings.Contains(msg, "at least 3600 seconds") {
				t.Fatalf("expected sub-1h TTL rejection, got %q", msg)
			}
		})
	}
}

// Note: with both bounds pinned to 3600s the sub-1h floor rejects this role too;
// the assertion is only that an inverted default/max pair cannot be written.
func TestRoleValidation_DefaultExceedsMax(t *testing.T) {
	b, storage := getTestBackend(t)
	writeDefaultMinterSet(t, b, storage)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]any{
			"default_ttl": 3600,
			"max_ttl":     1800,
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
