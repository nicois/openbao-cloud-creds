package credentialoci_test

import (
	"context"
	"testing"

	credentialoci "github.com/nicois/openbao-cloud-creds/plugins/credential-oci"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestRotateSlot_ChangesCredential(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// Read initial credential
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp1, err := b.HandleRequest(context.Background(), readReq)
	if err != nil || resp1.IsError() {
		t.Fatalf("first read failed: err=%v resp=%v", err, resp1)
	}
	origCredID := resp1.Data["credential_id"].(string)
	origCred := resp1.Data["credential"].(map[string]interface{})
	origToken := origCred["auth_token"].(string)

	// Rotate slot 0
	rotateReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-slot/test-role/0",
		Storage:   storage,
	}
	rotateResp, err := b.HandleRequest(context.Background(), rotateReq)
	if err != nil || rotateResp.IsError() {
		t.Fatalf("rotate failed: err=%v resp=%v", err, rotateResp)
	}

	// Read again
	resp2, err := b.HandleRequest(context.Background(), readReq)
	if err != nil || resp2.IsError() {
		t.Fatalf("second read failed: err=%v resp=%v", err, resp2)
	}
	newCredID := resp2.Data["credential_id"].(string)
	newCred := resp2.Data["credential"].(map[string]interface{})
	newToken := newCred["auth_token"].(string)

	// Credential should have changed after rotation
	if newCredID == origCredID {
		t.Fatal("credential_id should change after rotation")
	}
	if newToken == origToken {
		t.Fatal("auth_token should change after rotation")
	}
}

func TestRotateSlot_BothSlots(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// Rotate slot 0
	req0 := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-slot/test-role/0",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req0)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate slot 0 failed: err=%v resp=%v", err, resp)
	}

	// Rotate slot 1
	req1 := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-slot/test-role/1",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req1)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate slot 1 failed: err=%v resp=%v", err, resp)
	}

	// Should still be able to read
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	readResp, err := b.HandleRequest(context.Background(), readReq)
	if err != nil || readResp == nil || readResp.IsError() {
		t.Fatalf("read after both rotations failed: err=%v resp=%v", err, readResp)
	}
}

func TestSlotInitialization_CreatesTokens(t *testing.T) {
	b, storage := getTestBackend(t)

	fakeClient := credentialoci.NewTestFakeClient()
	credentialoci.TestSetClient(b, fakeClient)

	// Write config (operational settings only)
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{},
	}
	resp, err := b.HandleRequest(context.Background(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// Create the minter set the role binds to
	setReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":            "minter-1",
					"token":         "tenancy:user:fingerprint:key",
					"never_expires": true,
				},
			},
		},
	}
	if resp, err := b.HandleRequest(context.Background(), setReq); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Write role - should initialize 2 slots (create 2 tokens) via the bound set
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/init-test",
		Storage:   storage,
		Data: map[string]interface{}{
			"user_ocid":       "ocid1.user.oc1..inituser",
			"slot_count":      2,
			"rotation_period": 604800,
			"default_ttl":     302400,
			"max_ttl":         604800,
			"minter_set":      "default",
		},
	}
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	// Read role to verify slots were created
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/init-test",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), readReq)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("role read failed: err=%v resp=%v", err, resp)
	}

	slots, ok := resp.Data["slots"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected slots array, got %T", resp.Data["slots"])
	}
	if len(slots) != 2 {
		t.Fatalf("expected 2 slots, got %d", len(slots))
	}

	for i, s := range slots {
		if s["state"] != "active" {
			t.Fatalf("slot %d should be active, got %v", i, s["state"])
		}
		if s["token_id"] == nil || s["token_id"] == "" {
			t.Fatalf("slot %d should have token_id", i)
		}
	}
}
