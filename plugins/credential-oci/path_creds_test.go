package credentialoci_test

import (
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	credentialoci "github.com/nicois/openbao-cloud-creds/plugins/credential-oci"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func setupConfiguredBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)

	// Route every per-set minter through an in-memory fake OCI client.
	credentialoci.TestSetClient(b, credentialoci.NewTestFakeClient())

	// Write config (operational settings only — no minters here)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"region": "us-ashburn-1",
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// Create the minter set the role binds to
	req = &logical.Request{
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
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Write role bound to the set (this initializes slots via the set's minter)
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"user_ocid":       "ocid1.user.oc1..testuser",
			"slot_count":      2,
			"rotation_period": 604800,
			"default_ttl":     302400,
			"max_ttl":         604800,
			"minter_set":      "default",
		},
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	return b, storage
}

func TestCredsRead(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("creds read failed: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("creds read error: %v", resp)
	}

	// Verify envelope
	if resp.Data["cloud"] != "oci" {
		t.Fatalf("expected cloud=oci, got %v", resp.Data["cloud"])
	}
	if resp.Data["role"] != "test-role" {
		t.Fatalf("expected role=test-role, got %v", resp.Data["role"])
	}
	if resp.Data["renewable"] != false {
		t.Fatalf("expected renewable=false, got %v", resp.Data["renewable"])
	}
	if resp.Data["credential_id"] == nil || resp.Data["credential_id"] == "" {
		t.Fatal("expected credential_id")
	}

	cred, ok := resp.Data["credential"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credential map, got %T", resp.Data["credential"])
	}
	if cred["auth_token"] == nil || cred["auth_token"] == "" {
		t.Fatal("expected credential.auth_token")
	}
	if cred["user_id"] != "ocid1.user.oc1..testuser" {
		t.Fatalf("expected credential.user_id = user OCID, got %v", cred["user_id"])
	}

	// Verify metadata, including minter-set provenance recorded on the slot.
	meta, ok := resp.Data["metadata"].(map[string]interface{})
	if !ok || meta["api_version"] != credenvelope.APIVersion {
		t.Fatalf("bad metadata: %v", resp.Data["metadata"])
	}
	if meta["issued_by"] != "cloud-creds-oci/v0.1" {
		t.Fatalf("bad issued_by: %v", meta["issued_by"])
	}
	if meta["minter_set"] != "default" {
		t.Fatalf("expected metadata.minter_set=default, got %v", meta["minter_set"])
	}
	if meta["minter_id"] != "minter-1" {
		t.Fatalf("expected metadata.minter_id=minter-1, got %v", meta["minter_id"])
	}

	// Verify secret/lease exists
	if resp.Secret == nil {
		t.Fatal("expected secret/lease")
	}
	if resp.Secret.InternalData["token_id"] == nil {
		t.Fatal("expected token_id in internal_data")
	}
}

func TestCredsRead_RoleNotFound(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/nonexistent",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing role")
	}
}

func TestCredsRead_RoleNotFound_HasErrorCode(t *testing.T) {
	b, storage := getTestBackend(t)
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/nope", Storage: storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response")
	}
	got := resp.Error().Error()
	if !strings.HasPrefix(got, "role_not_found: ") {
		t.Fatalf("expected role_not_found: prefix, got %q", got)
	}
}

func TestCredsRead_MultipleReadsReturnSameSlot(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// Multiple reads should return the freshest slot (which is the same until rotation)
	var credIDs []string
	for i := 0; i < 3; i++ {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/test-role",
			Storage:   storage,
		}
		resp, err := b.HandleRequest(t.Context(), req)
		if err != nil || resp == nil || resp.IsError() {
			t.Fatalf("creds read %d failed: err=%v resp=%v", i, err, resp)
		}
		credIDs = append(credIDs, resp.Data["credential_id"].(string))
	}

	// All should be the same credential (from the same slot)
	for i := 1; i < len(credIDs); i++ {
		if credIDs[i] != credIDs[0] {
			t.Fatalf("expected same credential_id across reads, got %v vs %v", credIDs[0], credIDs[i])
		}
	}
}

func TestCredsRevoke_IsSoft(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// Issue
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	// Revoke (soft - should succeed without touching upstream)
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    resp.Secret,
	}
	revokeResp, err := b.HandleRequest(t.Context(), revokeReq)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if revokeResp != nil && revokeResp.IsError() {
		t.Fatalf("revoke error: %v", revokeResp)
	}

	// Credential should still be readable (soft revoke doesn't invalidate the slot)
	resp2, err := b.HandleRequest(t.Context(), req)
	if err != nil || resp2 == nil || resp2.IsError() {
		t.Fatalf("second read after revoke failed: err=%v resp=%v", err, resp2)
	}
}
