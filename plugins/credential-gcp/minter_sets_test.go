package credentialgcp_test

import (
	"context"
	"testing"

	credentialgcp "github.com/nicois/openbao-cloud-creds/plugins/credential-gcp"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestMinterSetCRUD(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write a set
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/backup",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "m1", "credentials_json": testCredentialsJSON, "never_expires": true},
			},
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("set write failed: err=%v resp=%v", err, resp)
	}

	// Read it back
	req = &logical.Request{Operation: logical.ReadOperation, Path: "minter-sets/backup", Storage: storage}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("set read failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["minter_count"] != 1 {
		t.Fatalf("expected minter_count=1, got %v", resp.Data["minter_count"])
	}

	// List
	req = &logical.Request{Operation: logical.ListOperation, Path: "minter-sets/", Storage: storage}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil {
		t.Fatalf("set list failed: err=%v resp=%v", err, resp)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "backup" {
		t.Fatalf("unexpected keys: %v", keys)
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
				map[string]interface{}{"id": "m1", "credentials_json": testCredentialsJSON, "expires_at": "2027-01-01T00:00:00Z"},
			},
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for single expiring minter in a set")
	}
}

func TestMinterSetMissingCredentialsJSON(t *testing.T) {
	b, storage := getTestBackend(t)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/bad",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "m1", "never_expires": true},
			},
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for missing credentials_json")
	}
}

// TestRoleRequiresExistingMinterSet proves a role cannot be written unless it
// binds to a minter set that already exists.
func TestRoleRequiresExistingMinterSet(t *testing.T) {
	b, storage := getTestBackend(t)

	// Missing minter_set entirely.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/no-set",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":           3600,
			"max_ttl":               3600,
			"service_account_email": "sa@test-project.iam.gserviceaccount.com",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for missing minter_set")
	}

	// minter_set names a set that does not exist.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/ghost-set",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":           3600,
			"max_ttl":               3600,
			"service_account_email": "sa@test-project.iam.gserviceaccount.com",
			"minter_set":            "does-not-exist",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for nonexistent minter_set")
	}
}

// TestMinterSetIsolation proves a role bound to a second, independent set mints
// from that set's minter — not the default set's — both in provenance metadata
// and in the actual credentials JSON handed to the IAM client factory.
func TestMinterSetIsolation(t *testing.T) {
	b, storage := getTestBackend(t)

	const secondaryCredentialsJSON = `{"type":"service_account","project_id":"test-project","private_key_id":"key999","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake2\n-----END RSA PRIVATE KEY-----\n","client_email":"minter2@test-project.iam.gserviceaccount.com","client_id":"987654321"}`

	// Capture which credentials JSON the factory is constructed with.
	var lastCredentialsJSON string
	credentialgcp.SetIAMClientFactory(b, func(credentialsJSON string) credentialgcp.IAMCredentialsClient {
		lastCredentialsJSON = credentialsJSON
		return credentialgcp.NewFakeIAMClient(nil, nil)
	})

	// config
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}

	// default set
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-1", "credentials_json": testCredentialsJSON, "never_expires": true},
		}},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("default set write: err=%v resp=%v", err, resp)
	}

	// secondary set + role
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/secondary", Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-2", "credentials_json": secondaryCredentialsJSON, "never_expires": true},
		}},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("secondary set write: err=%v resp=%v", err, resp)
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/role2", Storage: storage,
		Data: map[string]interface{}{
			"default_ttl": 3600, "max_ttl": 3600,
			"service_account_email": "target-sa@test-project.iam.gserviceaccount.com",
			"minter_set":            "secondary",
		},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role2 write: err=%v resp=%v", err, resp)
	}

	// role2 must mint via minter-2 / secondary credentials.
	req = &logical.Request{Operation: logical.ReadOperation, Path: "creds/role2", Storage: storage}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("role2 issue failed: err=%v resp=%v", err, resp)
	}
	meta := resp.Data["metadata"].(map[string]interface{})
	if meta["minter_set"] != "secondary" || meta["minter_id"] != "minter-2" {
		t.Fatalf("role2 used wrong minter: set=%v id=%v", meta["minter_set"], meta["minter_id"])
	}
	if lastCredentialsJSON != secondaryCredentialsJSON {
		t.Fatalf("role2 minted with wrong credentials JSON: %q", lastCredentialsJSON)
	}
}
