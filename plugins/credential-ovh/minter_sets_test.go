package credentialovh_test

import (
	"context"
	"testing"

	credentialovh "github.com/nicois/openbao-cloud-creds/plugins/credential-ovh"
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
				map[string]interface{}{"id": "m1", "client_id": "cid", "client_secret": "csec", "never_expires": true},
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
				map[string]interface{}{"id": "m1", "client_id": "cid", "client_secret": "csec", "expires_at": "2027-01-01T00:00:00Z"},
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

func TestMinterSetMissingClientCredentials(t *testing.T) {
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
		t.Fatal("expected error for missing client_id/client_secret")
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
			"default_ttl": 3600,
			"max_ttl":     3600,
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
			"default_ttl": 3600,
			"max_ttl":     3600,
			"minter_set":  "does-not-exist",
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
// and in the actual client_id/client_secret handed to the token client factory.
func TestMinterSetIsolation(t *testing.T) {
	b, storage := getTestBackend(t)

	// Capture which client_id the factory is constructed with.
	var lastClientID, lastClientSecret string
	credentialovh.SetTokenClientFactory(b, func(clientID, clientSecret, tokenEndpoint string) credentialovh.TokenClient {
		lastClientID = clientID
		lastClientSecret = clientSecret
		return credentialovh.NewFakeTokenClient(nil, nil)
	})

	// config
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{"region": "eu"},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}

	// default set
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-1", "client_id": "default-id", "client_secret": "default-secret", "never_expires": true},
		}},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("default set write: err=%v resp=%v", err, resp)
	}

	// secondary set + role
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/secondary", Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-2", "client_id": "secondary-id", "client_secret": "secondary-secret", "never_expires": true},
		}},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("secondary set write: err=%v resp=%v", err, resp)
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/role2", Storage: storage,
		Data: map[string]interface{}{
			"default_ttl": 3600, "max_ttl": 3600,
			"minter_set": "secondary",
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
	if lastClientID != "secondary-id" || lastClientSecret != "secondary-secret" {
		t.Fatalf("role2 minted with wrong credentials: id=%q secret=%q", lastClientID, lastClientSecret)
	}
}
