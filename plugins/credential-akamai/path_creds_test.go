package credentialakamai_test

import (
	"context"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func setupConfiguredBackend(t *testing.T, akamaiURL string) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)

	// config: host + operational settings (no minters)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"host":           "akab-test.luna.akamaiapis.net",
			"akamai_api_url": akamaiURL,
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// minter set
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":            "minter-1",
					"token":         "ct-test:at-test:cs-test",
					"never_expires": true,
				},
			},
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// role bound to the set
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl": 900,
			"max_ttl":     3600,
			"group_id":    100,
			"api_access":  `{"apis":[{"apiId":1,"roleId":2}]}`,
			"minter_set":  "default",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	return b, storage
}

func TestCredsIssue(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("creds read failed: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("creds read error: %v", resp)
	}

	if resp.Data["cloud"] != "akamai" {
		t.Fatalf("expected cloud=akamai, got %v", resp.Data["cloud"])
	}
	if resp.Data["role"] != "test-role" {
		t.Fatalf("expected role=test-role, got %v", resp.Data["role"])
	}
	if resp.Data["credential_id"] == nil || resp.Data["credential_id"] == "" {
		t.Fatal("expected credential_id")
	}

	cred, ok := resp.Data["credential"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credential map, got %T", resp.Data["credential"])
	}
	if cred["client_token"] == nil {
		t.Fatal("expected credential.client_token")
	}
	if cred["access_token"] == nil {
		t.Fatal("expected credential.access_token")
	}
	if cred["client_secret"] == nil {
		t.Fatal("expected credential.client_secret")
	}
	if cred["host"] == nil {
		t.Fatal("expected credential.host")
	}
	if cred["host"] != "akab-test.luna.akamaiapis.net" {
		t.Fatalf("expected host=akab-test.luna.akamaiapis.net, got %v", cred["host"])
	}

	// Verify lease internal data has upstream ID for revoke
	if resp.Secret == nil {
		t.Fatal("expected secret/lease")
	}
	if resp.Secret.InternalData["upstream_client_id"] == nil {
		t.Fatal("expected upstream_client_id in internal_data")
	}
	if resp.Secret.InternalData["minter_set"] != "default" {
		t.Fatalf("expected minter_set=default in internal_data, got %v", resp.Secret.InternalData["minter_set"])
	}
	if resp.Secret.InternalData["minter_id"] != "minter-1" {
		t.Fatalf("expected minter_id=minter-1 in internal_data, got %v", resp.Secret.InternalData["minter_id"])
	}

	// Verify envelope provenance metadata
	meta := resp.Data["metadata"].(map[string]interface{})
	if meta["minter_set"] != "default" {
		t.Fatalf("expected minter_set=default, got %v", meta["minter_set"])
	}
	if meta["minter_id"] != "minter-1" {
		t.Fatalf("expected minter_id=minter-1, got %v", meta["minter_id"])
	}
	if meta["api_version"] != "2" {
		t.Fatalf("expected api_version=2, got %v", meta["api_version"])
	}
}

// TestMinterSetIsolation proves that a role bound to one minter set signs the
// upstream request with that set's EdgeGrid triple, never another set's. The
// fake records the client_token from the EdgeGrid Authorization header, so we
// can assert the correct minter's credentials reached the signer.
func TestMinterSetIsolation(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL) // set "default" (minter-1, ct-test) + role "test-role"

	// Add an independent set "secondary" with a distinct triple and a role.
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/secondary", Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-2", "token": "ct-other:at-other:cs-other", "never_expires": true},
		}},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("secondary set write: err=%v resp=%v", err, resp)
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/role2", Storage: storage,
		Data: map[string]interface{}{"default_ttl": 900, "max_ttl": 3600, "group_id": 200, "api_access": "{}", "minter_set": "secondary"},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role2 write: err=%v resp=%v", err, resp)
	}

	// role2 must mint via minter-2 and sign with the "secondary" set's triple.
	req = &logical.Request{Operation: logical.ReadOperation, Path: "creds/role2", Storage: storage}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("role2 issue failed: err=%v resp=%v", err, resp)
	}
	meta := resp.Data["metadata"].(map[string]interface{})
	if meta["minter_set"] != "secondary" || meta["minter_id"] != "minter-2" {
		t.Fatalf("role2 used wrong minter: set=%v id=%v", meta["minter_set"], meta["minter_id"])
	}
	if got := srv.LastSigningClientToken(); got != "ct-other" {
		t.Fatalf("role2 should sign with secondary triple (client_token=ct-other), but signer used %q", got)
	}

	// role (set "default") must sign with the default set's triple.
	req = &logical.Request{Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("test-role issue failed: err=%v resp=%v", err, resp)
	}
	if got := srv.LastSigningClientToken(); got != "ct-test" {
		t.Fatalf("test-role should sign with default triple (client_token=ct-test), but signer used %q", got)
	}
}

func TestCredsRevoke(t *testing.T) {
	srv := fakes.NewAkamaiServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// Issue
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	// Revoke
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    resp.Secret,
	}
	resp, err = b.HandleRequest(context.Background(), revokeReq)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("revoke error: %v", resp)
	}
}

func TestCredsIssue_RoleNotFound(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/nonexistent",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing role")
	}
}
