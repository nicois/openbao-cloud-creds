package credentialazure_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func setupConfiguredBackend(t *testing.T, azureURL string) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)

	// config: cloud settings only (no minters)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"tenant_id":      "test-tenant-id",
			"graph_endpoint": azureURL,
			"login_endpoint": azureURL,
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
					"token":         "fake-client-id:fake-client-secret",
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
			"default_ttl":   3600,
			"max_ttl":       86400,
			"app_object_id": "fake-app-object-id",
			"client_id":     "fake-app-client-id",
			"minter_set":    "default",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	return b, storage
}

func TestCredsIssue(t *testing.T) {
	srv := fakes.NewAzureServer()
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

	if resp.Data["cloud"] != "azure" {
		t.Fatalf("expected cloud=azure, got %v", resp.Data["cloud"])
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
	if cred["client_secret"] == nil || cred["client_secret"] == "" {
		t.Fatal("expected credential.client_secret")
	}
	if cred["client_id"] != "fake-app-client-id" {
		t.Fatalf("expected credential.client_id=fake-app-client-id, got %v", cred["client_id"])
	}
	if cred["tenant_id"] != "test-tenant-id" {
		t.Fatalf("expected credential.tenant_id=test-tenant-id, got %v", cred["tenant_id"])
	}

	// Verify lease internal data has upstream ID for revoke
	if resp.Secret == nil {
		t.Fatal("expected secret/lease")
	}
	if resp.Secret.InternalData["upstream_key_id"] == nil {
		t.Fatal("expected upstream_key_id in internal_data")
	}
	if resp.Secret.InternalData["app_object_id"] == nil {
		t.Fatal("expected app_object_id in internal_data")
	}
	if resp.Secret.InternalData["minter_set"] != "default" {
		t.Fatalf("expected minter_set=default in internal_data, got %v", resp.Secret.InternalData["minter_set"])
	}
	if resp.Secret.InternalData["minter_id"] != "minter-1" {
		t.Fatalf("expected minter_id=minter-1 in internal_data, got %v", resp.Secret.InternalData["minter_id"])
	}

	// Provenance in the envelope metadata.
	meta := resp.Data["metadata"].(map[string]interface{})
	if meta["minter_set"] != "default" {
		t.Fatalf("expected metadata.minter_set=default, got %v", meta["minter_set"])
	}
	if meta["minter_id"] != "minter-1" {
		t.Fatalf("expected metadata.minter_id=minter-1, got %v", meta["minter_id"])
	}
	if meta["api_version"] != "2" {
		t.Fatalf("expected api_version=2, got %v", meta["api_version"])
	}
}

// TestMinterSetIsolation proves a role bound to set B mints with set B's
// minter — and, critically, that set B's client_secret (not set A's cached
// Graph token) is what reaches the Graph/OAuth2 endpoint. This guards against
// any cross-minter Graph-token cache bleed.
func TestMinterSetIsolation(t *testing.T) {
	srv := fakes.NewAzureServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL) // set "default" (secret fake-client-secret) + role "test-role"

	// Second, independent set with a DIFFERENT client_id:client_secret.
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/secondary", Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-2", "token": "other-client-id:other-client-secret", "never_expires": true},
		}},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("secondary set write: err=%v resp=%v", err, resp)
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/role2", Storage: storage,
		Data: map[string]interface{}{
			"default_ttl": 3600, "max_ttl": 86400,
			"app_object_id": "fake-app-object-id", "client_id": "fake-app-client-id", "minter_set": "secondary",
		},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role2 write: err=%v resp=%v", err, resp)
	}

	// Issue via role2 — must use minter-2.
	req = &logical.Request{Operation: logical.ReadOperation, Path: "creds/role2", Storage: storage}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("role2 issue failed: err=%v resp=%v", err, resp)
	}
	meta := resp.Data["metadata"].(map[string]interface{})
	if meta["minter_set"] != "secondary" || meta["minter_id"] != "minter-2" {
		t.Fatalf("role2 used wrong minter: set=%v id=%v", meta["minter_set"], meta["minter_id"])
	}

	// Prove set B's own client_secret reached the OAuth2 endpoint — i.e. the
	// Graph token was minted from minter-2's credentials, not minter-1's.
	creds := srv.TokenCreds()
	sawSecondary := false
	for _, c := range creds {
		if c[0] == "other-client-id" {
			if c[1] != "other-client-secret" {
				t.Fatalf("minter-2 presented wrong secret: %q", c[1])
			}
			sawSecondary = true
		}
		// minter-1's secret must never be presented under minter-2's client id.
		if c[0] == "other-client-id" && c[1] == "fake-client-secret" {
			t.Fatal("cross-minter secret bleed: minter-1 secret used for minter-2")
		}
	}
	if !sawSecondary {
		t.Fatal("secondary minter never authenticated to Graph with its own client_id")
	}
}

func TestCredsRevoke(t *testing.T) {
	srv := fakes.NewAzureServer()
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

func TestCredsIssue_RoleNotFound_HasErrorCode(t *testing.T) {
	b, storage := getTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
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
