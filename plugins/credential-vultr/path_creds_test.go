package credentialvultr_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestCredsIssue_RoleNotFound_HasErrorCode(t *testing.T) {
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

func setupConfiguredBackend(t *testing.T, vultrURL string) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)

	// config: operational settings only
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]any{"vultr_api_url": vultrURL},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// minter set
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]any{
			"minters": []any{
				map[string]any{"id": "minter-1", "token": "vultr_test_key", "never_expires": true},
			},
		},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// role bound to the set
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/test-role", Storage: storage,
		Data: map[string]any{
			"default_ttl": 900, "max_ttl": 3600, "acls": "subscriptions,provisioning",
			"email_domain": "managed.local", "minter_set": "default",
		},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	return b, storage
}

func TestCredsIssue(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

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

	if resp.Data["cloud"] != "vultr" {
		t.Fatalf("expected cloud=vultr, got %v", resp.Data["cloud"])
	}
	if resp.Data["role"] != "test-role" {
		t.Fatalf("expected role=test-role, got %v", resp.Data["role"])
	}
	if resp.Data["credential_id"] == nil || resp.Data["credential_id"] == "" {
		t.Fatal("expected credential_id")
	}

	cred, ok := resp.Data["credential"].(map[string]any)
	if !ok {
		t.Fatalf("expected credential map, got %T", resp.Data["credential"])
	}
	if cred["api_key"] == nil {
		t.Fatal("expected credential.api_key")
	}

	// Verify lease internal data has upstream ID for revoke
	if resp.Secret == nil {
		t.Fatal("expected secret/lease")
	}
	if resp.Secret.InternalData["upstream_user_id"] == nil {
		t.Fatal("expected upstream_user_id in internal_data")
	}

	meta := resp.Data["metadata"].(map[string]any)
	if meta["minter_set"] != "default" {
		t.Fatalf("expected minter_set=default, got %v", meta["minter_set"])
	}
	if meta["minter_id"] != "minter-1" {
		t.Fatalf("expected minter_id=minter-1, got %v", meta["minter_id"])
	}
	if meta["api_version"] != credenvelope.APIVersion {
		t.Fatalf("expected api_version=%s, got %v", credenvelope.APIVersion, meta["api_version"])
	}
}

func TestMinterSetIsolation(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL) // has set "default" + role "test-role"

	// Add a second, independent set "secondary" and a role bound to it.
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/secondary", Storage: storage,
		Data: map[string]any{"minters": []any{
			map[string]any{"id": "minter-2", "token": "vultr_other_key", "never_expires": true},
		}},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("secondary set write: err=%v resp=%v", err, resp)
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/role2", Storage: storage,
		Data: map[string]any{"default_ttl": 900, "max_ttl": 3600, "acls": "subscriptions", "minter_set": "secondary"},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role2 write: err=%v resp=%v", err, resp)
	}

	// role2 must mint via minter-2.
	req = &logical.Request{Operation: logical.ReadOperation, Path: "creds/role2", Storage: storage}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("role2 issue failed: err=%v resp=%v", err, resp)
	}
	meta := resp.Data["metadata"].(map[string]any)
	if meta["minter_set"] != "secondary" || meta["minter_id"] != "minter-2" {
		t.Fatalf("role2 used wrong minter: set=%v id=%v", meta["minter_set"], meta["minter_id"])
	}
}

func TestCredsRevoke(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

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

	// Revoke
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    resp.Secret,
	}
	resp, err = b.HandleRequest(t.Context(), revokeReq)
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
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing role")
	}
}

func TestCredsIssue_ClassifiesQuotaError(t *testing.T) {
	srv := fakes.NewVultrServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL)
	srv.SetNextStatus(http.StatusTooManyRequests) // next create returns 429

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response, got %v", resp)
	}
	msg := resp.Error().Error()
	if !strings.HasPrefix(msg, string(credenvelope.ErrUpstreamQuotaExceeded)+":") {
		t.Fatalf("expected upstream_quota_exceeded code, got %q", msg)
	}
	// #5: the raw upstream body must NOT leak to the client.
	if strings.Contains(msg, "injected") {
		t.Fatalf("client message leaked upstream detail: %q", msg)
	}
}
