package credentialgcp_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	credentialgcp "github.com/nicois/openbao-cloud-creds/plugins/credential-gcp"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const testCredentialsJSON = `{"type":"service_account","project_id":"test-project","private_key_id":"key123","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n","client_email":"minter@test-project.iam.gserviceaccount.com","client_id":"123456789"}`

func setupConfiguredBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)

	// Inject fake IAM client
	credentialgcp.SetIAMClientFactory(b, func(credentialsJSON string) credentialgcp.IAMCredentialsClient {
		return credentialgcp.NewFakeIAMClient(nil, nil)
	})

	// Write config: operational settings only
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"project": "test-project",
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// Write minter set
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
		Data: map[string]any{
			"minters": []any{
				map[string]any{
					"id":               "minter-1",
					"credentials_json": testCredentialsJSON,
					"never_expires":    true,
				},
			},
		},
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Write role bound to the set
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]any{
			"default_ttl":           3600,
			"max_ttl":               3600,
			"service_account_email": "target-sa@test-project.iam.gserviceaccount.com",
			"scopes":                testRoleScope,
			"minter_set":            "default",
		},
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	return b, storage
}

func TestCredsIssue(t *testing.T) {
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

	if resp.Data["cloud"] != "gcp" {
		t.Fatalf("expected cloud=gcp, got %v", resp.Data["cloud"])
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

	cred, ok := resp.Data["credential"].(map[string]any)
	if !ok {
		t.Fatalf("expected credential map, got %T", resp.Data["credential"])
	}
	if cred["access_token"] == nil {
		t.Fatal("expected credential.access_token")
	}
	if cred["token_type"] != "Bearer" {
		t.Fatalf("expected credential.token_type=Bearer, got %v", cred["token_type"])
	}

	// Verify lease internal data
	if resp.Secret == nil {
		t.Fatal("expected secret/lease")
	}
	if resp.Secret.InternalData["credential_id"] == nil {
		t.Fatal("expected credential_id in internal_data")
	}
	if resp.Secret.InternalData["minter_set"] != "default" {
		t.Fatalf("expected minter_set=default in internal_data, got %v", resp.Secret.InternalData["minter_set"])
	}
	if resp.Secret.InternalData["minter_id"] != "minter-1" {
		t.Fatalf("expected minter_id=minter-1 in internal_data, got %v", resp.Secret.InternalData["minter_id"])
	}

	// Verify provenance in the envelope metadata
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

func TestCredsRevoke(t *testing.T) {
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

	// Revoke (no-op for GCP, just removes tracking)
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

func TestCredsRenew_Denied(t *testing.T) {
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

	// Renew should fail — GCP access tokens are not renewable
	if resp.Secret.Renewable {
		t.Error("lease advertises renewable=true: OpenBao REVOKES a lease whose " +
			"renewal fails, so a renew attempt would destroy the credential the " +
			"client was trying to keep (docs/ttl-semantics.md)")
	}

	renewReq := &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    resp.Secret,
	}
	// Renewal is refused by the framework itself — the secret declares no Renew
	// callback — so no plugin code runs and no lease is put at risk.
	if _, err := b.HandleRequest(t.Context(), renewReq); !errors.Is(err, logical.ErrUnsupportedOperation) {
		t.Fatalf("renew: got err=%v, want ErrUnsupportedOperation", err)
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

func TestCredsIssue_UpstreamError(t *testing.T) {
	b, storage := getTestBackend(t)

	// Inject fake IAM client that returns an error
	credentialgcp.SetIAMClientFactory(b, func(credentialsJSON string) credentialgcp.IAMCredentialsClient {
		return credentialgcp.NewFakeIAMClient(
			func(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (string, time.Time, error) {
				return "", time.Time{}, fmt.Errorf("GCP API error (HTTP 403): PERMISSION_DENIED: caller does not have permission")
			},
			nil,
		)
	})

	// Write config
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			// The injected IAM client fails on purpose, so the role-write capability
			// probe would (correctly) reject the role. This test exercises
			// issuance-time failure/recovery, not configuration-time verification.
			"verify_minter_capability": false,
		},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// Write minter set
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
		Data: map[string]any{
			"minters": []any{
				map[string]any{
					"id":               "minter-1",
					"credentials_json": testCredentialsJSON,
					"never_expires":    true,
				},
			},
		},
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Write role
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]any{
			"default_ttl":           3600,
			"max_ttl":               3600,
			"service_account_email": "target-sa@test-project.iam.gserviceaccount.com",
			"scopes":                testRoleScope,
			"minter_set":            "default",
		},
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	// Issue should fail
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for upstream failure")
	}
}

func TestCredsIssue_ClassifiesQuotaError(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// Replace the IAM factory so GenerateAccessToken returns a quota error,
	// which classifyGCPError maps to HTTP 429.
	credentialgcp.SetIAMClientFactory(b, func(credentialsJSON string) credentialgcp.IAMCredentialsClient {
		return credentialgcp.NewFakeIAMClient(
			func(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (string, time.Time, error) {
				return "", time.Time{}, fmt.Errorf("GCP API error (HTTP 429): RESOURCE_EXHAUSTED: quota exceeded")
			},
			nil,
		)
	})

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
	// #5: the raw upstream error detail must NOT leak to the client.
	if strings.Contains(msg, "RESOURCE_EXHAUSTED") || strings.Contains(msg, "quota exceeded") {
		t.Fatalf("client message leaked upstream detail: %q", msg)
	}
}

func TestCredsIssue_CustomScopes(t *testing.T) {
	b, storage := getTestBackend(t)

	var capturedScopes []string

	// Inject fake IAM client that captures the scopes
	credentialgcp.SetIAMClientFactory(b, func(credentialsJSON string) credentialgcp.IAMCredentialsClient {
		return credentialgcp.NewFakeIAMClient(
			func(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (string, time.Time, error) {
				capturedScopes = scopes
				expiry := time.Now().Add(lifetime)
				return "ya29.custom-scope-token", expiry, nil
			},
			nil,
		)
	})

	// Write config
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]any{},
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// Write minter set
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
		Data: map[string]any{
			"minters": []any{
				map[string]any{
					"id":               "minter-1",
					"credentials_json": testCredentialsJSON,
					"never_expires":    true,
				},
			},
		},
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Write role with custom scopes
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/scoped-role",
		Storage:   storage,
		Data: map[string]any{
			"default_ttl":           3600,
			"max_ttl":               3600,
			"service_account_email": "target-sa@test-project.iam.gserviceaccount.com",
			"scopes":                "https://www.googleapis.com/auth/compute,https://www.googleapis.com/auth/devstorage.read_only",
			"minter_set":            "default",
		},
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	// Issue credential
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/scoped-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("creds issue failed: err=%v resp=%v", err, resp)
	}

	// Verify scopes were passed
	if len(capturedScopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d: %v", len(capturedScopes), capturedScopes)
	}
	if capturedScopes[0] != "https://www.googleapis.com/auth/compute" {
		t.Fatalf("unexpected scope[0]: %v", capturedScopes[0])
	}
	if capturedScopes[1] != "https://www.googleapis.com/auth/devstorage.read_only" {
		t.Fatalf("unexpected scope[1]: %v", capturedScopes[1])
	}
}

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
