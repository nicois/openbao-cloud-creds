package credentialovh_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	credentialovh "github.com/nicois/openbao-cloud-creds/plugins/credential-ovh"
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

func setupConfiguredBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)

	// Inject fake token client
	credentialovh.SetTokenClientFactory(b, func(clientID, clientSecret, tokenEndpoint string) credentialovh.TokenClient {
		return credentialovh.NewFakeTokenClient(nil, nil)
	})

	// Write config: operational settings only (minters live in minter-sets)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"region": "eu",
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
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":            "minter-1",
					"client_id":     "test-client-id",
					"client_secret": "test-client-secret",
					"never_expires": true,
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
		Data: map[string]interface{}{
			"default_ttl": 3600,
			"max_ttl":     3600,
			"minter_set":  "default",
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

	if resp.Data["cloud"] != "ovh" {
		t.Fatalf("expected cloud=ovh, got %v", resp.Data["cloud"])
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

	// Revoke (no-op for OVH, just removes tracking)
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

	// Renew should fail — OVH access tokens are not renewable
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

	// Inject fake token client that returns an error
	credentialovh.SetTokenClientFactory(b, func(clientID, clientSecret, tokenEndpoint string) credentialovh.TokenClient {
		return credentialovh.NewFakeTokenClient(
			func(ctx context.Context) (string, int, error) {
				return "", 0, fmt.Errorf("OVH OAuth2 error (HTTP 401): invalid_client: invalid client_id or client_secret")
			},
			nil,
		)
	})

	// Write config
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"region": "eu",
			// The injected token client fails on purpose, so the role-write capability
			// probe would (correctly) reject the role. This test exercises issuance-time
			// failure/recovery, not configuration-time verification.
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
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":            "minter-1",
					"client_id":     "bad-id",
					"client_secret": "bad-secret",
					"never_expires": true,
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
		Data: map[string]interface{}{
			"default_ttl": 3600,
			"max_ttl":     3600,
			"minter_set":  "default",
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

	// Replace the token factory so MintToken returns a quota error, which
	// classifyOVHError maps to HTTP 429.
	credentialovh.SetTokenClientFactory(b, func(clientID, clientSecret, tokenEndpoint string) credentialovh.TokenClient {
		return credentialovh.NewFakeTokenClient(
			func(ctx context.Context) (string, int, error) {
				return "", 0, fmt.Errorf("OVH OAuth2 error (HTTP 429): rate limit exceeded")
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
	if strings.Contains(msg, "rate limit exceeded") || strings.Contains(msg, "429") {
		t.Fatalf("client message leaked upstream detail: %q", msg)
	}
}

// TestCredsIssue_SetNotLoaded proves issuing fails when the role's bound minter
// set is no longer loaded (e.g. it was deleted after the role was created).
func TestCredsIssue_SetNotLoaded(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// Delete the minter set the role is bound to.
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set delete failed: err=%v resp=%v", err, resp)
	}

	// Issue should fail because the bound set is no longer loaded.
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
		t.Fatal("expected error response when bound minter set is not loaded")
	}
}
