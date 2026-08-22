package credentialgcp_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	credentialgcp "github.com/nicois/openbao-cloud-creds/plugins/credential-gcp"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestMinterFailureAndRecovery(t *testing.T) {
	b, storage := getTestBackend(t)

	callCount := 0
	credentialgcp.SetIAMClientFactory(b, func(credentialsJSON string) credentialgcp.IAMCredentialsClient {
		return credentialgcp.NewFakeIAMClient(
			func(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (string, time.Time, error) {
				callCount++
				if callCount == 1 {
					return "", time.Time{}, fmt.Errorf("GCP API error (HTTP 403): PERMISSION_DENIED: not authorized")
				}
				expiry := time.Now().Add(lifetime)
				return "ya29.recovered-token", expiry, nil
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
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
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
		Data: map[string]interface{}{
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

	// First call should fail
	issueReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(t.Context(), issueReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when minter fails")
	}

	// Recovery: second call should succeed
	resp, err = b.HandleRequest(t.Context(), issueReq)
	if err != nil {
		t.Fatalf("unexpected error on retry: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("expected success after recovery, got: %v", resp)
	}
}
