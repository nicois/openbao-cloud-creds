package credentialovh_test

import (
	"context"
	"fmt"
	"testing"

	credentialovh "github.com/nicois/openbao-cloud-creds/plugins/credential-ovh"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestMinterFailureAndRecovery(t *testing.T) {
	b, storage := getTestBackend(t)

	callCount := 0
	credentialovh.SetTokenClientFactory(b, func(clientID, clientSecret, tokenEndpoint string) credentialovh.TokenClient {
		return credentialovh.NewFakeTokenClient(
			func(ctx context.Context) (string, int, error) {
				callCount++
				if callCount == 1 {
					return "", 0, fmt.Errorf("OVH OAuth2 error (HTTP 401): invalid_client: temporary failure")
				}
				return "ovh-recovered-token", 3600, nil
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
			"minters": []interface{}{
				map[string]interface{}{
					"id":            "minter-1",
					"client_id":     "test-client-id",
					"client_secret": "test-client-secret",
					"never_expires": true,
				},
			},
			"region": "eu",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// Write role
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl": 3600,
			"max_ttl":     3600,
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	// First call should fail
	issueReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when minter fails")
	}

	// Recovery: second call should succeed
	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil {
		t.Fatalf("unexpected error on retry: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("expected success after recovery, got: %v", resp)
	}
}
