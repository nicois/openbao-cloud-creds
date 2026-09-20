package credentialaws_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	credentialaws "github.com/nicois/openbao-cloud-creds/plugins/credential-aws"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestMinterFailureAndRecovery(t *testing.T) {
	b, storage := getTestBackend(t)

	callCount := 0
	credentialaws.SetSTSClientFactory(b, func(accessKeyID, secretAccessKey, region, endpoint string) credentialaws.STSClient {
		return credentialaws.NewFakeSTSClient(
			func(ctx context.Context, params *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
				callCount++
				if callCount == 1 {
					return nil, fmt.Errorf("AccessDenied: not authorized")
				}
				expiration := time.Now().Add(900 * time.Second)
				return &sts.AssumeRoleOutput{
					Credentials: &ststypes.Credentials{
						AccessKeyId:     aws.String("AKIAFAKEKEY123456789"),
						SecretAccessKey: aws.String("fakesecret"),
						SessionToken:    aws.String("faketoken"),
						Expiration:      &expiration,
					},
					AssumedRoleUser: &ststypes.AssumedRoleUser{
						Arn:           aws.String("arn:aws:sts::123456789012:assumed-role/test/session"),
						AssumedRoleId: aws.String("AROAFAKEID:session"),
					},
				}, nil
			},
			nil,
		)
	})

	// Write config: operational settings only
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			// The injected STS client fails on purpose, so the role-write capability
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
					"id":                "minter-1",
					"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					"never_expires":     true,
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
			"default_ttl":  900,
			"max_ttl":      3600,
			"iam_role_arn": "arn:aws:iam::123456789012:role/test",
			"minter_set":   "default",
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
