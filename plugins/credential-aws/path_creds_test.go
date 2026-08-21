package credentialaws_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	credentialaws "github.com/nicois/openbao-cloud-creds/plugins/credential-aws"
	"github.com/openbao/openbao/sdk/v2/logical"
)

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

func setupConfiguredBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)

	// Inject fake STS client
	credentialaws.SetSTSClientFactory(b, func(accessKeyID, secretAccessKey, region, endpoint string) credentialaws.STSClient {
		return credentialaws.NewFakeSTSClient(nil, nil)
	})

	// Write config: operational settings only
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"region": "us-east-1",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
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
					"id":                "minter-1",
					"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					"never_expires":     true,
				},
			},
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Write role bound to the set
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":  900,
			"max_ttl":      3600,
			"iam_role_arn": "arn:aws:iam::123456789012:role/test",
			"minter_set":   "default",
			"session_tags": map[string]interface{}{
				"owner": "cloud-creds",
			},
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
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
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("creds read failed: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("creds read error: %v", resp)
	}

	if resp.Data["cloud"] != "aws" {
		t.Fatalf("expected cloud=aws, got %v", resp.Data["cloud"])
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
	if cred["access_key_id"] == nil {
		t.Fatal("expected credential.access_key_id")
	}
	if cred["secret_access_key"] == nil {
		t.Fatal("expected credential.secret_access_key")
	}
	if cred["session_token"] == nil {
		t.Fatal("expected credential.session_token")
	}

	// Verify lease internal data
	if resp.Secret == nil {
		t.Fatal("expected secret/lease")
	}
	if resp.Secret.InternalData["access_key_id"] == nil {
		t.Fatal("expected access_key_id in internal_data")
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
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	// Revoke (no-op for STS, just removes tracking)
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

func TestCredsRenew_Denied(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

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

	// Renew should fail — STS creds are not renewable
	renewReq := &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    resp.Secret,
	}
	resp, err = b.HandleRequest(context.Background(), renewReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for renew attempt")
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

func TestCredsIssue_UpstreamError(t *testing.T) {
	b, storage := getTestBackend(t)

	// Inject fake STS client that returns an error
	credentialaws.SetSTSClientFactory(b, func(accessKeyID, secretAccessKey, region, endpoint string) credentialaws.STSClient {
		return credentialaws.NewFakeSTSClient(
			func(ctx context.Context, params *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
				return nil, fmt.Errorf("AccessDenied: User: arn:aws:iam::123456789012:user/minter is not authorized to perform: sts:AssumeRole")
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
			// The injected STS client fails on purpose, so the role-write capability
			// probe would (correctly) reject the role. This test exercises
			// issuance-time failure/recovery, not configuration-time verification.
			"verify_minter_capability": false,
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
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
					"id":                "minter-1",
					"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					"never_expires":     true,
				},
			},
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Write role
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":  900,
			"max_ttl":      3600,
			"iam_role_arn": "arn:aws:iam::123456789012:role/test",
			"minter_set":   "default",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	// Issue should fail
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for upstream failure")
	}
}

func TestCredsIssue_ClassifiesQuotaError(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// Replace the STS factory so AssumeRole returns a throttling error, which
	// classifyAWSError maps to HTTP 429.
	credentialaws.SetSTSClientFactory(b, func(accessKeyID, secretAccessKey, region, endpoint string) credentialaws.STSClient {
		return credentialaws.NewFakeSTSClient(
			func(ctx context.Context, params *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
				return nil, fmt.Errorf("Throttling: Rate exceeded")
			},
			nil,
		)
	})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
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
	if strings.Contains(msg, "Throttling") || strings.Contains(msg, "Rate exceeded") {
		t.Fatalf("client message leaked upstream detail: %q", msg)
	}
}

func TestCredsIssue_SessionTags(t *testing.T) {
	b, storage := getTestBackend(t)

	var capturedInput *sts.AssumeRoleInput

	// Inject fake STS client that captures the input
	credentialaws.SetSTSClientFactory(b, func(accessKeyID, secretAccessKey, region, endpoint string) credentialaws.STSClient {
		return credentialaws.NewFakeSTSClient(
			func(ctx context.Context, params *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
				capturedInput = params
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

	// Write config
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{},
	}
	resp, err := b.HandleRequest(context.Background(), req)
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
					"id":                "minter-1",
					"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					"never_expires":     true,
				},
			},
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Write role with session tags
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/tagged-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl":  900,
			"max_ttl":      3600,
			"iam_role_arn": "arn:aws:iam::123456789012:role/tagged",
			"minter_set":   "default",
			"session_tags": map[string]interface{}{
				"team":  "platform",
				"owner": "cloud-creds",
			},
			"external_id": "ext-456",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	// Issue credential
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/tagged-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("creds issue failed: err=%v resp=%v", err, resp)
	}

	// Verify session tags were passed
	if capturedInput == nil {
		t.Fatal("expected AssumeRole to be called")
	}
	if len(capturedInput.Tags) != 2 {
		t.Fatalf("expected 2 session tags, got %d", len(capturedInput.Tags))
	}
	if capturedInput.ExternalId == nil || *capturedInput.ExternalId != "ext-456" {
		t.Fatalf("expected external_id=ext-456, got %v", capturedInput.ExternalId)
	}
}

// TestMinterSetIsolation proves a role bound to a second, independent set mints
// from that set's minter — not the default set's — both in provenance metadata
// and in the actual access key handed to the STS client factory.
func TestMinterSetIsolation(t *testing.T) {
	b, storage := getTestBackend(t)

	// Capture which access key id the factory is constructed with.
	var lastAccessKeyID string
	credentialaws.SetSTSClientFactory(b, func(accessKeyID, secretAccessKey, region, endpoint string) credentialaws.STSClient {
		lastAccessKeyID = accessKeyID
		return credentialaws.NewFakeSTSClient(nil, nil)
	})

	// config
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}

	// default set + role
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-1", "access_key_id": "AKIADEFAULT", "secret_access_key": "s1", "never_expires": true},
		}},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("default set write: err=%v resp=%v", err, resp)
	}

	// secondary set + role
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/secondary", Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-2", "access_key_id": "AKIASECONDARY", "secret_access_key": "s2", "never_expires": true},
		}},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("secondary set write: err=%v resp=%v", err, resp)
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/role2", Storage: storage,
		Data: map[string]interface{}{
			"default_ttl": 900, "max_ttl": 3600,
			"iam_role_arn": "arn:aws:iam::123456789012:role/role2", "minter_set": "secondary",
		},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role2 write: err=%v resp=%v", err, resp)
	}

	// role2 must mint via minter-2 / AKIASECONDARY.
	req = &logical.Request{Operation: logical.ReadOperation, Path: "creds/role2", Storage: storage}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("role2 issue failed: err=%v resp=%v", err, resp)
	}
	meta := resp.Data["metadata"].(map[string]interface{})
	if meta["minter_set"] != "secondary" || meta["minter_id"] != "minter-2" {
		t.Fatalf("role2 used wrong minter: set=%v id=%v", meta["minter_set"], meta["minter_id"])
	}
	if lastAccessKeyID != "AKIASECONDARY" {
		t.Fatalf("role2 minted with wrong access key: %q", lastAccessKeyID)
	}
}
