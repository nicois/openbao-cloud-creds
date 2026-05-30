package credentialaws_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestFullLifecycle(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// 1. Issue credential
	issueReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	issueResp, err := b.HandleRequest(context.Background(), issueReq)
	if err != nil || issueResp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, issueResp)
	}

	// Verify envelope
	if issueResp.Data["cloud"] != "aws" {
		t.Fatalf("bad cloud: %v", issueResp.Data["cloud"])
	}
	if issueResp.Data["renewable"] != false {
		t.Fatalf("expected renewable=false, got %v", issueResp.Data["renewable"])
	}
	if issueResp.Data["expires_at"] == nil {
		t.Fatal("missing expires_at")
	}
	meta, ok := issueResp.Data["metadata"].(map[string]interface{})
	if !ok || meta["api_version"] != "2" {
		t.Fatalf("bad metadata: %v", issueResp.Data["metadata"])
	}
	if meta["minter_set"] != "default" || meta["minter_id"] != "minter-1" {
		t.Fatalf("bad provenance: set=%v id=%v", meta["minter_set"], meta["minter_id"])
	}
	if meta["issued_by"] != "cloud-creds-aws/v0.1" {
		t.Fatalf("bad issued_by: %v", meta["issued_by"])
	}
	if meta["scope"] != "arn:aws:iam::123456789012:role/test" {
		t.Fatalf("bad scope: %v", meta["scope"])
	}

	// Verify credential structure
	cred, ok := issueResp.Data["credential"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credential map, got %T", issueResp.Data["credential"])
	}
	if cred["access_key_id"] == nil || cred["access_key_id"] == "" {
		t.Fatal("expected credential.access_key_id")
	}
	if cred["secret_access_key"] == nil || cred["secret_access_key"] == "" {
		t.Fatal("expected credential.secret_access_key")
	}
	if cred["session_token"] == nil || cred["session_token"] == "" {
		t.Fatal("expected credential.session_token")
	}

	// 2. Renew should be denied (STS creds are not renewable)
	renewReq := &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    issueResp.Secret,
	}
	renewResp, err := b.HandleRequest(context.Background(), renewReq)
	if err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	if renewResp == nil || !renewResp.IsError() {
		t.Fatal("expected renew to be denied for STS creds")
	}

	// 3. Revoke lease (no-op, just removes tracking)
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    issueResp.Secret,
	}
	revokeResp, err := b.HandleRequest(context.Background(), revokeReq)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if revokeResp != nil && revokeResp.IsError() {
		t.Fatalf("revoke error: %v", revokeResp)
	}

	// 4. Issue another to prove plugin still works after revoke
	issueResp2, err := b.HandleRequest(context.Background(), issueReq)
	if err != nil || issueResp2.IsError() {
		t.Fatalf("second issue failed: err=%v resp=%v", err, issueResp2)
	}

	// 5. Reconcile dry-run
	reconcileReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data:      map[string]interface{}{"mode": "dry_run"},
	}
	reconcileResp, err := b.HandleRequest(context.Background(), reconcileReq)
	if err != nil || (reconcileResp != nil && reconcileResp.IsError()) {
		t.Fatalf("reconcile failed: err=%v resp=%v", err, reconcileResp)
	}

	// 6. Metrics query
	metricsReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metrics/entity/default/minter-1",
		Storage:   storage,
	}
	metricsResp, err := b.HandleRequest(context.Background(), metricsReq)
	if err != nil {
		t.Fatalf("metrics query failed: %v", err)
	}
	if metricsResp == nil {
		t.Fatal("expected metrics data")
	}
	if metricsResp.Data["access_count"] == nil {
		t.Fatal("expected access_count in metrics response")
	}
}
