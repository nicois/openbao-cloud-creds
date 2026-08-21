package credentialupcloud_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestFullLifecycle(t *testing.T) {
	srv := fakes.NewUpCloudServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

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
	if issueResp.Data["cloud"] != "upcloud" {
		t.Fatalf("bad cloud: %v", issueResp.Data["cloud"])
	}
	if issueResp.Data["expires_at"] == nil {
		t.Fatal("missing expires_at")
	}
	meta, ok := issueResp.Data["metadata"].(map[string]interface{})
	if !ok || meta["api_version"] != "2" {
		t.Fatalf("bad metadata: %v", issueResp.Data["metadata"])
	}
	if meta["issued_by"] != "cloud-creds-upcloud/v0.1" {
		t.Fatalf("bad issued_by: %v", meta["issued_by"])
	}

	// Verify credential structure
	cred, ok := issueResp.Data["credential"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credential map, got %T", issueResp.Data["credential"])
	}
	if cred["username"] != "testuser" {
		t.Fatalf("expected credential.username=testuser, got %v", cred["username"])
	}
	if cred["password"] == nil || cred["password"] == "" {
		t.Fatal("expected credential.password (bearer token)")
	}

	// 2. Renewal must be refused: the token's expires_in is fixed at mint, so a
	// renewed lease would outlive the token.
	if issueResp.Secret.Renewable {
		t.Error("lease advertises renewable=true: OpenBao REVOKES a lease whose " +
			"renewal fails, so a renew attempt would destroy the credential the " +
			"client was trying to keep (docs/ttl-semantics.md)")
	}

	renewReq := &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    issueResp.Secret,
	}
	// Renewal is refused by the framework itself — the secret declares no Renew
	// callback — so no plugin code runs and no lease is put at risk.
	if _, err := b.HandleRequest(context.Background(), renewReq); !errors.Is(err, logical.ErrUnsupportedOperation) {
		t.Fatalf("renew: got err=%v, want ErrUnsupportedOperation", err)
	}

	// 3. Revoke lease
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
	if issueResp2.Data["credential_id"] == issueResp.Data["credential_id"] {
		t.Fatal("second issue should produce a different credential_id")
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
