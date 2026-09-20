package credentialazure_test

import (
	"errors"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestFullLifecycle(t *testing.T) {
	srv := fakes.NewAzureServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// 1. Issue credential
	issueReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	issueResp, err := b.HandleRequest(t.Context(), issueReq)
	if err != nil || issueResp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, issueResp)
	}

	// Verify envelope
	if issueResp.Data["cloud"] != "azure" {
		t.Fatalf("bad cloud: %v", issueResp.Data["cloud"])
	}
	if issueResp.Data["expires_at"] == nil {
		t.Fatal("missing expires_at")
	}
	meta, ok := issueResp.Data["metadata"].(map[string]any)
	if !ok || meta["api_version"] != credenvelope.APIVersion {
		t.Fatalf("bad metadata: %v", issueResp.Data["metadata"])
	}
	if meta["minter_set"] != "default" || meta["minter_id"] != "minter-1" {
		t.Fatalf("bad provenance: set=%v id=%v", meta["minter_set"], meta["minter_id"])
	}
	if meta["issued_by"] != "cloud-creds-azure/v0.1" {
		t.Fatalf("bad issued_by: %v", meta["issued_by"])
	}

	// Verify credential structure
	cred, ok := issueResp.Data["credential"].(map[string]any)
	if !ok {
		t.Fatalf("expected credential map, got %T", issueResp.Data["credential"])
	}
	if cred["client_secret"] == nil || cred["client_secret"] == "" {
		t.Fatal("expected credential.client_secret (password)")
	}
	if cred["client_id"] == nil || cred["client_id"] == "" {
		t.Fatal("expected credential.client_id")
	}
	if cred["tenant_id"] == nil || cred["tenant_id"] == "" {
		t.Fatal("expected credential.tenant_id")
	}

	// 2. Renewal must be refused: the secret's endDateTime is fixed at mint, so a
	// renewed lease would outlive the credential.
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
	if _, err := b.HandleRequest(t.Context(), renewReq); !errors.Is(err, logical.ErrUnsupportedOperation) {
		t.Fatalf("renew: got err=%v, want ErrUnsupportedOperation", err)
	}

	// 3. Revoke lease
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    issueResp.Secret,
	}
	revokeResp, err := b.HandleRequest(t.Context(), revokeReq)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if revokeResp != nil && revokeResp.IsError() {
		t.Fatalf("revoke error: %v", revokeResp)
	}

	// 4. Issue another to prove plugin still works after revoke
	issueResp2, err := b.HandleRequest(t.Context(), issueReq)
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
		Data:      map[string]any{"mode": "dry_run"},
	}
	reconcileResp, err := b.HandleRequest(t.Context(), reconcileReq)
	if err != nil || (reconcileResp != nil && reconcileResp.IsError()) {
		t.Fatalf("reconcile failed: err=%v resp=%v", err, reconcileResp)
	}

}
