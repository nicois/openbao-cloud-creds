package credentialoci_test

import (
	"context"
	"testing"

	credentialoci "github.com/nicois/openbao-cloud-creds/plugins/credential-oci"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestFullLifecycle(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// 1. Issue credential (reads from slot)
	issueReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	issueResp, err := b.HandleRequest(context.Background(), issueReq)
	if err != nil || issueResp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, issueResp)
	}

	// Verify envelope shape
	if issueResp.Data["cloud"] != "oci" {
		t.Fatalf("bad cloud: %v", issueResp.Data["cloud"])
	}
	if issueResp.Data["expires_at"] == nil {
		t.Fatal("missing expires_at")
	}
	if issueResp.Data["renewable"] != false {
		t.Fatal("OCI credentials should not be renewable")
	}
	meta, ok := issueResp.Data["metadata"].(map[string]interface{})
	if !ok || meta["api_version"] != "2" {
		t.Fatalf("bad metadata: %v", issueResp.Data["metadata"])
	}
	if meta["minter_set"] != "default" || meta["minter_id"] != "minter-1" {
		t.Fatalf("bad provenance: set=%v id=%v", meta["minter_set"], meta["minter_id"])
	}

	// 2. Emergency rotation of slot 0
	rotateReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-slot/test-role/0",
		Storage:   storage,
	}
	rotateResp, err := b.HandleRequest(context.Background(), rotateReq)
	if err != nil || (rotateResp != nil && rotateResp.IsError()) {
		t.Fatalf("rotate failed: err=%v resp=%v", err, rotateResp)
	}
	if rotateResp.Data["rotated"] != true {
		t.Fatal("expected rotated=true")
	}

	// 3. Read again — should now get the rotated credential (freshest)
	issueResp2, err := b.HandleRequest(context.Background(), issueReq)
	if err != nil || issueResp2.IsError() {
		t.Fatalf("second issue failed: err=%v resp=%v", err, issueResp2)
	}
	// After rotating slot 0, the freshest slot should be slot 0 with new token
	if issueResp2.Data["credential_id"] == issueResp.Data["credential_id"] {
		t.Fatal("after rotation, credential_id should change")
	}

	// 4. Revoke (soft) — should succeed
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    issueResp2.Secret,
	}
	revokeResp, err := b.HandleRequest(context.Background(), revokeReq)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if revokeResp != nil && revokeResp.IsError() {
		t.Fatalf("revoke error: %v", revokeResp)
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

func TestRotateSlot_InvalidIndex(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-slot/test-role/5",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for invalid slot index")
	}
}

func TestRotateSlot_RoleNotFound(t *testing.T) {
	b, storage := getTestBackend(t)
	credentialoci.TestSetClient(b, credentialoci.NewTestFakeClient())

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-slot/nonexistent/0",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for missing role")
	}
}

func TestRoleDelete_CleansUpSlots(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// Verify creds work before delete
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), readReq)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("pre-delete read failed: err=%v resp=%v", err, resp)
	}

	// Delete role
	delReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/test-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), delReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role delete failed: err=%v resp=%v", err, resp)
	}

	// Verify creds no longer work
	resp, err = b.HandleRequest(context.Background(), readReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error after role deletion")
	}
}
