package credentialazure_test

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	credentialazure "github.com/nicois/openbao-cloud-creds/plugins/credential-azure"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := credentialazure.Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	// Point the backend at a fake Graph/login endpoint. Minter-set and role
	// writes now run a capability probe (a real addPassword/removePassword, see
	// capability.go), so a backend left on the production endpoints would make a
	// live network call. Tests that need their own fake rewrite config over this.
	srv := fakes.NewAzureServer()
	t.Cleanup(srv.Close)
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: config.StorageView,
		Data: map[string]any{
			"tenant_id": "test-tenant-id", "graph_endpoint": srv.URL, "login_endpoint": srv.URL,
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("test config write failed: err=%v resp=%v", err, resp)
	}
	return b, config.StorageView
}

func TestConfigWriteRead(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write config (cloud settings only; minters live in minter sets)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"tenant_id": "test-tenant-id",
		},
	}

	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// Read config
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config read failed: err=%v resp=%v", err, resp)
	}

	if resp.Data["cloud"] != "azure" {
		t.Fatalf("expected cloud=azure, got %v", resp.Data["cloud"])
	}
}

func TestConfigWrite_MissingTenantID(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]any{},
	}

	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for missing tenant_id")
	}
}
