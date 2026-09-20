package credentialupcloud_test

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	credentialupcloud "github.com/nicois/openbao-cloud-creds/plugins/credential-upcloud"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := credentialupcloud.Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	// Point the backend at a fake UpCloud API. Minter-set and role writes now run
	// a capability probe (a real token create-and-delete, see capability.go), so a
	// backend left on the production base URL would make a live network call.
	// Tests that need their own fake simply rewrite config over this one.
	srv := fakes.NewUpCloudServer()
	t.Cleanup(srv.Close)
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: config.StorageView,
		Data: map[string]any{"username": "testuser", "upcloud_api_url": srv.URL},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("test config write failed: err=%v resp=%v", err, resp)
	}
	return b, config.StorageView
}

func TestConfigWriteRead(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write config
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"username": "testuser",
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

	if resp.Data["cloud"] != "upcloud" {
		t.Fatalf("expected cloud=upcloud, got %v", resp.Data["cloud"])
	}
}

func TestConfigWrite_MissingUsername(t *testing.T) {
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
		t.Fatal("expected error for missing username")
	}
}
