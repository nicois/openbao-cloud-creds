package credentialexoscale_test

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	credentialexoscale "github.com/nicois/openbao-cloud-creds/plugins/credential-exoscale"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := credentialexoscale.Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	// Point the backend at a fake Exoscale API. Minter-set and role writes now run
	// a capability probe (a real create/delete api-key, see capability.go), so a
	// backend left on the production URL would make a live network call. Tests
	// needing their own fake rewrite config over this.
	srv := fakes.NewExoscaleServer()
	t.Cleanup(srv.Close)
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: config.StorageView,
		Data: map[string]interface{}{"exoscale_api_url": srv.URL},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("test config write failed: err=%v resp=%v", err, resp)
	}
	return b, config.StorageView
}

func TestConfigWriteRead(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write config (operational settings only; minters live in minter-sets)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{},
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

	if resp.Data["cloud"] != "exoscale" {
		t.Fatalf("expected cloud=exoscale, got %v", resp.Data["cloud"])
	}
}
