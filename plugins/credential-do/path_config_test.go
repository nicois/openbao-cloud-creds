package credentialdo_test

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// backendOption adjusts the BackendConfig before the backend is constructed. Variadic so the
// existing callers are untouched; it exists because the identity view core would supply is part of
// that config, and a test asserting on WHOSE unit obtained a credential cannot set it afterwards.
type backendOption func(*logical.BackendConfig)

func getTestBackend(t *testing.T, opts ...backendOption) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	for _, opt := range opts {
		opt(config)
	}
	b, err := credentialdo.Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	// Point the backend at a fake DO API. Minter-set and role writes now run a
	// capability probe (a real mint-and-delete, see capability.go), so a backend
	// left on the default production base URL would make a live network call.
	// Tests that need their own fake simply rewrite config over this one.
	srv := fakes.NewDOServer()
	t.Cleanup(srv.Close)
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: config.StorageView,
		Data: map[string]any{"do_api_url": srv.URL},
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
		Data:      map[string]any{},
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

	if resp.Data["cloud"] != "do" {
		t.Fatalf("expected cloud=do, got %v", resp.Data["cloud"])
	}
}
