package credentialgcp_test

import (
	"testing"

	credentialgcp "github.com/nicois/openbao-cloud-creds/plugins/credential-gcp"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := credentialgcp.Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	// Role and minter-set writes run a capability probe (a real
	// generateAccessToken), so a test backend with no injected client would
	// otherwise try to sign a JWT with a fake SA key and call Google. Tests that
	// need particular impersonation behaviour inject their own factory over this.
	credentialgcp.SetIAMClientFactory(b, func(_ string) credentialgcp.IAMCredentialsClient {
		return credentialgcp.NewFakeIAMClient(nil, nil)
	})
	return b, config.StorageView
}

func TestConfigWriteRead(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write config: operational settings only (minters live in minter-sets)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"project": "test-project",
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

	if resp.Data["cloud"] != "gcp" {
		t.Fatalf("expected cloud=gcp, got %v", resp.Data["cloud"])
	}
	if resp.Data["project"] != "test-project" {
		t.Fatalf("expected project=test-project, got %v", resp.Data["project"])
	}
}
