package credentialdo_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := credentialdo.Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
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
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":            "minter-1",
					"token":         "dop_v1_abc123",
					"never_expires": true,
				},
			},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// Read config
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config read failed: err=%v resp=%v", err, resp)
	}

	if resp.Data["cloud"] != "do" {
		t.Fatalf("expected cloud=do, got %v", resp.Data["cloud"])
	}
}
