package credentialovh_test

import (
	"context"
	"testing"

	credentialovh "github.com/nicois/openbao-cloud-creds/plugins/credential-ovh"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := credentialovh.Factory(context.Background(), config)
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
					"client_id":     "my-client-id",
					"client_secret": "my-client-secret",
					"never_expires": true,
				},
			},
			"region": "eu",
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

	if resp.Data["cloud"] != "ovh" {
		t.Fatalf("expected cloud=ovh, got %v", resp.Data["cloud"])
	}
	if resp.Data["region"] != "eu" {
		t.Fatalf("expected region=eu, got %v", resp.Data["region"])
	}
}

func TestConfigWrite_MissingMinters(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for missing minters")
	}
}

func TestConfigWrite_MissingClientCredentials(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":            "minter-1",
					"never_expires": true,
				},
			},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for missing client_id/client_secret")
	}
}

func TestConfigWrite_InvalidRegion(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":            "minter-1",
					"client_id":     "cid",
					"client_secret": "csec",
					"never_expires": true,
				},
			},
			"region": "invalid",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for invalid region")
	}
}

func TestConfigWrite_AllRegions(t *testing.T) {
	for _, region := range []string{"eu", "ca", "us"} {
		t.Run(region, func(t *testing.T) {
			b, storage := getTestBackend(t)

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config",
				Storage:   storage,
				Data: map[string]interface{}{
					"minters": []interface{}{
						map[string]interface{}{
							"id":            "minter-1",
							"client_id":     "cid",
							"client_secret": "csec",
							"never_expires": true,
						},
					},
					"region": region,
				},
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("config write failed for region %s: err=%v resp=%v", region, err, resp)
			}

			// Read back
			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "config",
				Storage:   storage,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("config read failed: err=%v resp=%v", err, resp)
			}
			if resp.Data["region"] != region {
				t.Fatalf("expected region=%s, got %v", region, resp.Data["region"])
			}
		})
	}
}
