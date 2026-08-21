package credentialaws_test

import (
	"testing"

	credentialaws "github.com/nicois/openbao-cloud-creds/plugins/credential-aws"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := credentialaws.Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	// Role and minter-set writes run a capability probe (a real AssumeRole), so a
	// test backend with no injected client would otherwise call AWS. Tests that
	// need particular STS behaviour inject their own factory over this one.
	credentialaws.SetSTSClientFactory(b, func(_, _, _, _ string) credentialaws.STSClient {
		return credentialaws.NewFakeSTSClient(nil, nil)
	})
	return b, config.StorageView
}

func TestConfigWriteRead(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write config: operational settings only (minters live in minter sets)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"region": "eu-west-1",
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

	if resp.Data["cloud"] != "aws" {
		t.Fatalf("expected cloud=aws, got %v", resp.Data["cloud"])
	}
	if resp.Data["region"] != "eu-west-1" {
		t.Fatalf("expected region=eu-west-1, got %v", resp.Data["region"])
	}
}
