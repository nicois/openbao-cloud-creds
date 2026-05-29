package credentialazure_test

import (
	"context"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestMinterFailureAndRecovery(t *testing.T) {
	srv := fakes.NewAzureServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// Inject 401 error
	srv.SetNextStatus(401)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when minter fails")
	}

	// Recovery: next call should succeed (no more injected errors)
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error on retry: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("expected success after recovery, got: %v", resp)
	}
}

func TestUpstreamTimeout(t *testing.T) {
	srv := fakes.NewAzureServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	srv.SetNextStatus(504)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for upstream timeout")
	}
}
