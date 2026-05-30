package credentialexoscale_test

import (
	"context"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestMetricsEntityEndpoint(t *testing.T) {
	srv := fakes.NewExoscaleServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// Issue a cred first to generate metrics
	issueReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	_, err := b.HandleRequest(context.Background(), issueReq)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	// Query metrics
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metrics/entity/default/minter-1",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("metrics read failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected metrics response")
	}
	if resp.Data["access_count"] == nil {
		t.Fatal("expected access_count in metrics")
	}
}
