package credentialoci_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestMetricsEntity(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// Issue a credential to generate metrics
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("creds read failed: %v", err)
	}

	// Query metrics for the minter (composite set/minter entity key)
	metricsReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metrics/entity/default/minter-1",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), metricsReq)
	if err != nil {
		t.Fatalf("metrics query failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected metrics response")
	}
	if resp.Data["access_count"] == nil {
		t.Fatal("expected access_count")
	}
}

func TestMetricsStale(t *testing.T) {
	b, storage := setupConfiguredBackend(t)

	// Issue a credential
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("creds read failed: %v", err)
	}

	// Query stale entities (everything accessed within last second should not be stale)
	staleReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "metrics/stale",
		Storage:   storage,
		Data:      map[string]interface{}{"older_than": 1},
	}
	resp, err := b.HandleRequest(context.Background(), staleReq)
	if err != nil {
		t.Fatalf("stale query failed: %v", err)
	}
	// Since we just accessed, nothing should be stale at 1 second threshold
	if resp != nil && resp.Data != nil {
		keys, ok := resp.Data["keys"].([]string)
		if ok && len(keys) > 0 {
			t.Fatalf("expected no stale entities immediately after access, got %v", keys)
		}
	}
}
