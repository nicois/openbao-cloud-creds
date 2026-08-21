package metricspath_test

import (
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
	"github.com/nicois/openbao-cloud-creds/pkg/metricspath"
)

func findPath(t *testing.T, paths []*framework.Path, substr string) *framework.Path {
	t.Helper()
	for _, p := range paths {
		if strings.Contains(p.Pattern, substr) {
			return p
		}
	}
	t.Fatalf("no path matching %q", substr)
	return nil
}

func call(t *testing.T, p *framework.Path, op logical.Operation, raw map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	return p.Operations[op].Handler()(t.Context(), &logical.Request{}, &framework.FieldData{Raw: raw, Schema: p.Fields})
}

func TestPaths_EntityReturnsMergedFields(t *testing.T) {
	now := time.Now()
	tr := metrics.NewAccessTracker("node-1", metrics.NewInMemoryStore())
	tr.RecordAccess("ent-1", "role-a", now)
	paths := metricspath.Paths(func() *metrics.AccessTracker { return tr }, 604800)

	resp, err := call(t, findPath(t, paths, "metrics/entity/"), logical.ReadOperation, map[string]interface{}{"entity_id": "ent-1"})
	if err != nil {
		t.Fatalf("entity read: %v", err)
	}
	if resp == nil || resp.Data["access_count"] == nil {
		t.Fatalf("expected access_count, got %v", resp)
	}
}

func TestPaths_EntityUnknownReturnsNil(t *testing.T) {
	tr := metrics.NewAccessTracker("node-1", metrics.NewInMemoryStore())
	paths := metricspath.Paths(func() *metrics.AccessTracker { return tr }, 604800)
	resp, err := call(t, findPath(t, paths, "metrics/entity/"), logical.ReadOperation, map[string]interface{}{"entity_id": "nope"})
	if err != nil {
		t.Fatalf("entity read: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil for unknown entity, got %v", resp)
	}
}

func TestPaths_NilTrackerErrors(t *testing.T) {
	paths := metricspath.Paths(func() *metrics.AccessTracker { return nil }, 604800)
	resp, err := call(t, findPath(t, paths, "metrics/entity/"), logical.ReadOperation, map[string]interface{}{"entity_id": "x"})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response for nil tracker, got %v", resp)
	}
}

func TestPaths_StaleReturnsList(t *testing.T) {
	now := time.Now()
	tr := metrics.NewAccessTracker("node-1", metrics.NewInMemoryStore())
	tr.RecordAccess("old-ent", "role-a", now.Add(-10*24*time.Hour))
	paths := metricspath.Paths(func() *metrics.AccessTracker { return tr }, 604800)
	resp, err := call(t, findPath(t, paths, "metrics/stale"), logical.ListOperation, map[string]interface{}{"older_than": 604800})
	if err != nil {
		t.Fatalf("stale list: %v", err)
	}
	if resp == nil {
		t.Fatal("expected stale list response")
	}
}
