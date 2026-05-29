package metrics_test

import (
	"context"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
)

func TestRecordAccess(t *testing.T) {
	store := metrics.NewInMemoryStore()
	tracker := metrics.NewAccessTracker("node-1", store)

	now := time.Now()
	tracker.RecordAccess("entity-1", "role-a", now)
	tracker.RecordAccess("entity-1", "role-a", now.Add(time.Minute))

	entry := tracker.Get("entity-1", "role-a")
	if entry == nil {
		t.Fatal("expected entry")
	}
	if entry.AccessCount != 2 {
		t.Fatalf("expected count=2, got %d", entry.AccessCount)
	}
	if !entry.LastAccessAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected last_access_at: %v", entry.LastAccessAt)
	}
}

func TestFlushAndLoad(t *testing.T) {
	store := metrics.NewInMemoryStore()
	tracker := metrics.NewAccessTracker("node-1", store)

	now := time.Now()
	tracker.RecordAccess("entity-1", "role-a", now)
	tracker.RecordAccess("entity-1", "role-a", now.Add(time.Minute))

	if err := tracker.Flush(context.Background(), now.Add(2*time.Minute)); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	tracker2 := metrics.NewAccessTracker("node-2", store)
	merged, err := tracker2.MergeEntity(context.Background(), "entity-1", now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if merged.AccessCount != 2 {
		t.Fatalf("expected merged count=2, got %d", merged.AccessCount)
	}
	if merged.StalenessSeconds > 120 {
		t.Fatalf("unexpected staleness: %d", merged.StalenessSeconds)
	}
}

func TestMergeMultipleNodes(t *testing.T) {
	store := metrics.NewInMemoryStore()
	t1 := metrics.NewAccessTracker("node-1", store)
	t2 := metrics.NewAccessTracker("node-2", store)

	now := time.Now()
	t1.RecordAccess("entity-1", "role-a", now)
	t1.RecordAccess("entity-1", "role-a", now.Add(time.Minute))
	t2.RecordAccess("entity-1", "role-a", now.Add(2*time.Minute))

	if err := t1.Flush(context.Background(), now.Add(3*time.Minute)); err != nil {
		t.Fatalf("t1 flush failed: %v", err)
	}
	if err := t2.Flush(context.Background(), now.Add(3*time.Minute)); err != nil {
		t.Fatalf("t2 flush failed: %v", err)
	}

	t3 := metrics.NewAccessTracker("node-3", store)
	merged, err := t3.MergeEntity(context.Background(), "entity-1", now.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if merged.AccessCount != 3 {
		t.Fatalf("expected merged count=3, got %d", merged.AccessCount)
	}
}

func TestListStaleEntities(t *testing.T) {
	store := metrics.NewInMemoryStore()
	tracker := metrics.NewAccessTracker("node-1", store)

	now := time.Now()
	tracker.RecordAccess("old-entity", "role-a", now.Add(-10*24*time.Hour))
	tracker.RecordAccess("fresh-entity", "role-a", now.Add(-1*time.Hour))

	if err := tracker.Flush(context.Background(), now); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	stale, err := tracker.ListStaleEntities(context.Background(), 7*24*time.Hour, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stale) != 1 {
		t.Fatalf("expected 1 stale entity, got %d", len(stale))
	}
	if stale[0] != "old-entity" {
		t.Fatalf("expected old-entity, got %s", stale[0])
	}
}
