package metrics_test

import (
	"sort"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestStorageBackedStore_PutGetRoundTrip(t *testing.T) {
	ctx := t.Context()
	s := metrics.NewStorageBackedStore(&logical.InmemStorage{})
	if err := s.Put(ctx, "metrics/e/r/node", []byte("hello")); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.Get(ctx, "metrics/e/r/node")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want hello", got)
	}
}

func TestStorageBackedStore_GetMissingReturnsNotFound(t *testing.T) {
	ctx := t.Context()
	s := metrics.NewStorageBackedStore(&logical.InmemStorage{})
	if _, err := s.Get(ctx, "metrics/absent/r/node"); err == nil {
		t.Fatal("expected not-found error for absent key, got nil")
	}
}

// The contract test: List must return FULL recursive keys, matching what
// InMemoryStore returns and what MergeEntity/ListStaleEntities consume. A
// naive delegate that returns logical.Storage's relative children would
// return ["e/"] here and break every consumer.
func TestStorageBackedStore_ListReturnsFullRecursiveKeys(t *testing.T) {
	ctx := t.Context()
	s := metrics.NewStorageBackedStore(&logical.InmemStorage{})
	put := func(k string) {
		if err := s.Put(ctx, k, []byte("x")); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
	}
	put("metrics/entityA/roleX/node1")
	put("metrics/entityA/roleX/node2")
	put("metrics/entityA/roleY/node1")
	put("metrics/entityB/roleZ/node1")

	got, err := s.List(ctx, "metrics/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{
		"metrics/entityA/roleX/node1",
		"metrics/entityA/roleX/node2",
		"metrics/entityA/roleY/node1",
		"metrics/entityB/roleZ/node1",
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %d keys %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key %d: got %q want %q", i, got[i], want[i])
		}
	}
}

// End-to-end: the real consumers (Flush + ListStaleEntities) must work through
// StorageBackedStore exactly as they do through InMemoryStore.
func TestStorageBackedStore_ConsumerParity(t *testing.T) {
	ctx := t.Context()
	s := metrics.NewStorageBackedStore(&logical.InmemStorage{})
	tr := metrics.NewAccessTracker("node1", s)

	old := time.Now().Add(-48 * time.Hour)
	tr.RecordAccess("set/minter-old", "role-a", old)
	if err := tr.Flush(ctx, old); err != nil {
		t.Fatalf("flush: %v", err)
	}

	stale, err := tr.ListStaleEntities(ctx, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("list stale: %v", err)
	}
	found := false
	for _, e := range stale {
		if e == "set/minter-old" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected set/minter-old in stale list, got %v", stale)
	}
}
