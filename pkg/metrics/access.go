package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type AccessEntry struct {
	LastAccessAt time.Time `json:"last_access_at"`
	AccessCount  int64     `json:"access_count"`
	FlushedAt    time.Time `json:"flushed_at"`
}

type MergedEntry struct {
	LastAccessAt     time.Time `json:"last_access_at"`
	AccessCount      int64     `json:"access_count"`
	StalenessSeconds int       `json:"staleness_seconds"`
	Source           string    `json:"source"`
}

type MetricsStore interface {
	Put(ctx context.Context, key string, value []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	List(ctx context.Context, prefix string) ([]string, error)
}

type accessKey struct {
	EntityID string
	Role     string
}

type AccessTracker struct {
	mu      sync.Mutex
	nodeID  string
	store   MetricsStore
	entries map[accessKey]*AccessEntry
}

func NewAccessTracker(nodeID string, store MetricsStore) *AccessTracker {
	return &AccessTracker{
		nodeID:  nodeID,
		store:   store,
		entries: make(map[accessKey]*AccessEntry),
	}
}

func (t *AccessTracker) RecordAccess(entityID, role string, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := accessKey{EntityID: entityID, Role: role}
	entry, ok := t.entries[key]
	if !ok {
		entry = &AccessEntry{}
		t.entries[key] = entry
	}
	entry.AccessCount++
	if at.After(entry.LastAccessAt) {
		entry.LastAccessAt = at
	}
}

func (t *AccessTracker) Get(entityID, role string) *AccessEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.entries[accessKey{EntityID: entityID, Role: role}]
}

func (t *AccessTracker) Flush(ctx context.Context, now time.Time) error {
	t.mu.Lock()
	snapshot := make(map[accessKey]*AccessEntry, len(t.entries))
	for k, v := range t.entries {
		cp := *v
		cp.FlushedAt = now
		snapshot[k] = &cp
	}
	t.mu.Unlock()

	for k, entry := range snapshot {
		storageKey := fmt.Sprintf("metrics/%s/%s/%s",
			url.PathEscape(k.EntityID), url.PathEscape(k.Role), url.PathEscape(t.nodeID))
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if err := t.store.Put(ctx, storageKey, data); err != nil {
			return err
		}
	}
	return nil
}

func (t *AccessTracker) MergeEntity(ctx context.Context, entityID string, now time.Time) (*MergedEntry, error) {
	prefix := fmt.Sprintf("metrics/%s/", url.PathEscape(entityID))
	localSuffix := "/" + url.PathEscape(t.nodeID)
	keys, err := t.store.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	merged := &MergedEntry{Source: "merged_only"}
	var latestFlush time.Time

	for _, key := range keys {
		// Skip this node's own flushed key: its accesses are counted from the
		// live in-memory map below, so summing the storage copy too would
		// double-count on any node that both issued and serves this query.
		if strings.HasSuffix(key, localSuffix) {
			continue
		}
		data, err := t.store.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		var entry AccessEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, err
		}
		merged.AccessCount += entry.AccessCount
		if entry.LastAccessAt.After(merged.LastAccessAt) {
			merged.LastAccessAt = entry.LastAccessAt
		}
		if entry.FlushedAt.After(latestFlush) {
			latestFlush = entry.FlushedAt
		}
	}

	// Add this node's contribution from the live in-memory map (its storage
	// key was skipped above). Edge case: if a local entry was evicted after a
	// flush, this node contributes nothing here — which is correct, since an
	// evicted entry means no active lease for it.
	t.mu.Lock()
	for k, entry := range t.entries {
		if k.EntityID == entityID {
			merged.AccessCount += entry.AccessCount
			if entry.LastAccessAt.After(merged.LastAccessAt) {
				merged.LastAccessAt = entry.LastAccessAt
			}
			merged.Source = "merged_with_local_active"
		}
	}
	t.mu.Unlock()

	if !latestFlush.IsZero() {
		merged.StalenessSeconds = int(now.Sub(latestFlush).Seconds())
	}

	return merged, nil
}

// InMemoryStore is a simple store for testing.
type InMemoryStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{data: make(map[string][]byte)}
}

func (s *InMemoryStore) Put(ctx context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return nil
}

func (s *InMemoryStore) Get(ctx context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return v, nil
}

func (s *InMemoryStore) List(ctx context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (t *AccessTracker) ListStaleEntities(ctx context.Context, olderThan time.Duration, now time.Time) ([]string, error) {
	prefix := "metrics/"
	keys, err := t.store.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	entityAccess := make(map[string]time.Time)
	for _, key := range keys {
		data, err := t.store.Get(ctx, key)
		if err != nil {
			continue
		}
		var entry AccessEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		const maxKeyParts = 3 // entityID/role/nodeID
		parts := strings.SplitN(strings.TrimPrefix(key, "metrics/"), "/", maxKeyParts)
		if len(parts) < 1 {
			continue
		}
		entityID, err := url.PathUnescape(parts[0])
		if err != nil {
			continue
		}
		if existing, ok := entityAccess[entityID]; !ok || entry.LastAccessAt.After(existing) {
			entityAccess[entityID] = entry.LastAccessAt
		}
	}

	threshold := now.Add(-olderThan)
	var stale []string
	for entityID, lastAccess := range entityAccess {
		if lastAccess.Before(threshold) {
			stale = append(stale, entityID)
		}
	}

	sort.Slice(stale, func(i, j int) bool {
		return entityAccess[stale[i]].Before(entityAccess[stale[j]])
	})

	return stale, nil
}
