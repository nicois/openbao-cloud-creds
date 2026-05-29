package metrics

import (
	"encoding/json"
	"fmt"
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
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
	List(prefix string) ([]string, error)
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

func (t *AccessTracker) Flush(now time.Time) error {
	t.mu.Lock()
	snapshot := make(map[accessKey]*AccessEntry, len(t.entries))
	for k, v := range t.entries {
		cp := *v
		cp.FlushedAt = now
		snapshot[k] = &cp
	}
	t.mu.Unlock()

	for k, entry := range snapshot {
		storageKey := fmt.Sprintf("metrics/%s/%s/%s", k.EntityID, k.Role, t.nodeID)
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if err := t.store.Put(storageKey, data); err != nil {
			return err
		}
	}
	return nil
}

func (t *AccessTracker) MergeEntity(entityID string, now time.Time) (*MergedEntry, error) {
	prefix := fmt.Sprintf("metrics/%s/", entityID)
	keys, err := t.store.List(prefix)
	if err != nil {
		return nil, err
	}

	merged := &MergedEntry{Source: "merged_only"}
	var latestFlush time.Time

	for _, key := range keys {
		data, err := t.store.Get(key)
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

	// Check local in-memory entries
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

func (s *InMemoryStore) Put(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return nil
}

func (s *InMemoryStore) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return v, nil
}

func (s *InMemoryStore) List(prefix string) ([]string, error) {
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
