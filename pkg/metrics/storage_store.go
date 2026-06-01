package metrics

import (
	"context"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// StorageBackedStore implements MetricsStore over a logical.Storage view, so
// flushed access metrics persist across reloads and (because the keyspace is
// raft-replicated) merge across nodes via the per-node key suffix.
type StorageBackedStore struct {
	storage logical.Storage
}

func NewStorageBackedStore(storage logical.Storage) *StorageBackedStore {
	return &StorageBackedStore{storage: storage}
}

func (s *StorageBackedStore) Put(ctx context.Context, key string, value []byte) error {
	return s.storage.Put(ctx, &logical.StorageEntry{Key: key, Value: value})
}

func (s *StorageBackedStore) Get(ctx context.Context, key string) ([]byte, error) {
	entry, err := s.storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		// Match InMemoryStore.Get so consumers see an identical contract.
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return entry.Value, nil
}

// List returns the full keys under prefix. logical.Storage.List returns only
// the relative immediate children (a nested level appears as "child/"), so we
// recurse and re-prepend the prefix, yielding the flat full-key list the
// MetricsStore consumers (MergeEntity / ListStaleEntities) require.
func (s *StorageBackedStore) List(ctx context.Context, prefix string) ([]string, error) {
	children, err := s.storage.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, child := range children {
		full := prefix + child
		if strings.HasSuffix(child, "/") {
			sub, err := s.List(ctx, full)
			if err != nil {
				return nil, err
			}
			keys = append(keys, sub...)
			continue
		}
		keys = append(keys, full)
	}
	return keys, nil
}
