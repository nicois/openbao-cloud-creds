package plugintest

import (
	"context"
	"errors"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// ErrInjectedStorage is returned by FailingStorage. It is a distinct sentinel so a
// test can tell an injected fault from a genuine bug in the code under test.
var ErrInjectedStorage = errors.New("injected storage failure")

// FailingStorage wraps a storage view and fails reads, writes or both on demand.
//
// It exists because the repo had NO storage-fault injection at all — `rg
// failingStorage|errStorage` found nothing — and that absence hid a whole class:
// 229 handler sites return a bare `return nil, err`, which OpenBao renders as a 500
// with no error_code, contradicting API-002's "on every path" (A7, A31 in
// docs/audit-2026-08-22.md). The error-taxonomy category could not reach those
// branches, because reaching them requires storage to fail.
//
// Raft quorum loss and a corrupt stored entry are the realistic causes, and both are
// exactly when an operator most needs a machine-readable answer.
type FailingStorage struct {
	logical.Storage

	// FailReads and FailWrites gate the two directions independently: a read
	// failure is what a caller hits mid-request, while a write failure is what an
	// operator hits mid-configuration.
	FailReads  bool
	FailWrites bool
}

func (s *FailingStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	if s.FailReads {
		return nil, ErrInjectedStorage
	}
	return s.Storage.Get(ctx, key)
}

func (s *FailingStorage) List(ctx context.Context, prefix string) ([]string, error) {
	if s.FailReads {
		return nil, ErrInjectedStorage
	}
	return s.Storage.List(ctx, prefix)
}

func (s *FailingStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if s.FailWrites {
		return ErrInjectedStorage
	}
	return s.Storage.Put(ctx, entry)
}

func (s *FailingStorage) Delete(ctx context.Context, key string) error {
	if s.FailWrites {
		return ErrInjectedStorage
	}
	return s.Storage.Delete(ctx, key)
}
