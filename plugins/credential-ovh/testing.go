package credentialovh

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// SetTokenClientFactory injects a custom token client factory into the backend.
// This is used by tests to inject fake clients.
func SetTokenClientFactory(b logical.Backend, fn TokenClientFactory) {
	ovhBackend := b.(*backend)
	ovhBackend.mu.Lock()
	defer ovhBackend.mu.Unlock()
	ovhBackend.tokenClientFn = fn
}

// MintTokenFunc is the signature for a fake MintToken implementation.
type MintTokenFunc func(ctx context.Context) (string, int, error)

// TestConnectionFunc is the signature for a fake TestConnection implementation.
type TestConnectionFunc func(ctx context.Context) error

// NewFakeTokenClient creates a fake token client for testing.
func NewFakeTokenClient(mintFn MintTokenFunc, testConnFn TestConnectionFunc) TokenClient {
	return &fakeTokenClient{
		mintTokenFunc:      mintFn,
		testConnectionFunc: testConnFn,
	}
}

// WorkersRunning reports whether this backend's background workers are running.
//
// Exported as a test seam so the shared conformance suite can assert what KI-007
// was actually about. Its guard asserted only that Initialize returned nil twice
// and that issuance then worked — but framework.Backend.Initialize returns nil
// when InitializeFunc is unset, and issuance never needed a worker, so deleting
// InitializeFunc from all ten plugins left the category green (A11 in
// docs/audit-2026-08-22.md). Workers are the only thing that recovers a minter
// from AuthFailing, so "no workers" is not a telemetry gap; it wedges a minter
// permanently.
func WorkersRunning(b logical.Backend) bool {
	backend, ok := b.(*backend)
	if !ok {
		return false
	}
	// workerMgr is guarded by workerLifecycleMu: startWorkers replaces it and
	// stopWorkersLocked clears it, both from a goroutine Initialize spawns. Reading
	// it unlocked is a data race, and the race detector says so.
	backend.workerLifecycleMu.Lock()
	defer backend.workerLifecycleMu.Unlock()
	if backend.workerMgr == nil {
		return false
	}
	return backend.workerMgr.Running()
}
