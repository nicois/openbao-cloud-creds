package credentialgcp

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// SetIAMClientFactory injects a custom IAM client factory into the backend.
// This is used by tests to inject fake clients.
func SetIAMClientFactory(b logical.Backend, fn IAMClientFactory) {
	gcpBackend := b.(*backend)
	gcpBackend.mu.Lock()
	defer gcpBackend.mu.Unlock()
	gcpBackend.iamClientFn = fn
}

// SetSAKeyClientFactory injects a custom service-account key-management client
// factory into the backend. Used by tests to inject a fake key-management client
// (mirrors SetIAMClientFactory).
func SetSAKeyClientFactory(b logical.Backend, fn SAKeyClientFactory) {
	gcpBackend := b.(*backend)
	gcpBackend.mu.Lock()
	defer gcpBackend.mu.Unlock()
	gcpBackend.saKeyClientFn = fn
}

// GenerateAccessTokenFunc is the signature for a fake GenerateAccessToken implementation.
type GenerateAccessTokenFunc func(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (string, time.Time, error)

// TestConnectionFunc is the signature for a fake TestConnection implementation.
type TestConnectionFunc func(ctx context.Context) error

// NewFakeIAMClient creates a fake IAM Credentials client for testing.
func NewFakeIAMClient(generateFn GenerateAccessTokenFunc, testConnFn TestConnectionFunc) IAMCredentialsClient {
	return &fakeIAMClient{
		generateAccessTokenFunc: generateFn,
		testConnectionFunc:      testConnFn,
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
