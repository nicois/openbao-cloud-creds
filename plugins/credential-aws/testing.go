package credentialaws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// SetSTSClientFactory injects a custom STS client factory into the backend.
// This is used by tests to inject fake clients.
func SetSTSClientFactory(b logical.Backend, fn STSClientFactory) {
	awsBackend := b.(*backend)
	awsBackend.mu.Lock()
	defer awsBackend.mu.Unlock()
	awsBackend.stsClientFn = fn
}

// SetIAMMinterClientFactory injects a custom IAM minter-client factory into the
// backend. Used by tests to inject a fake key-management client (mirrors
// SetSTSClientFactory).
func SetIAMMinterClientFactory(b logical.Backend, fn IAMMinterClientFactory) {
	awsBackend := b.(*backend)
	awsBackend.mu.Lock()
	defer awsBackend.mu.Unlock()
	awsBackend.iamMinterClientFn = fn
}

// AssumeRoleFunc is the signature for a fake AssumeRole implementation.
type AssumeRoleFunc func(ctx context.Context, params *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)

// GetCallerIdentityFunc is the signature for a fake GetCallerIdentity implementation.
type GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)

// NewFakeSTSClient creates a fake STS client for testing.
func NewFakeSTSClient(assumeRoleFn AssumeRoleFunc, getCallerIdentityFn GetCallerIdentityFunc) STSClient {
	return &fakeSTSClient{
		assumeRoleFunc:        assumeRoleFn,
		getCallerIdentityFunc: getCallerIdentityFn,
	}
}

// NewSwitchableSTSClient returns a fake STS client whose AssumeRole fails with
// AccessDenied whenever deny() reports true, while GetCallerIdentity — the health
// check, which AWS permits with no policy at all — keeps succeeding. That is the
// "authenticates but cannot mint" shape the cloud-agnostic conformance suite
// needs; deny is consulted per call, so the switch can be flipped between
// requests. It lives here rather than in the caller so the STS request types stay
// inside this module.
func NewSwitchableSTSClient(deny func() bool, onMint func()) STSClient {
	return NewFakeSTSClient(func(ctx context.Context, params *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
		if onMint != nil {
			onMint()
		}
		if deny != nil && deny() {
			return nil, fmt.Errorf("AccessDenied: this access key is not authorized to perform: sts:AssumeRole")
		}
		return NewFakeSTSClient(nil, nil).AssumeRole(ctx, params)
	}, nil)
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
