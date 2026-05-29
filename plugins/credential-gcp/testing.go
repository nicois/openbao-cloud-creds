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
