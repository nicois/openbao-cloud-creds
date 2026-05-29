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
