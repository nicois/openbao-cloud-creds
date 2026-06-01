package credentialaws

import (
	"context"

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
