package credentialaws_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialaws "github.com/nicois/openbao-cloud-creds/plugins/credential-aws"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// countingSTSClient wraps a fake STSClient and counts how many AssumeRole
// credentials it has minted. This is the AWS analogue of the DO fake's
// ProvisionedCount: there is no HTTP server to inspect, so we count in-process.
type countingSTSClient struct {
	credentialaws.STSClient
	counter *int64
}

func (c *countingSTSClient) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	out, err := c.STSClient.AssumeRole(ctx, params, optFns...)
	if err == nil {
		atomic.AddInt64(c.counter, 1)
	}
	return out, err
}

// newResilienceHarness builds the AWS resilience harness.
//
// AWS differs from the JIT clouds (e.g. DigitalOcean) in two load-bearing ways:
//
//  1. There is no HTTP fake. The fake is an in-process STSClient injected into a
//     specific *backend instance via SetSTSClientFactory. There is no
//     package-level/global factory and no countable HTTP server, so for
//     ProvisionedCount we wire a counter that the injected factory increments
//     each time it mints AssumeRole credentials (i.e. each successful issue).
//
//  2. Revoke is a no-op: STS credentials expire naturally and have no upstream
//     entity to delete, so ExpectsHardRevoke is false.
//
// Reload-injection case: (c) — strictly per-backend injection, no global, no
// HTTP fake. plugintest.ReloadBackend calls Factory directly with no
// SetSTSClientFactory, so the reloaded backend's stsClientFn is nil and
// buildSTSClient falls back to newRealSTSClient pointing at the real STS
// endpoint. The harness has no hook to inject the fake into the reloaded
// backend before issuance, so the Reload category cannot be exercised here and
// TestResilience_Reload is skipped with an explanation.
func newResilienceHarness(t *testing.T) plugintest.Harness {
	var minted int64

	configure := func(t *testing.T, b logical.Backend, storage logical.Storage) {
		// Inject a counting fake STS client into THIS backend instance. The
		// counter is shared with ProvisionedCount below.
		credentialaws.SetSTSClientFactory(b, func(accessKeyID, secretAccessKey, region, endpoint string) credentialaws.STSClient {
			inner := credentialaws.NewFakeSTSClient(nil, nil)
			return &countingSTSClient{STSClient: inner, counter: &minted}
		})

		write := func(path string, data map[string]interface{}) {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
			})
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("%s write failed: err=%v resp=%v", path, err, resp)
			}
		}
		write("config", map[string]interface{}{"region": "us-east-1", "sts_endpoint": ""})
		write("minter-sets/default", map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":                "minter-1",
					"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					"never_expires":     true,
				},
			},
		})
		write("roles/test-role", map[string]interface{}{
			"default_ttl":  900,
			"max_ttl":      3600,
			"iam_role_arn": "arn:aws:iam::123456789012:role/test",
			"minter_set":   "default",
		})
	}

	rewriteWithout := func(t *testing.T, b logical.Backend, storage logical.Storage) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
			Data: map[string]interface{}{
				"minters": []interface{}{
					map[string]interface{}{
						"id":                "minter-2",
						"access_key_id":     "AKIARESEEDEDKEY00000",
						"secret_access_key": "reseededSecretAccessKey1234567890abcdef",
						"never_expires":     true,
					},
				},
			},
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("reseed minter-set failed: err=%v resp=%v", err, resp)
		}
	}

	return plugintest.Harness{
		Factory:                  credentialaws.Factory,
		Configure:                configure,
		IssuePath:                "creds/test-role",
		RewriteDefaultSetWithout: rewriteWithout,
		ProvisionedCount:         func() int { return int(atomic.LoadInt64(&minted)) },
		ExpectsHardRevoke:        false,
	}
}

func TestResilience_Reload(t *testing.T) {
	t.Skip("AWS uses strictly per-backend STS client injection (SetSTSClientFactory " +
		"on the *backend instance) with no package-level factory and no HTTP fake. " +
		"plugintest.ReloadBackend re-runs Factory without re-injecting, so the " +
		"reloaded backend would hit the real STS endpoint. The harness has no hook " +
		"to inject the fake into the reloaded backend, so the Reload category cannot " +
		"be exercised for AWS through this harness (reload-injection case c).")
}

func TestResilience_Perturbation(t *testing.T) {
	h := newResilienceHarness(t)
	plugintest.RunPerturbationSuite(t, h)
}

func TestResilience_Revoke(t *testing.T) {
	h := newResilienceHarness(t)
	plugintest.RunRevokeResilienceSuite(t, h)
}
