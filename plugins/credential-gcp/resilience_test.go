package credentialgcp_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialgcp "github.com/nicois/openbao-cloud-creds/plugins/credential-gcp"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// countingIAMClient wraps a fake IAMCredentialsClient and counts how many access
// tokens it has minted. This is the GCP analogue of the DO fake's
// ProvisionedCount: there is no HTTP server to inspect, so we count in-process.
type countingIAMClient struct {
	credentialgcp.IAMCredentialsClient
	counter *int64
}

func (c *countingIAMClient) GenerateAccessToken(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (string, time.Time, error) {
	token, expiry, err := c.IAMCredentialsClient.GenerateAccessToken(ctx, serviceAccount, scopes, lifetime)
	if err == nil {
		atomic.AddInt64(c.counter, 1)
	}
	return token, expiry, err
}

// newResilienceHarness builds the GCP resilience harness.
//
// GCP differs from the JIT clouds (e.g. DigitalOcean) in two load-bearing ways,
// exactly mirroring AWS:
//
//  1. There is no HTTP fake. The fake is an in-process IAMCredentialsClient
//     injected into a specific *backend instance via SetIAMClientFactory. There
//     is no package-level/global factory and no countable HTTP server, so for
//     ProvisionedCount we wire a counter that the injected factory increments
//     each time it mints an access token (i.e. each successful issue).
//
//  2. Revoke is a no-op: impersonation access tokens expire naturally and have
//     no upstream entity to delete, so ExpectsHardRevoke is false.
//
// Reload-injection case: (c) — strictly per-backend injection, no global, no
// HTTP fake. plugintest.ReloadBackend calls Factory directly with no
// SetIAMClientFactory, so the reloaded backend's iamClientFn is nil and
// buildIAMClient falls back to newRealIAMClient pointing at the real GCP IAM
// Credentials endpoint. The harness has no hook to inject the fake into the
// reloaded backend before issuance, so the Reload category cannot be exercised
// here and TestResilience_Reload is skipped with an explanation.
func newResilienceHarness() plugintest.Harness {
	var minted int64

	configure := func(t *testing.T, b logical.Backend, storage logical.Storage) {
		// Inject a counting fake IAM client into THIS backend instance. The
		// counter is shared with ProvisionedCount below.
		credentialgcp.SetIAMClientFactory(b, func(credentialsJSON string) credentialgcp.IAMCredentialsClient {
			inner := credentialgcp.NewFakeIAMClient(nil, nil)
			return &countingIAMClient{IAMCredentialsClient: inner, counter: &minted}
		})

		write := func(path string, data map[string]interface{}) {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
			})
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("%s write failed: err=%v resp=%v", path, err, resp)
			}
		}
		write("config", map[string]interface{}{"project": "test-project"})
		write("minter-sets/default", map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":               "minter-1",
					"credentials_json": testCredentialsJSON,
					"never_expires":    true,
				},
			},
		})
		write("roles/test-role", map[string]interface{}{
			"default_ttl":           900,
			"max_ttl":               3600,
			"service_account_email": "target-sa@test-project.iam.gserviceaccount.com",
			"minter_set":            "default",
		})
	}

	rewriteWithout := func(t *testing.T, b logical.Backend, storage logical.Storage) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
			Data: map[string]interface{}{
				"minters": []interface{}{
					map[string]interface{}{
						"id":               "minter-2",
						"credentials_json": testCredentialsJSON,
						"never_expires":    true,
					},
				},
			},
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("reseed minter-set failed: err=%v resp=%v", err, resp)
		}
	}

	return plugintest.Harness{
		Factory:                  credentialgcp.Factory,
		Configure:                configure,
		IssuePath:                "creds/test-role",
		RewriteDefaultSetWithout: rewriteWithout,
		ProvisionedCount:         func() int { return int(atomic.LoadInt64(&minted)) },
		ExpectsHardRevoke:        false,
	}
}

func TestResilience_Reload(t *testing.T) {
	t.Skip("GCP uses strictly per-backend IAM client injection (SetIAMClientFactory " +
		"on the *backend instance) with no package-level factory and no HTTP fake. " +
		"plugintest.ReloadBackend re-runs Factory without re-injecting, so the " +
		"reloaded backend would hit the real GCP IAM Credentials endpoint. The harness " +
		"has no hook to inject the fake into the reloaded backend, so the Reload " +
		"category cannot be exercised for GCP through this harness (reload-injection case c).")
}

func TestResilience_Perturbation(t *testing.T) {
	plugintest.RunPerturbationSuite(t, newResilienceHarness())
}

func TestResilience_Revoke(t *testing.T) {
	plugintest.RunRevokeResilienceSuite(t, newResilienceHarness())
}
