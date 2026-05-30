package credentialoci_test

import (
	"context"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialoci "github.com/nicois/openbao-cloud-creds/plugins/credential-oci"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// tokenCounter is satisfied by the in-memory fake OCI client (*fakeOCIClient),
// whose TokenCount() method is exported even though the concrete type is not.
// We type-assert against this interface so ProvisionedCount can report how many
// slot credentials the fake currently holds.
type tokenCounter interface {
	TokenCount() int
}

// newResilienceHarness builds the OCI resilience harness.
//
// OCI is the phased-rotation outlier and differs from both the JIT clouds
// (DigitalOcean) and the native clouds (AWS/STS) in three load-bearing ways:
//
//  1. Issuance reads a PRE-PROVISIONED SLOT. There is no per-read cloud call —
//     credentials are minted at role-write time when the plugin initializes the
//     role's slots via the bound minter set. So Configure must write a role
//     (which provisions slots) before any issue can succeed.
//
//  2. Revoke is SOFT: pathCredsRevoke is a no-op that forgets the lease; the
//     slot credential lives until its next rotation and the missing minter is
//     never contacted. So ExpectsHardRevoke is false, the Perturbation suite
//     (revoke after the issuing minter is removed) passes trivially, and the
//     DoubleRevoke suite passes.
//
//  3. The cloud client is an INJECTED in-process fake (OCIIAMClient registered
//     via SetClientFactory / TestSetClient), not an HTTP fake. There is no
//     package-level factory and no countable HTTP server, so ProvisionedCount
//     reads the fake's TokenCount() and the fake is injected into THIS backend
//     instance only.
//
// Reload-injection case: (c) — strictly per-backend client injection, no global,
// no HTTP fake. plugintest.ReloadBackend re-runs Factory without re-injecting,
// so the reloaded backend's clientFactory is nil and newOCIClient falls back to
// newSigningOCIClient, whose methods return "not implemented" in this build. The
// harness has no hook to inject the fake into the reloaded backend before
// issuance, so the Reload category cannot be exercised for OCI through this
// harness and TestResilience_Reload is skipped (same rationale as AWS/GCP).
func newResilienceHarness() plugintest.Harness {
	fake := credentialoci.NewTestFakeClient()

	configure := func(t *testing.T, b logical.Backend, storage logical.Storage) {
		// Inject the in-memory fake into THIS backend instance so slot
		// provisioning (on role write) and rotation route through it.
		credentialoci.TestSetClient(b, fake)

		write := func(path string, data map[string]interface{}) {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
			})
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("%s write failed: err=%v resp=%v", path, err, resp)
			}
		}
		write("config", map[string]interface{}{
			"region":                  "us-ashburn-1",
			"rotation_check_interval": 60,
		})
		write("minter-sets/default", map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":            "minter-1",
					"token":         "tenancy:user:fingerprint:key",
					"never_expires": true,
				},
			},
		})
		// Writing the role provisions slot_count credentials via the bound set's
		// minter (through the injected fake), so creds reads return a credential.
		write("roles/test-role", map[string]interface{}{
			"user_ocid":       "ocid1.user.oc1..testuser",
			"slot_count":      2,
			"rotation_period": 604800,
			"default_ttl":     302400,
			"max_ttl":         604800,
			"minter_set":      "default",
		})
	}

	rewriteWithout := func(t *testing.T, b logical.Backend, storage logical.Storage) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
			Data: map[string]interface{}{
				"minters": []interface{}{
					map[string]interface{}{
						"id":            "minter-2",
						"token":         "reseeded-tenancy:user:fingerprint:key",
						"never_expires": true,
					},
				},
			},
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("reseed minter-set failed: err=%v resp=%v", err, resp)
		}
	}

	provisionedCount := func() int {
		if c, ok := fake.(tokenCounter); ok {
			return c.TokenCount()
		}
		return 0
	}

	return plugintest.Harness{
		Factory:                  credentialoci.Factory,
		Configure:                configure,
		IssuePath:                "creds/test-role",
		RewriteDefaultSetWithout: rewriteWithout,
		ProvisionedCount:         provisionedCount,
		ExpectsHardRevoke:        false,
	}
}

func TestResilience_Reload(t *testing.T) {
	t.Skip("OCI uses strictly per-backend OCI client injection (TestSetClient / " +
		"SetClientFactory on the *backend instance) with no package-level factory " +
		"and no HTTP fake. plugintest.ReloadBackend re-runs Factory without " +
		"re-injecting, so the reloaded backend falls back to the signing client " +
		"(unimplemented in this build) and cannot provision/read slots. The " +
		"harness has no hook to inject the fake into the reloaded backend, so the " +
		"Reload category cannot be exercised for OCI through this harness " +
		"(reload-injection case c).")
}

func TestResilience_Perturbation(t *testing.T) {
	plugintest.RunPerturbationSuite(t, newResilienceHarness())
}

func TestResilience_Revoke(t *testing.T) {
	plugintest.RunRevokeResilienceSuite(t, newResilienceHarness())
}
