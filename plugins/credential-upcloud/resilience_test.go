package credentialupcloud_test

import (
	"context"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialupcloud "github.com/nicois/openbao-cloud-creds/plugins/credential-upcloud"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func newResilienceHarness(t *testing.T) plugintest.Harness {
	srv := fakes.NewUpCloudServer()
	t.Cleanup(srv.Close)

	configure := func(t *testing.T, b logical.Backend, storage logical.Storage) {
		write := func(path string, data map[string]interface{}) {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
			})
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("%s write failed: err=%v resp=%v", path, err, resp)
			}
		}
		write("config", map[string]interface{}{"username": "testuser", "upcloud_api_url": srv.URL})
		write("minter-sets/default", map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "minter-1", "token": "ucat_v1_test", "never_expires": true},
			},
		})
		write("roles/test-role", map[string]interface{}{
			"default_ttl": 900, "max_ttl": 3600, "scopes": "read,write", "minter_set": "default",
		})
	}

	rewriteWithout := func(t *testing.T, b logical.Backend, storage logical.Storage) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
			Data: map[string]interface{}{
				"minters": []interface{}{
					map[string]interface{}{"id": "minter-2", "token": "ucat_v1_reseeded", "never_expires": true},
				},
			},
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("reseed minter-set failed: err=%v resp=%v", err, resp)
		}
	}

	return plugintest.Harness{
		Factory:                  credentialupcloud.Factory,
		Configure:                configure,
		IssuePath:                "creds/test-role",
		RewriteDefaultSetWithout: rewriteWithout,
		ProvisionedCount:         srv.ProvisionedCount,
		ExpectsHardRevoke:        true,
	}
}

func TestResilience_Reload(t *testing.T) {
	plugintest.RunReloadSuite(t, newResilienceHarness(t))
}

func TestResilience_Perturbation(t *testing.T) {
	plugintest.RunPerturbationSuite(t, newResilienceHarness(t))
}

func TestResilience_Revoke(t *testing.T) {
	plugintest.RunRevokeResilienceSuite(t, newResilienceHarness(t))
}
