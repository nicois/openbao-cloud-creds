package credentialexoscale_test

import (
	"context"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialexoscale "github.com/nicois/openbao-cloud-creds/plugins/credential-exoscale"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func newResilienceHarness(t *testing.T) (plugintest.Harness, *fakes.ExoscaleServer) {
	srv := fakes.NewExoscaleServer()
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
		write("config", map[string]interface{}{"exoscale_api_url": srv.URL})
		write("minter-sets/default", map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "minter-1", "key": "EXO_test_key_minter1", "never_expires": true},
			},
		})
		write("roles/test-role", map[string]interface{}{
			"default_ttl": 900, "max_ttl": 3600, "role_id": "11111111-1111-1111-1111-111111111111", "minter_set": "default",
		})
	}

	rewriteWithout := func(t *testing.T, b logical.Backend, storage logical.Storage) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
			Data: map[string]interface{}{
				"minters": []interface{}{
					map[string]interface{}{"id": "minter-2", "key": "EXO_reseeded_key", "never_expires": true},
				},
			},
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("reseed minter-set failed: err=%v resp=%v", err, resp)
		}
	}

	return plugintest.Harness{
		Factory:                  credentialexoscale.Factory,
		Configure:                configure,
		IssuePath:                "creds/test-role",
		RewriteDefaultSetWithout: rewriteWithout,
		ProvisionedCount:         srv.ProvisionedCount,
		ExpectsHardRevoke:        true,
	}, srv
}

func TestResilience_Reload(t *testing.T) {
	h, _ := newResilienceHarness(t)
	plugintest.RunReloadSuite(t, h)
}

func TestResilience_Perturbation(t *testing.T) {
	h, _ := newResilienceHarness(t)
	plugintest.RunPerturbationSuite(t, h)
}

func TestResilience_Revoke(t *testing.T) {
	h, _ := newResilienceHarness(t)
	plugintest.RunRevokeResilienceSuite(t, h)
}
