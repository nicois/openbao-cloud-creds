package credentialdo_test

import (
	"testing"

	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestConfigWriteRefusesExfiltratingEndpoint proves the endpoint check is wired
// into the real handler, not merely present in pkg/cloudconfig.
//
// A3: the field is documented "(for testing)" but is persisted and used in
// production, and the minter credential is sent to whatever host it names as
// `Authorization: Bearer`. Config-write privilege — less than any read endpoint
// grants, since none expose a minter secret — was therefore enough to exfiltrate
// every minter in every set.
func TestConfigWriteRefusesExfiltratingEndpoint(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := credentialdo.Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	for _, raw := range []string{"http://attacker.example", "http://169.254.169.254"} {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.UpdateOperation, Path: "config", Storage: config.StorageView,
			Data: map[string]any{"do_api_url": raw},
		})
		if err != nil {
			t.Fatalf("unexpected transport error for %q: %v", raw, err)
		}
		if resp == nil || !resp.IsError() {
			t.Fatalf("config write ACCEPTED %q; the minter credential would be sent there", raw)
		}
		if code, _ := credenvelope.CodeOf(resp.Error().Error()); code != credenvelope.ErrConfigInvalid {
			t.Errorf("rejection of %q carries code %q, want %q", raw, code, credenvelope.ErrConfigInvalid)
		}
	}

	// Loopback must still work, or every HTTP-fake test and the e2e layer break.
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: config.StorageView,
		Data: map[string]any{"do_api_url": "http://127.0.0.1:45231"},
	})
	if err != nil {
		t.Fatalf("loopback endpoint returned a transport error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Errorf("loopback endpoint was refused: %v", resp.Error())
	}
}
