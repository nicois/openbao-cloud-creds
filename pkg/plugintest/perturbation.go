package plugintest

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// RunPerturbationSuite verifies that mutating the minter set after a lease is
// issued does not wedge revocation. Catches KI-002.
func RunPerturbationSuite(t *testing.T, h Harness) {
	t.Run("RevokeAfterIssuingMinterRemoved", func(t *testing.T) {
		b, storage := newConfiguredBackend(t, h)
		resp, err := issue(t, b, storage, h.IssuePath)
		if err != nil || resp == nil || resp.IsError() {
			t.Fatalf("initial issue failed: err=%v resp=%v", err, resp)
		}
		secret := resp.Secret
		if secret == nil {
			t.Fatal("issue returned no secret/lease")
		}
		h.RewriteDefaultSetWithout(t, b, storage)
		revResp, revErr := b.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.RevokeOperation,
			Path:      h.IssuePath,
			Storage:   storage,
			Secret:    secret,
		})
		if revErr != nil {
			t.Fatalf("revoke after minter removal errored (KI-002): %v", revErr)
		}
		if revResp != nil && revResp.IsError() {
			t.Fatalf("revoke after minter removal returned error response (KI-002): %v", revResp)
		}
	})
}
