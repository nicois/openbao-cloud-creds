package plugintest

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// RunRevokeResilienceSuite verifies revoke is well-behaved under adverse
// conditions: a double revoke must be a clean no-op.
func RunRevokeResilienceSuite(t *testing.T, h Harness) {
	t.Run("DoubleRevokeIsNoOp", func(t *testing.T) {
		b, storage := newConfiguredBackend(t, h)
		resp, err := issue(t, b, storage, h.IssuePath)
		if err != nil || resp == nil || resp.IsError() {
			t.Fatalf("issue failed: err=%v resp=%v", err, resp)
		}
		secret := resp.Secret
		if secret == nil {
			t.Fatal("issue returned no secret/lease")
		}
		revoke := func() (*logical.Response, error) {
			return b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.RevokeOperation,
				Path:      h.IssuePath,
				Storage:   storage,
				Secret:    secret,
			})
		}
		if r, e := revoke(); e != nil || (r != nil && r.IsError()) {
			t.Fatalf("first revoke failed: err=%v resp=%v", e, r)
		}
		if r, e := revoke(); e != nil || (r != nil && r.IsError()) {
			t.Fatalf("second revoke (no-op) failed: err=%v resp=%v", e, r)
		}
	})
}
