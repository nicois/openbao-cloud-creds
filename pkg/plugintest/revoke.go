package plugintest

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// RunRevokeResilienceSuite verifies revoke is well-behaved: it actually revokes,
// and a double revoke is a clean no-op.
//
// The "actually revokes" half was missing, and its absence was invisible — both
// assertions were `err == nil && !IsError`, so rewriting any hard-revoke callback
// as `return nil, nil` passed on all six hard-revoke clouds (A10 in
// docs/audit-2026-08-22.md). Harness.ProvisionedCount was wired by every harness
// and used by neither suite, while the Harness doc claimed the counts were
// asserted to return to zero.
func RunRevokeResilienceSuite(t *testing.T, h Harness) {
	t.Run("RevokeDeletesTheUpstreamCredential", func(t *testing.T) { assertRevokeDeletesUpstream(t, h) })
	t.Run("DoubleRevokeIsNoOp", func(t *testing.T) { assertDoubleRevokeIsNoOp(t, h) })
	t.Run("RevokeWithUnusableInternalDataReleasesTheLease", func(t *testing.T) {
		assertRevokeWithoutInternalDataReleases(t, h)
	})
}

// assertRevokeWithoutInternalDataReleases: a revoke that cannot possibly succeed
// must fail the lease OPEN, not retry it forever.
//
// OpenBao retries a failed revoke indefinitely, so an error is a promise that a
// later attempt could work. A missing internal_data key is the opposite of that: it
// will be missing on every attempt. Returning an error therefore wedged the lease
// permanently — visible in `bao list sys/leases` for good — while the upstream
// credential it named stayed alive anyway. That is KI-002's wedge reached by a
// different route, and version skew is the route (A30).
//
// The lease is released instead, loudly, because a human has to reclaim a credential
// we can no longer name.
func assertRevokeWithoutInternalDataReleases(t *testing.T, h Harness) {
	t.Helper()
	b, storage := newConfiguredBackend(t, h)
	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil || resp == nil || resp.IsError() || resp.Secret == nil {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	// Strip everything the PLUGIN put there, keeping only the framework's own
	// secret_type — which is how core routes the revoke to a callback at all, so
	// removing it would test the SDK rather than the plugin. What is left is a lease
	// whose every plugin-written key a newer binary renamed.
	stripped := *resp.Secret
	stripped.InternalData = map[string]interface{}{
		"secret_type": resp.Secret.InternalData["secret_type"],
	}

	r, e := revokeSecret(t, b, storage, h.IssuePath, &stripped)
	if e != nil {
		t.Fatalf("revoke with unusable internal_data returned an error (%v), so core will retry it "+
			"forever and the lease never goes away. Nothing about it is retryable", e)
	}
	if r != nil && r.IsError() {
		t.Fatalf("revoke with unusable internal_data returned an error response (%v); same "+
			"consequence as an error", r.Error())
	}
}

// assertRevokeDeletesUpstream is the assertion whose absence made this category
// vacuous on exactly the clouds where revoke is the only bound on a credential.
func assertRevokeDeletesUpstream(t *testing.T, h Harness) {
	t.Helper()
	if !h.ExpectsHardRevoke {
		t.Skipf("%s: credentials expire upstream rather than being deleted, so ProvisionedCount is a "+
			"cumulative mint count and cannot return to zero", h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	before := h.ProvisionedCount()

	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}
	if got := h.ProvisionedCount(); got != before+1 {
		t.Fatalf("upstream count is %d after issuing, want %d: the mint did not reach the cloud, so "+
			"this test cannot tell whether revoke does either", got, before+1)
	}

	if r, e := revokeSecret(t, b, storage, h.IssuePath, resp.Secret); e != nil || (r != nil && r.IsError()) {
		t.Fatalf("revoke failed: err=%v resp=%v", e, r)
	}

	if got := h.ProvisionedCount(); got != before {
		t.Errorf("upstream count is %d after revoke, want %d: the credential is still live on the "+
			"cloud. On this cloud the credential has no upstream expiry, so revoke is the only bound "+
			"on it", got, before)
	}
}

func assertDoubleRevokeIsNoOp(t *testing.T, h Harness) {
	t.Helper()
	b, storage := newConfiguredBackend(t, h)
	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}
	if resp.Secret == nil {
		t.Fatal("issue returned no secret/lease")
	}
	for pass := range 2 {
		r, e := revokeSecret(t, b, storage, h.IssuePath, resp.Secret)
		if e != nil || (r != nil && r.IsError()) {
			t.Fatalf("revoke (pass %d) failed: err=%v resp=%v", pass, e, r)
		}
	}
}

func revokeSecret(t *testing.T, b logical.Backend, storage logical.Storage, path string,
	secret *logical.Secret,
) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      path,
		Storage:   storage,
		Secret:    secret,
	})
}
