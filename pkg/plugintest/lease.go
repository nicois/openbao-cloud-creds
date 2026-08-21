package plugintest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// leaseSlack is how far the envelope's expires_at may sit from now+ttl_seconds.
// Minting takes some wall-clock, and some clouds echo their own expiry back, so
// an exact match is not the contract; agreement to within a minute is.
const leaseSlack = time.Minute

// RunLeaseContractSuite verifies the agreement between what the response
// envelope promises a client and what the lease OpenBao creates actually says.
// These are two separate structures built in the same handler, so nothing but a
// test keeps them honest, and a client that reads one while core acts on the
// other is the failure mode.
//
// The renewability assertion is the load-bearing one (KI-008): OpenBao REVOKES a
// lease whose renewal fails, so a lease that advertises renewable=true while
// renewal cannot work does not merely inconvenience a client — the renew attempt
// destroys the credential. framework.Secret.Renewable() is (Renew != nil), so a
// Renew callback that always returns an error still advertises renewable=true;
// the only correct way to say "not renewable" is to register no callback.
func RunLeaseContractSuite(t *testing.T, h Harness) {
	t.Run("EnvelopeAgreesWithLease", func(t *testing.T) { assertEnvelopeAgreesWithLease(t, h) })
	t.Run("RenewMatchesWhatTheLeaseAdvertises", func(t *testing.T) { assertRenewMatchesLease(t, h) })
	t.Run("InternalDataSurvivesRPC", func(t *testing.T) { assertInternalDataSurvivesRPC(t, h) })
}

func assertEnvelopeAgreesWithLease(t *testing.T, h Harness) {
	t.Helper()
	b, storage := newConfiguredBackend(t, h)
	resp := mustIssue(t, b, storage, h.IssuePath)
	if resp.Secret == nil {
		t.Fatal("issue returned no secret/lease")
	}

	renewable, ok := resp.Data["renewable"].(bool)
	if !ok {
		t.Fatalf("envelope renewable is %T, want bool", resp.Data["renewable"])
	}
	if renewable != resp.Secret.Renewable {
		t.Errorf("envelope says renewable=%v but the lease says %v: OpenBao revokes a "+
			"lease whose renewal fails, so this disagreement can cost a client its "+
			"credential (docs/ttl-semantics.md)", renewable, resp.Secret.Renewable)
	}

	ttl, ok := resp.Data["ttl_seconds"].(int)
	if !ok {
		t.Fatalf("envelope ttl_seconds is %T, want int", resp.Data["ttl_seconds"])
	}
	if got := int(resp.Secret.TTL.Seconds()); got != ttl {
		t.Errorf("lease TTL is %ds but the envelope promises %ds: the lease is what core "+
			"expires on, so a shorter lease revokes early and a longer one outlives the "+
			"credential", got, ttl)
	}

	assertExpiresAt(t, resp.Data, ttl)
}

// assertExpiresAt checks the envelope's own expiry field against its TTL — the
// field a client schedules its refresh from, which is not the lease.
func assertExpiresAt(t *testing.T, data map[string]interface{}, ttl int) {
	t.Helper()
	expiresAt, err := time.Parse(time.RFC3339, str(t, data, "expires_at"))
	if err != nil {
		t.Fatalf("envelope expires_at is not RFC3339: %v", err)
	}
	want := time.Now().Add(time.Duration(ttl) * time.Second)
	if expiresAt.Sub(want).Abs() > leaseSlack {
		t.Errorf("envelope expires_at %s is not now+%ds (%s): a client scheduling its own "+
			"refresh reads this field, not the lease", expiresAt, ttl, want)
	}
}

func assertRenewMatchesLease(t *testing.T, h Harness) {
	t.Helper()
	b, storage := newConfiguredBackend(t, h)
	resp := mustIssue(t, b, storage, h.IssuePath)
	renewResp, renewErr := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Path:      h.IssuePath,
		Storage:   storage,
		Secret:    resp.Secret,
	})
	if resp.Secret.Renewable {
		if renewErr != nil || (renewResp != nil && renewResp.IsError()) {
			t.Fatalf("lease advertises renewable=true but renewal failed: err=%v resp=%v",
				renewErr, renewResp)
		}
		return
	}
	// Non-renewable: the framework must refuse before any plugin code runs, which
	// is only true when the secret registers no Renew callback.
	if !errors.Is(renewErr, logical.ErrUnsupportedOperation) {
		t.Fatalf("lease advertises renewable=false but renewal was handled (err=%v resp=%v): "+
			"the secret must declare no Renew callback", renewErr, renewResp)
	}
}

// assertInternalDataSurvivesRPC checks the lease's internal_data through a JSON
// round trip: it crosses the plugin's RPC boundary as JSON before revoke ever
// sees it, so a value that does not survive wedges revocation in production while
// passing every in-process test that skips the encode.
func assertInternalDataSurvivesRPC(t *testing.T, h Harness) {
	t.Helper()
	b, storage := newConfiguredBackend(t, h)
	resp := mustIssue(t, b, storage, h.IssuePath)

	raw, err := json.Marshal(resp.Secret.InternalData)
	if err != nil {
		t.Fatalf("internal_data is not JSON-encodable, so revoke could never read it: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("internal_data does not decode: %v", err)
	}
	if decoded["secret_type"] == nil || decoded["secret_type"] == "" {
		t.Errorf("internal_data lost secret_type across JSON, so core could not route "+
			"revoke: %v", decoded)
	}
	for key, want := range resp.Secret.InternalData {
		got, present := decoded[key]
		if !present {
			t.Errorf("internal_data key %q vanished across JSON", key)
			continue
		}
		// Numbers legitimately change Go type (float64) across JSON; strings must
		// be identical, since that is what revoke looks entities up by.
		if s, isString := want.(string); isString && got != s {
			t.Errorf("internal_data[%q] changed across JSON: %v -> %v", key, want, got)
		}
	}
}

// mustIssue reads the issuance path and fails on anything but a credential.
func mustIssue(t *testing.T, b logical.Backend, storage logical.Storage, path string) *logical.Response {
	t.Helper()
	resp, err := issue(t, b, storage, path)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}
	return resp
}

// str reads a string field out of a response, failing with the field name rather
// than panicking on a type assertion.
func str(t *testing.T, data map[string]interface{}, key string) string {
	t.Helper()
	value, ok := data[key].(string)
	if !ok {
		t.Fatalf("field %q is %T, want string", key, data[key])
	}
	return value
}
