package plugintest

import (
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
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
	t.Run("EnvelopeShapeIsTheDeclaredShape", func(t *testing.T) { assertEnvelopeShape(t, h) })
	t.Run("EnvelopeAgreesWithLease", func(t *testing.T) { assertEnvelopeAgreesWithLease(t, h) })
	t.Run("RenewMatchesWhatTheLeaseAdvertises", func(t *testing.T) { assertRenewMatchesLease(t, h) })
	t.Run("InternalDataSurvivesRPC", func(t *testing.T) { assertInternalDataSurvivesRPC(t, h) })
	t.Run("SecretTypeAndInternalDataKeysAreTheDeclaredOnes", func(t *testing.T) {
		assertLeaseIdentifiersAreDeclared(t, h)
	})
	t.Run("CredentialBlockIsTheDeclaredShape", func(t *testing.T) { assertCredentialBlock(t, h) })
	t.Run("ScopeKindIsFromTheClosedVocabulary", func(t *testing.T) { assertScopeKind(t, h) })
}

// assertCredentialBlock pins the part of the payload a client actually consumes.
//
// The `credential` block was documented for six of ten clouds and asserted for none,
// and the cost of that showed up as a plain bug: Exoscale's create returns `key` AND
// `secret`, the client struct had no secret field, so the signing half was decoded
// away and callers got a credential they could not use. The fake hid it by returning
// a secret-shaped value in `key` (A28).
//
// Exact, not "at least": an extra key is as much a contract change as a missing one,
// and on this payload an unexpected extra key is a credential fragment nobody meant
// to publish.
func assertCredentialBlock(t *testing.T, h Harness) {
	t.Helper()
	if len(h.CredentialKeys) == 0 {
		t.Fatalf("%s: the harness declares no CredentialKeys, so the one part of the envelope a "+
			"client consumes is unspecified", h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}
	credential, ok := resp.Data["credential"].(map[string]interface{})
	if !ok {
		t.Fatalf("envelope credential is %T, want an object", resp.Data["credential"])
	}

	allowed := make(map[string]bool, len(h.CredentialKeys)+len(h.OptionalCredentialKeys))
	for _, key := range h.CredentialKeys {
		allowed[key] = true
		value, present := credential[key]
		if !present {
			t.Errorf("credential has no %q; a client that follows the documented shape cannot use "+
				"this credential. Present: %v", key, keysOf(credential))
			continue
		}
		if str, ok := value.(string); ok && str == "" {
			t.Errorf("credential[%q] is empty, which for a credential field means the caller was "+
				"handed an unusable credential rather than an error", key)
		}
	}
	for _, key := range h.OptionalCredentialKeys {
		allowed[key] = true
	}
	for key := range credential {
		if !allowed[key] {
			t.Errorf("credential carries an undeclared key %q. The credential block is the payload a "+
				"client consumes, so an undeclared key is either an unspecified contract or a "+
				"credential fragment nobody meant to publish", key)
		}
	}
}

// assertScopeKind: a client must be able to read metadata.scope without knowing
// which cloud it is talking to, which means scope_kind has to be present and from
// the closed vocabulary — and empty scope is only legitimate for the kind that says
// the cloud has no per-credential boundary at all (A28).
func assertScopeKind(t *testing.T, h Harness) {
	t.Helper()
	if h.ScopeKind == "" {
		t.Fatalf("%s: the harness declares no ScopeKind", h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}
	metadata, ok := resp.Data["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("envelope metadata is %T, want an object", resp.Data["metadata"])
	}

	kind, _ := metadata["scope_kind"].(string)
	if kind != h.ScopeKind {
		t.Fatalf("metadata.scope_kind is %q, declared %q", kind, h.ScopeKind)
	}
	if !credenvelope.ValidScopeKind(credenvelope.ScopeKind(kind)) {
		t.Fatalf("scope_kind %q is not in the closed vocabulary %v: a client switching on it cannot "+
			"know what to do", kind, credenvelope.AllScopeKinds())
	}

	scope, _ := metadata["scope"].(string)
	accountWide := credenvelope.ScopeKind(kind) == credenvelope.ScopeKindAccount
	switch {
	case accountWide && scope != "":
		t.Errorf("scope_kind is %q — the cloud offers no per-credential narrowing — but scope is %q. "+
			"Reporting a boundary that does not exist is the failure UpCloud's `scopes` field was",
			kind, scope)
	case !accountWide && scope == "":
		t.Errorf("scope_kind is %q but scope is empty, so a client is told there IS a boundary and "+
			"not what it is", kind)
	}
}

// assertLeaseIdentifiersAreDeclared pins the two strings an upgrade can rename
// without any other test noticing, and whose rename silently orphans every live
// lease (A30).
//
// framework.Secret.Type is how core routes a revoke back to a callback: rename it
// and every lease issued by the old binary revokes to nothing, so its upstream
// credential lives on with the lease gone. An internal_data key is how revoke finds
// the credential to delete: rename it and revoke cannot identify what to revoke —
// which, before this batch, also meant retrying forever.
//
// Both are declared in the conformance registry rather than inferred here, so the
// test states a contract instead of restating whatever the code happens to do.
func assertLeaseIdentifiersAreDeclared(t *testing.T, h Harness) {
	t.Helper()
	if h.SecretType == "" || len(h.LeaseInternalDataKeys) == 0 {
		t.Fatalf("%s: the harness declares no SecretType/LeaseInternalDataKeys, so a rename of "+
			"either would go unnoticed. Both are part of this cloud's lease contract", h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil || resp == nil || resp.IsError() || resp.Secret == nil {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	if resp.Secret.TTL <= 0 {
		t.Errorf("issued lease has a non-positive TTL (%s)", resp.Secret.TTL)
	}
	if got := resp.Secret.InternalData["secret_type"]; got != nil && got != h.SecretType {
		t.Errorf("internal_data secret_type is %v, declared %q", got, h.SecretType)
	}
	for _, key := range h.LeaseInternalDataKeys {
		value, present := resp.Secret.InternalData[key]
		if !present {
			t.Errorf("issued lease has no internal_data[%q]; revoke reads it, so its absence means a "+
				"credential nothing can revoke. Present keys: %v", key, keysOf(resp.Secret.InternalData))
			continue
		}
		if str, ok := value.(string); ok && str == "" {
			t.Errorf("issued lease has an empty internal_data[%q]", key)
		}
	}
}

func keysOf(data map[string]interface{}) []string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// assertEnvelopeShape checks the success side of the response contract, which is
// the counterpart to the error-taxonomy category's check on the failure side.
//
// Every plugin builds its issuance response through credenvelope.NewEnvelope and
// serialises it with ToMap, so the shape is centralised by construction — but
// nothing *enforced* that, and a hand-built Data map would have been as invisible
// in review as the 166 code-less error responses were. So the assertion compares
// against a reference envelope built by the same constructor rather than against a
// hard-coded key list: the reference cannot drift from ToMap, and an added or
// dropped field fails here for all ten plugins at once. An EXTRA key fails too — a
// client pinning api_version 2 is entitled to be told when the shape grows.
func assertEnvelopeShape(t *testing.T, h Harness) {
	t.Helper()
	b, storage := newConfiguredBackend(t, h)
	resp := mustIssue(t, b, storage, h.IssuePath)

	reference := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{}).ToMap()
	assertSameKeys(t, "envelope", reference, resp.Data)

	refMeta, ok := reference["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("reference envelope metadata is %T, want map", reference["metadata"])
	}
	gotMeta, ok := resp.Data["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("envelope metadata is %T, want map[string]interface{} — clients read "+
			"api_version out of it", resp.Data["metadata"])
	}
	assertSameKeys(t, "envelope metadata", refMeta, gotMeta)

	if version, _ := gotMeta["api_version"].(string); version != credenvelope.APIVersion {
		t.Errorf("envelope api_version is %q, want %q: this is the field clients pin to, and an "+
			"empty one means the response was built without NewEnvelope", version, credenvelope.APIVersion)
	}
}

// assertSameKeys compares two maps by key set only, in both directions.
func assertSameKeys(t *testing.T, what string, want, got map[string]interface{}) {
	t.Helper()
	for key := range want {
		if _, present := got[key]; !present {
			t.Errorf("%s is missing key %q, which credenvelope.ToMap always writes", what, key)
		}
	}
	for key := range got {
		if _, expected := want[key]; !expected {
			t.Errorf("%s carries an extra key %q that credenvelope.ToMap does not write: the "+
				"envelope shape is versioned by api_version, so growing it silently breaks the "+
				"contract clients pin to", what, key)
		}
	}
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
	renewResp, renewErr := b.HandleRequest(t.Context(), &logical.Request{
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
