package plugintest

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	t.Run("MinterAffinityPinsAClientAndSpreadsTheFleet", func(t *testing.T) {
		assertMinterAffinity(t, h)
	})
	t.Run("EnvelopeShapeIsTheDeclaredShape", func(t *testing.T) { assertEnvelopeShape(t, h) })
	t.Run("EnvelopeAgreesWithLease", func(t *testing.T) { assertEnvelopeAgreesWithLease(t, h) })
	t.Run("RenewMatchesWhatTheLeaseAdvertises", func(t *testing.T) { assertRenewMatchesLease(t, h) })
	t.Run("InternalDataSurvivesRPC", func(t *testing.T) { assertInternalDataSurvivesRPC(t, h) })
	t.Run("SecretTypeAndInternalDataKeysAreTheDeclaredOnes", func(t *testing.T) {
		assertLeaseIdentifiersAreDeclared(t, h)
	})
	t.Run("CredentialBlockIsTheDeclaredShape", func(t *testing.T) { assertCredentialBlock(t, h) })
	t.Run("ScopeKindIsFromTheClosedVocabulary", func(t *testing.T) { assertScopeKind(t, h) })
	t.Run("CredentialKindIsDeclaredAndPinnable", func(t *testing.T) { assertCredentialKind(t, h) })
}

// assertCredentialKind covers the shape contract from both ends: the envelope names
// the shape it is returning, and a client may PIN the shape it can parse.
//
// Pinning is what makes a new credential shape additive instead of breaking. A cloud
// can grow a second shape — AWS SES over SMTP needs `{username, password}` from a
// static key, because SMTP has nowhere to put a session token — and an older client
// keeps working, because it keeps getting the shape it asked for or an error it can
// act on, never a payload it silently misparses (A28 follow-up).
//
// The mismatch case also asserts that NOTHING was minted, which is the property that
// makes the refusal cheap rather than wasteful: the pin is checked before the role is
// loaded, so a caller that cannot parse the answer never causes an upstream mint it
// will then throw away.
func assertCredentialKind(t *testing.T, h Harness) {
	t.Helper()
	if h.CredentialKind == "" {
		t.Fatalf("%s: the harness declares no CredentialKind, so a client has no way to know what "+
			"shape it is parsing except by hard-coding the cloud", h.Cloud)
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
	kind, _ := metadata["credential_kind"].(string)
	if kind != h.CredentialKind {
		t.Fatalf("metadata.credential_kind is %q, declared %q", kind, h.CredentialKind)
	}
	if !credenvelope.ValidCredentialKind(credenvelope.CredentialKind(kind)) {
		t.Fatalf("credential_kind %q is not in the closed vocabulary %v",
			kind, credenvelope.AllCredentialKinds())
	}

	t.Run("MatchingPinIsServed", func(t *testing.T) {
		pinned := issueWithKind(t, b, storage, h.IssuePath, h.CredentialKind)
		if pinned == nil || pinned.IsError() {
			t.Fatalf("a client pinning the shape this role actually serves was refused: %v", pinned)
		}
	})

	t.Run("MismatchedPinIsRefusedWithoutMinting", func(t *testing.T) {
		other := otherKind(h.CredentialKind)
		before := h.ProvisionedCount()

		refused := issueWithKind(t, b, storage, h.IssuePath, other)
		if refused == nil || !refused.IsError() {
			t.Fatalf("a client pinning %q was served this role's %q payload anyway: %v — silently "+
				"handing a client a shape it did not ask for is the failure pinning exists to prevent",
				other, h.CredentialKind, refused)
		}
		if got := refused.Error().Error(); !strings.Contains(got, string(credenvelope.ErrCredentialKindUnsupported)) {
			t.Errorf("the refusal should carry %q so a client that can parse another shape knows to "+
				"ask for it, got: %v", credenvelope.ErrCredentialKindUnsupported, got)
		}
		if after := h.ProvisionedCount(); after != before {
			t.Errorf("upstream count went %d -> %d on a refused pin: a credential was minted for a "+
				"caller that could not have used it", before, after)
		}
	})
}

// otherKind returns any kind from the vocabulary that is not the one given, so the
// mismatch case does not need per-cloud data to know what to ask for wrongly.
func otherKind(kind string) string {
	for _, k := range credenvelope.AllCredentialKinds() {
		if string(k) != kind {
			return string(k)
		}
	}
	return ""
}

func issueWithKind(t *testing.T, b logical.Backend, storage logical.Storage, path, kind string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   storage,
		Data:      map[string]interface{}{"credential_kind": kind},
	})
	if err != nil {
		t.Fatalf("credential read with credential_kind=%q errored: %v", kind, err)
	}
	return resp
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

// assertMinterAffinity: a shard key pins a client to one minter of the set, and different keys
// reach more than one.
//
// This is what makes a minter set a way to multiply an upstream rate limit rather than only to
// survive a failure. The upstream meters per CREDENTIAL, not per account — measured on
// DigitalOcean 2026-09-03: per token, 5000/hour each, and two credentials from ONE account do not
// share a budget. So each minter carries its own budget for the mint, list and revoke calls a
// plugin makes, and a set multiplies ISSUANCE throughput within a single account; it does not
// multiply a client's own throughput, since an issued credential is metered on itself whichever
// minter made it. That only works if a worker's requests land consistently on one minter: random
// selection sprays every client across every budget, so one heavy client degrades all of them and
// exhausting any single minter's budget affects everybody.
//
// Two properties, and both matter:
//
//   - STABILITY. The same key must reach the same minter every time, or a client's consumption is
//     spread across budgets it cannot reason about and the isolation is lost.
//   - SPREAD. Different keys must not all land on one minter, which is what a plugin that ignores
//     the affinity order (or forgets to pass the key) would produce — and it would look perfectly
//     healthy, because a single minter serves every request correctly.
//
// The second is the one worth having in conformance: nine plugins wire this individually, and the
// failure mode of getting it wrong is silence.
func assertMinterAffinity(t *testing.T, h Harness) {
	t.Helper()
	if h.SharesOneCredential {
		t.Skipf("%s serves one credential to every reader, minted once by one minter, so a shard "+
			"key cannot spread anything: there is nothing per-read for affinity to place", h.Cloud)
	}
	if h.WriteSetWithMinters == nil {
		t.Skip("harness declares no WriteSetWithMinters, so affinity cannot be observed: a " +
			"one-minter set serves every key from the same minter whether or not affinity works")
	}

	b, storage := newConfiguredBackend(t, h)
	if resp := h.WriteSetWithMinters(t, b, storage, "minter-1", "minter-2"); resp != nil && resp.IsError() {
		t.Fatalf("writing a two-minter set was refused: %v", resp.Error())
	}

	// Stability: one key, several reads, one minter.
	const stableKey = "worker-a"
	first := minterServing(t, b, storage, h, stableKey)
	for range 4 {
		if again := minterServing(t, b, storage, h, stableKey); again != first {
			t.Errorf("shard key %q was served by %q and then %q; a client's requests must stay on "+
				"one minter, or its consumption is spread across every upstream budget",
				stableKey, first, again)
			break
		}
	}

	// Spread: enough distinct keys that landing on one minter is not chance. With two minters and
	// a sound hash the odds of 20 keys all choosing the same one are 2^-19.
	seen := map[string]int{}
	for i := range 20 {
		seen[minterServing(t, b, storage, h, fmt.Sprintf("worker-%d", i))]++
	}
	if len(seen) < 2 {
		t.Errorf("20 different shard keys were all served by %v. Either the affinity order is "+
			"ignored or the key never reaches selection — and a set that always uses one minter "+
			"multiplies no rate limit, while looking entirely healthy", seen)
	}
	t.Logf("20 keys over 2 minters: %v", seen)
}

// minterServing issues one credential with a shard key and reports which minter the envelope says
// served it. Read from metadata rather than from any internal state: it is what a client sees, and
// what an operator would use to check the spread.
func minterServing(t *testing.T, b logical.Backend, storage logical.Storage, h Harness, shardKey string) string {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      h.IssuePath,
		Storage:   storage,
		Data:      map[string]interface{}{"shard_key": shardKey},
		ID:        "req-" + shardKey,
	})
	if err != nil {
		t.Fatalf("issuing with shard_key=%q failed: %v", shardKey, err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("issuing with shard_key=%q was refused: %v", shardKey, resp)
	}
	metadata, ok := resp.Data["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("the response carries no metadata: %#v", resp.Data)
	}
	minterID, _ := metadata["minter_id"].(string)
	if minterID == "" {
		t.Fatal("metadata.minter_id is empty, so which minter served this is unobservable")
	}
	return minterID
}
