package baotest

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/api/v2"
)

// The end-to-end scenario, once, for every plugin that speaks this project's contract.
//
// # Why it is here rather than in a test file
//
// This started as `e2e/`'s `_test.go` files, which made it unreachable from any other
// module — so a second repository driving the same contract had to re-implement it, and
// a re-implementation is a second opinion about what the contract is. The lab
// repository's first attempt asserted six of the properties below and silently omitted
// the rest, which is the failure mode: a hand-written approximation looks like coverage.
//
// The split is the same one plugintest.Harness draws. What is cloud-agnostic — the
// order of the writes, what the lease must say, what the envelope must carry, that two
// reads differ, that renewal follows the credential's expiry, that revoke is idempotent,
// that a reload can still issue — lives here. What is per-cloud — which config field
// names the endpoint, what a minter looks like, which scopes exist — is the Case a
// caller fills in.
//
// # What only this layer can see
//
// In-process tests share an address space with the plugin and stub OpenBao out, so they
// cannot observe anything owned by the boundary itself: the JSON round-trip of a
// response and of a lease's internal_data, `req.ID` (which only core populates), the
// lease OpenBao actually created, revocation driven by the expiration manager, a query
// parameter surviving the HTTP layer, or a `plugin reload` rebuilding a backend from
// storage alone. Each of those has produced a real defect here.

// Paths inside a mount. Uniform across the plugins by design (CLAUDE.md), so a caller
// needing a different one would be saying something about its cloud rather than about
// its wiring — which is why they are constants and not Case fields.
const (
	ConfigPath = "config"

	// DefaultSetName is the minter set every case writes, and the value asserted back
	// out of the envelope's provenance metadata.
	DefaultSetName = "default"
	SetPath        = "minter-sets/" + DefaultSetName

	// DefaultRoleName is the role every case writes. Also asserted back out of the
	// envelope, so a plugin that echoes a different role name fails here.
	DefaultRoleName = "e2e-role"

	// DefaultMinterID is the single minter's id. Fixed, because every case writes one
	// minter and the envelope must name it.
	DefaultMinterID = "minter-1"
)

// Field names shared by more than one cloud's minter-set or role write.
const (
	FieldMinters      = "minters"
	FieldID           = "id"
	FieldToken        = "token"
	FieldNeverExpires = "never_expires"
	FieldDefaultTTL   = "default_ttl"
	FieldMaxTTL       = "max_ttl"
	FieldScopes       = "scopes"
	FieldMinterSet    = "minter_set"
)

// upstreamPollAttempts and upstreamPollInterval bound how long an upstream count is
// given to settle. Revocation through sys/leases/revoke is synchronous, but the
// plugin's own bookkeeping is not, so a bounded poll beats a sleep.
const (
	upstreamPollAttempts = 40
	upstreamPollInterval = 250 * time.Millisecond
)

// Case is one cloud's translation of the shared scenario: the three configuration
// writes, what the resulting lease must look like, and how to see the upstream side of
// it. It is the e2e analogue of plugintest.Harness — a translation, not a second
// implementation.
type Case struct {
	// Cloud is the plugin's cloud name. Mount and Binary default from it.
	Cloud string

	// Mount defaults to "cloud-creds/<Cloud>", the convention in this project. A
	// separate repository with its own mount naming sets it.
	Mount string

	// Binary is the plugin name registered with OpenBao; it defaults to
	// "credential-<Cloud>" and must match the Plugin.Name given to Start.
	Binary string

	// Config, MinterSet and Role are the three writes, in that order. Config must
	// point the plugin at this case's fake.
	Config    map[string]interface{}
	MinterSet map[string]interface{}
	Role      map[string]interface{}

	// RoleName, SetName and MinterID name what the three writes created. Each
	// defaults to the constant above, and each is asserted back out of the response —
	// a plugin that loses provenance fails here rather than in production.
	RoleName string
	SetName  string
	MinterID string

	// TTLSeconds is the role's default TTL, and therefore the lease duration OpenBao
	// must report. A mismatch means the plugin did not set resp.Secret.TTL, or core
	// clamped it against a mount/system max.
	TTLSeconds int

	// GrantedTTLSeconds is the lease duration to expect when the upstream chooses a
	// lifetime of its own rather than honouring the request. Zero means "the same as
	// TTLSeconds", which is the common case.
	GrantedTTLSeconds int

	// Renewable is the cloud's renewability contract (docs/ttl-semantics.md): false
	// wherever the credential's expiry is fixed at mint. Asserted against the LEASE,
	// which is what a client acts on, and against the envelope's own renewable field,
	// which must agree.
	Renewable bool

	// HardRevoke is true when lease revocation must delete the upstream credential, so
	// the fake's count must fall back.
	HardRevoke bool

	// DeletesIssuedCredentials is true when the cloud can destroy a credential this role
	// has already issued, ahead of whatever expiry it carries — which is what makes
	// roles/<name>/revoke-upstream a real lever rather than a refusal.
	//
	// A SEPARATE fact from HardRevoke, which says a LEASE ENDING deletes one. Every cloud
	// that hard-revokes can also be purged, so the two agree on eight of nine rows and the
	// scenario refuses a Case that claims otherwise. They come apart on a credential SHARED
	// by its readers: one reader's lease must not destroy it, yet an operator containing an
	// incident must still be able to. Reading the purge lever off HardRevoke would have
	// asserted a refusal on exactly the role where the lever works.
	DeletesIssuedCredentials bool

	// SharesOneCredential is true where every reader of the role holds ONE credential that
	// the plugin replaces on its own schedule, rather than one minted per read.
	//
	// It inverts what the scenario expects of a second read — the same credential, and
	// nothing new upstream — so it is stated by the Case rather than measured. A role that
	// regressed from sharing to minting per read, or the other way, then fails here instead
	// of quietly agreeing with whatever it now does.
	SharesOneCredential bool

	// Upstream reports how many credentials the fake currently holds. On clouds whose
	// credentials cannot be revoked it is a monotonic count of mints instead;
	// HardRevoke says which. Nil disables every upstream-count assertion, which is a
	// real loss — a plugin can then leak a credential per issuance undetected.
	Upstream func() int

	// CredentialKind, when set, is the shape this role must serve. Left empty the
	// scenario reads whatever the envelope declares and pins THAT, which still proves
	// the plumbing; setting it also proves the plugin serves the shape intended.
	CredentialKind credenvelope.CredentialKind
}

// withDefaults resolves the fields a caller may leave empty.
func (tc Case) withDefaults() Case {
	if tc.Mount == "" {
		tc.Mount = "cloud-creds/" + tc.Cloud
	}
	if tc.Binary == "" {
		tc.Binary = "credential-" + tc.Cloud
	}
	if tc.RoleName == "" {
		tc.RoleName = DefaultRoleName
	}
	if tc.SetName == "" {
		tc.SetName = DefaultSetName
	}
	if tc.MinterID == "" {
		tc.MinterID = DefaultMinterID
	}
	if tc.GrantedTTLSeconds == 0 {
		tc.GrantedTTLSeconds = tc.TTLSeconds
	}
	return tc
}

// mintsPerRead is how far the upstream count moves on a credential read after the first
// one. Zero where the credential is shared: the first read provisions it and every read
// after that re-serves it, which is the whole reason a fleet can share one.
func (tc Case) mintsPerRead() int {
	if tc.SharesOneCredential {
		return 0
	}
	return 1
}

func (tc Case) rolePath() string  { return tc.Mount + "/roles/" + tc.RoleName }
func (tc Case) issuePath() string { return tc.Mount + "/creds/" + tc.RoleName }
func (tc Case) purgePath() string { return tc.rolePath() + "/revoke-upstream" }

// The revoke-upstream report's keys and modes, spelled out rather than imported from the
// package that produces them: what this layer checks is that a client receives them, and a
// test that reads the keys from the code under test asserts nothing about that.
const (
	purgeKeyTracked  = "tracked"
	purgeKeyDeleted  = "deleted"
	purgeKeyComplete = "complete"
	purgeKeyMode     = "mode"

	purgeModeNormal = "normal"
	purgeModeDryRun = "dry_run"
)

// RunScenario drives one cloud through the whole scenario. Each step is a named helper,
// so a failure names the property that broke rather than a line number.
//
// The mount is enabled and unmounted here, so one live server serves many cases.
func RunScenario(t *testing.T, c *Cluster, tc Case) {
	t.Helper()
	tc = tc.withDefaults()
	if tc.HardRevoke && !tc.DeletesIssuedCredentials {
		t.Fatalf("%s declares HardRevoke without DeletesIssuedCredentials: a lease ending cannot "+
			"delete a credential the cloud will not delete. Declare both, so the purge lever is "+
			"asserted rather than declared unsupported by omission", tc.Cloud)
	}

	c.Enable(tc.Binary, tc.Mount)
	t.Cleanup(func() { c.Unmount(tc.Mount) })

	c.Write(tc.Mount+"/"+ConfigPath, tc.Config)
	c.Write(tc.Mount+"/minter-sets/"+tc.SetName, tc.MinterSet)
	c.Write(tc.rolePath(), tc.Role)

	// Baseline AFTER configuration: a minter-set write and a role write each run a
	// capability probe, which mints and deletes.
	want := upstreamCount(tc)

	first := c.Read(tc.issuePath())
	AssertLease(t, tc, first)
	AssertEnvelope(t, tc, first)
	want++
	AssertUpstream(t, tc, want)

	second := c.Read(tc.issuePath())
	assertSecondRead(t, tc, first, second)
	want += tc.mintsPerRead()
	AssertUpstream(t, tc, want)

	want = assertCredentialKindPin(t, c, tc, first, want)

	assertLeaseIsTracked(t, c, first.LeaseID)
	assertRenewContract(t, c, tc, first.LeaseID)

	if tc.HardRevoke {
		want--
	}
	assertRevoke(t, c, tc, first.LeaseID, want)

	want += tc.mintsPerRead()
	assertReloadThenIssue(t, c, tc, want)

	assertPurgeUpstream(t, c, tc, want)
}

// assertPurgeUpstream drives containment's second lever through the real API: destroy what
// the role has already issued, without touching a single lease.
//
// It runs last, deliberately, because it needs what the rest of the scenario has left behind —
// credentials still live upstream, issued through the plugin RPC boundary and belonging to
// leases core is still tracking. That is the situation the endpoint is for, and it is the
// situation an in-process test cannot assemble.
//
// What this layer adds over conformance is the wire: the report is assembled by a process of
// its own and reaches a client through OpenBao's JSON layer, so every count arrives as a
// json.Number. A plugin whose report was correct in-process and unreadable to `bao write`
// would pass every other test in the repository.
func assertPurgeUpstream(t *testing.T, c *Cluster, tc Case, live int) {
	t.Helper()
	if !tc.DeletesIssuedCredentials {
		// Nothing to delete, so the endpoint must refuse rather than report a purge of zero:
		// the role's TTL ceiling is this cloud's whole blast radius, and a clean report would
		// tell an operator the incident was contained.
		// Matched inside the message rather than parsed off the front of it: the API client
		// wraps a refusal in its own request context, so what a client actually receives is
		// the code somewhere in a larger string.
		err := c.WriteExpectingError(tc.purgePath(), map[string]interface{}{})
		if !strings.Contains(err.Error(), string(credenvelope.ErrUnsupported)) {
			t.Errorf("revoking upstream on %s was refused with %v, which does not carry %q — an "+
				"operator cannot tell a cloud that will not do this from one that failed to",
				tc.Cloud, err, credenvelope.ErrUnsupported)
		}
		return
	}

	dry := c.Write(tc.purgePath(), map[string]interface{}{purgeKeyMode: purgeModeDryRun})
	if got := JSONInt(t, dry.Data[purgeKeyTracked]); got != live {
		t.Errorf("the dry run reported %s=%d, want the %d credentials this role has issued",
			purgeKeyTracked, got, live)
	}
	AssertUpstream(t, tc, live)

	purged := c.Write(tc.purgePath(), map[string]interface{}{purgeKeyMode: purgeModeNormal})
	if got := Str(t, purged.Data, purgeKeyMode); got != purgeModeNormal {
		t.Errorf("the purge reported %s=%q, want %q", purgeKeyMode, got, purgeModeNormal)
	}
	if got := JSONInt(t, purged.Data[purgeKeyDeleted]); got != live {
		t.Errorf("the purge reported %s=%d, want %d", purgeKeyDeleted, got, live)
	}
	if purged.Data[purgeKeyComplete] != true {
		t.Errorf("the purge reported %s=%v, want it finished", purgeKeyComplete,
			purged.Data[purgeKeyComplete])
	}
	AssertUpstream(t, tc, 0)

	if progress := c.Read(tc.purgePath()); progress.Data[purgeKeyComplete] != true {
		t.Errorf("reading the purge back reports %s=%v, want it finished", purgeKeyComplete,
			progress.Data[purgeKeyComplete])
	}
}

// AssertLease checks the lease OpenBao actually created. None of this is observable
// in-process: the in-memory tests read resp.Secret's fields straight back out of the
// struct the plugin populated.
func AssertLease(t *testing.T, tc Case, secret *api.Secret) {
	t.Helper()
	tc = tc.withDefaults()
	if secret.LeaseID == "" {
		t.Fatalf("OpenBao created no lease for the issued credential; without one nothing "+
			"revokes it (secret: %+v)", secret)
	}
	if prefix := tc.issuePath(); !strings.HasPrefix(secret.LeaseID, prefix+"/") {
		t.Errorf("lease id %q is not under %q", secret.LeaseID, prefix)
	}
	if secret.LeaseDuration != tc.GrantedTTLSeconds {
		t.Errorf("lease duration is %ds, want %ds: either the plugin left resp.Secret.TTL "+
			"unset or core clamped it against a mount/system max_lease_ttl "+
			"(docs/openbao-integration-gaps.md G5)", secret.LeaseDuration, tc.GrantedTTLSeconds)
	}
	if secret.Renewable != tc.Renewable {
		t.Errorf("lease says renewable=%v, want %v: renewability must be false wherever the "+
			"credential's expiry is fixed at mint, and the LEASE is what a client renews "+
			"(docs/ttl-semantics.md)", secret.Renewable, tc.Renewable)
	}
}

// AssertEnvelope checks the response envelope after a round trip through the plugin RPC
// boundary and the HTTP API — where an int becomes json.Number and a time.Time would
// become a string.
func AssertEnvelope(t *testing.T, tc Case, secret *api.Secret) {
	t.Helper()
	tc = tc.withDefaults()
	data := secret.Data
	if code, ok := data["error_code"]; ok {
		t.Fatalf("issuance returned an error envelope: error_code=%v data=%v", code, data)
	}
	if got := Str(t, data, "cloud"); got != tc.Cloud {
		t.Errorf("envelope cloud is %q, want %q", got, tc.Cloud)
	}
	if got := Str(t, data, "role"); got != tc.RoleName {
		t.Errorf("envelope role is %q, want %q", got, tc.RoleName)
	}
	if credential := Nested(t, data, "credential"); len(credential) == 0 {
		t.Errorf("envelope carries an empty credential")
	}
	expiresAt, err := time.Parse(time.RFC3339, Str(t, data, "expires_at"))
	if err != nil {
		t.Errorf("envelope expires_at did not survive the round trip as RFC3339: %v", err)
	} else if !expiresAt.After(time.Now()) {
		t.Errorf("envelope expires_at %s is not in the future", expiresAt)
	}
	if got := JSONInt(t, data["ttl_seconds"]); got != tc.GrantedTTLSeconds {
		t.Errorf("envelope ttl_seconds is %d, want %d", got, tc.GrantedTTLSeconds)
	}
	if got, ok := data["renewable"].(bool); !ok || got != secret.Renewable {
		t.Errorf("envelope says renewable=%v but the lease says %v: a client reading one and "+
			"acting on the other is the failure this disagreement produces", data["renewable"],
			secret.Renewable)
	}

	assertEnvelopeMetadata(t, tc, Nested(t, data, "metadata"))
}

// assertEnvelopeMetadata checks the provenance and contract half of the envelope: which
// version a client should read it as, what shape the credential block is, and which
// minter issued it. Split out of AssertEnvelope to keep each readable — and because
// these are the fields a CLIENT keys off, where the ones above are what it consumes.
func assertEnvelopeMetadata(t *testing.T, tc Case, metadata map[string]interface{}) {
	t.Helper()
	if got := Str(t, metadata, "api_version"); got != credenvelope.APIVersion {
		t.Errorf("envelope api_version is %q, want %q", got, credenvelope.APIVersion)
	}
	kind := credenvelope.CredentialKind(Str(t, metadata, "credential_kind"))
	if !credenvelope.ValidCredentialKind(kind) {
		t.Errorf("envelope metadata.credential_kind is %q, which is not in the closed vocabulary "+
			"%v: a client cannot know what shape it is parsing", kind,
			credenvelope.AllCredentialKinds())
	}
	if tc.CredentialKind != "" && kind != tc.CredentialKind {
		t.Errorf("envelope metadata.credential_kind is %q, want %q", kind, tc.CredentialKind)
	}
	if got := Str(t, metadata, "minter_set"); got != tc.SetName {
		t.Errorf("envelope metadata.minter_set is %q, want %q", got, tc.SetName)
	}
	if got := Str(t, metadata, "minter_id"); got != tc.MinterID {
		t.Errorf("envelope metadata.minter_id is %q, want %q", got, tc.MinterID)
	}
}

// assertDistinctIssuance proves two reads produce two credentials. The upstream name is
// built from req.ID, which ONLY core populates — in-process tests either leave it empty
// or invent it (docs/openbao-integration-gaps.md G4).
// assertSecondRead checks what a re-read gives a client, which is the one thing the two
// lifecycles disagree about outright.
//
// The lease is always new — core registers one per read whoever owns the credential — so
// only the credential's identity distinguishes them, and each direction has its own way of
// being wrong: a per-lease role that re-served one credential would hand every reader a key
// somebody else's revoke can delete, and a shared role that minted per read would spend the
// account's cap per reader and give none of them the replacement.
func assertSecondRead(t *testing.T, tc Case, first, second *api.Secret) {
	t.Helper()
	if first.LeaseID == second.LeaseID {
		t.Errorf("two reads produced one lease id %q", first.LeaseID)
	}
	same := first.Data["credential_id"] == second.Data["credential_id"]
	if tc.SharesOneCredential {
		if !same {
			t.Errorf("two reads of a shared credential returned %v then %v: every reader of this "+
				"role holds the same credential until the role's schedule replaces it, so a client "+
				"re-reading has been handed something new that nothing but its own lease bounds",
				first.Data["credential_id"], second.Data["credential_id"])
		}
		return
	}
	if same {
		t.Errorf("two reads produced the same upstream credential id %v: the name is derived "+
			"from req.ID, so this is core's request id not varying — or not reaching the plugin",
			first.Data["credential_id"])
	}
}

func assertLeaseIsTracked(t *testing.T, c *Cluster, leaseID string) {
	t.Helper()
	secret, err := c.Client().Sys().Lookup(leaseID)
	if err != nil {
		t.Fatalf("the expiration manager does not know lease %q: %v", leaseID, err)
	}
	if secret.Data["expire_time"] == nil {
		t.Errorf("lease %q has no expire_time: %v", leaseID, secret.Data)
	}
}

func assertRenewContract(t *testing.T, c *Cluster, tc Case, leaseID string) {
	t.Helper()
	renewed, err := c.Client().Sys().Renew(leaseID, 0)
	if tc.Renewable {
		if err != nil {
			t.Errorf("renewing a renewable lease failed: %v", err)
			return
		}
		if renewed.LeaseID != leaseID {
			t.Errorf("renew returned lease %q, want %q", renewed.LeaseID, leaseID)
		}
		return
	}
	if err == nil {
		t.Errorf("renew succeeded on %q, whose credential expiry is fixed at mint: the lease "+
			"would then outlive the credential (techrfc OBC-002). A non-renewable secret must "+
			"register NO Renew callback — framework.Secret.Renewable() is (Renew != nil), and "+
			"OpenBao revokes a lease whose renewal fails", leaseID)
	}
}

// assertRevoke revokes through the expiration manager — the production path, where
// in-process tests call the plugin's revoke callback directly.
func assertRevoke(t *testing.T, c *Cluster, tc Case, leaseID string, want int) {
	t.Helper()
	if err := c.Client().Sys().Revoke(leaseID); err != nil {
		t.Fatalf("revoking lease %q failed: %v", leaseID, err)
	}
	if _, err := c.Client().Sys().Lookup(leaseID); err == nil {
		t.Errorf("lease %q still resolves after revocation", leaseID)
	}
	AssertUpstream(t, tc, want)

	// A second revoke must be a clean no-op. KI-002 was exactly this wedging forever,
	// and the retry that wedged was the expiration manager's, which only exists here.
	if err := c.Client().Sys().Revoke(leaseID); err != nil {
		t.Errorf("revoking lease %q a second time errored (KI-002 class): %v", leaseID, err)
	}
}

// assertReloadThenIssue is KI-001 through core: the backend is rebuilt from storage
// alone, with no config write, and must still issue.
func assertReloadThenIssue(t *testing.T, c *Cluster, tc Case, want int) {
	t.Helper()
	c.Reload(tc.Binary)

	role := c.Read(tc.rolePath())
	if got := Str(t, role.Data, FieldMinterSet); got != tc.SetName {
		t.Errorf("after reload the role's minter_set is %q, want %q", got, tc.SetName)
	}

	secret := c.Read(tc.issuePath())
	AssertLease(t, tc, secret)
	AssertEnvelope(t, tc, secret)
	AssertUpstream(t, tc, want)
}

func upstreamCount(tc Case) int {
	if tc.Upstream == nil {
		return 0
	}
	return tc.Upstream()
}

// AssertUpstream polls the fake until it holds the expected number of credentials. The
// fake runs in the test process while the plugin runs in its own, so this is a direct
// read of upstream state rather than an inference.
func AssertUpstream(t *testing.T, tc Case, want int) {
	t.Helper()
	if tc.Upstream == nil {
		return
	}
	got := 0
	for range upstreamPollAttempts {
		got = tc.Upstream()
		if got == want {
			return
		}
		time.Sleep(upstreamPollInterval)
	}
	t.Errorf("the fake holds %d credentials, want %d", got, want)
}

// assertCredentialKindPin drives the shape pin over real HTTP, which is the half of the
// contract conformance structurally cannot reach: the pin is a query parameter on a
// READ, so it has to survive OpenBao's HTTP layer and the plugin RPC boundary before it
// becomes framework.FieldData. An in-process test calls the handler with a Data map and
// would pass whether or not that plumbing works.
//
// Returns the updated upstream count, since a served read costs whatever a read costs on
// this role, and a refused one must cost nothing whoever owns the credential.
func assertCredentialKindPin(t *testing.T, c *Cluster, tc Case, issued *api.Secret, want int) int {
	t.Helper()
	kind := Str(t, Nested(t, issued.Data, "metadata"), "credential_kind")

	// Pinning what this role serves must be served — and must be the same shape.
	pinned := c.ReadWithData(tc.issuePath(), map[string][]string{"credential_kind": {kind}})
	want += tc.mintsPerRead()
	if got := Str(t, Nested(t, pinned.Data, "metadata"), "credential_kind"); got != kind {
		t.Errorf("a read pinned to %q returned credential_kind %q", kind, got)
	}
	AssertUpstream(t, tc, want)

	// Pinning a shape this role does not serve must be refused, with the code a client
	// can act on, and WITHOUT minting: a caller that cannot parse the answer must not
	// cost an upstream credential.
	err := c.ReadExpectingError(tc.issuePath(),
		map[string][]string{"credential_kind": {string(otherKindThan(kind))}})
	if !strings.Contains(err.Error(), string(credenvelope.ErrCredentialKindUnsupported)) {
		t.Errorf("a refused pin reported %v, which does not carry %q — a client that can parse "+
			"another shape has no way to know it should ask for one",
			err, credenvelope.ErrCredentialKindUnsupported)
	}
	AssertUpstream(t, tc, want)
	return want
}

// otherKindThan picks a valid kind from the closed vocabulary that is NOT the one
// served. Chosen from the vocabulary rather than hardcoded so that adding a kind cannot
// silently turn this assertion into a comparison of a kind with itself.
func otherKindThan(served string) credenvelope.CredentialKind {
	for _, kind := range credenvelope.AllCredentialKinds() {
		if string(kind) != served {
			return kind
		}
	}
	// Unreachable: the vocabulary has more than one member, and a registry-wide
	// conformance test fails if it ever does not.
	return credenvelope.KindBasicAuth
}

// MinterSet wraps minter maps in the "minters" field every minter-set write takes.
// Values must be JSON-encodable: unlike the in-process tests, these cross the HTTP API.
func MinterSet(minters ...map[string]interface{}) map[string]interface{} {
	list := make([]interface{}, 0, len(minters))
	for _, one := range minters {
		list = append(list, one)
	}
	return map[string]interface{}{FieldMinters: list}
}

// TokenMinter builds the id/token/never_expires minter the token-style clouds take. The
// id is DefaultMinterID because the scenario asserts that same id back out of the
// envelope's provenance metadata.
func TokenMinter(token string) map[string]interface{} {
	return map[string]interface{}{
		FieldID: DefaultMinterID, FieldToken: token, FieldNeverExpires: true,
	}
}

// JSONInt reads a number that has been through the API's JSON decoder, which uses
// json.Number — an int in the plugin is not an int by the time it lands here, which is
// exactly the coercion this layer exists to exercise.
func JSONInt(t *testing.T, raw interface{}) int {
	t.Helper()
	switch v := raw.(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			t.Fatalf("%v is not an integer: %v", raw, err)
		}
		return int(n)
	case float64:
		return int(v)
	case int:
		return v
	default:
		t.Fatalf("expected a number, got %T (%v)", raw, raw)
		return 0
	}
}

// Str reads a string field, failing with the field name rather than a bare type
// assertion panic.
func Str(t *testing.T, data map[string]interface{}, key string) string {
	t.Helper()
	raw, ok := data[key]
	if !ok {
		t.Fatalf("field %q is absent from %s", key, fieldNames(data))
	}
	value, ok := raw.(string)
	if !ok {
		t.Fatalf("field %q is %T, want string", key, raw)
	}
	return value
}

// Nested reads an object field.
func Nested(t *testing.T, data map[string]interface{}, key string) map[string]interface{} {
	t.Helper()
	raw, ok := data[key]
	if !ok {
		t.Fatalf("field %q is absent from %s", key, fieldNames(data))
	}
	value, ok := raw.(map[string]interface{})
	if !ok {
		t.Fatalf("field %q is %T, want an object", key, raw)
	}
	return value
}

func fieldNames(data map[string]interface{}) string {
	names := make([]string, 0, len(data))
	for name := range data {
		names = append(names, name)
	}
	return fmt.Sprintf("%v", names)
}
