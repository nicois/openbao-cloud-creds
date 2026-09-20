package plugintest

import (
	"encoding/json"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/requester"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The identity the suite presents. Core populates these two fields from the token that presented
// the request; an in-process logical.Request carries neither unless a test supplies them, which is
// why every case here builds its own request rather than using issue().
const (
	suiteTokenAccessor = "conformance-token-accessor"
	suiteEntityID      = "conformance-entity-id"
)

// RunProvenanceSuite covers WHO obtained a credential: that the mount records it, that the caller
// cannot dictate it, and that a role may refuse to issue to a caller the mount cannot name.
//
// The tracking record is where this lives because it is the only durable statement about an issued
// credential that survives the lease: a credential found upstream is traced back through it. Before
// provenance it named the role and the minter, so an incident could be narrowed to a mount and a
// role and no further — while the question being asked is which UNIT is compromised.
//
// Two of the four cases need a tracking record to read and print why they cannot run when a subject
// has no per-read record (OCI serves a slot provisioned earlier; a rotated credential is shared by
// every reader, so no single caller obtained it). The other two apply to every subject, because
// refusing to hand a credential to an unidentifiable caller is not a question about the cloud.
func RunProvenanceSuite(t *testing.T, h Harness) {
	for _, c := range []struct {
		name string
		run  func(*testing.T, Harness)
	}{
		{"AnIssuedCredentialRecordsWhoObtainedIt", provRecordsRequester},
		{"ProvenanceCannotBeForgedByTheCaller", provCannotBeForged},
		{"ARoleReportsWhatItRequiresOfACaller", provRequirementIsVisible},
		{"ARoleCanRequireAResolvableCaller", provRequireAny},
		{"ARoleCanRefuseACallerWithNoTokenAccessor", provRequireAccessor},
		{"RefusingAnUnidentifiedCallerCostsTheUpstreamNothing", provRefusalMintsNothing},
	} {
		t.Run(c.name, func(t *testing.T) { c.run(t, h) })
	}
}

// provRecordsRequester: the record the plugin writes at mint time names the caller.
func provRecordsRequester(t *testing.T, h Harness) {
	requireTrackingRecords(t, h)
	b, storage := newConfiguredBackend(t, h)

	if resp := issueAsCaller(t, b, storage, h.IssuePath, nil); resp == nil || resp.IsError() {
		t.Fatalf("the role could not issue, so this case would prove nothing: %v", resp)
	}

	record := soleTrackingRecord(t, storage, h.TrackingPrefix)
	assertRecordField(t, record, requester.FieldTokenAccessor, suiteTokenAccessor)
	assertRecordField(t, record, requester.FieldEntityID, suiteEntityID)
}

// provCannotBeForged: a caller supplying the provenance fields itself does not get them recorded.
//
// This is the case that distinguishes provenance from minter affinity, which binds the same two
// request fields and deliberately LETS a caller override its shard key. A forgeable value here
// would let one unit record another unit's identity against a credential it obtained — worse than
// recording nothing, because an incident responder chases the named service while the compromised
// one keeps its access.
func provCannotBeForged(t *testing.T, h Harness) {
	requireTrackingRecords(t, h)
	b, storage := newConfiguredBackend(t, h)

	forged := map[string]interface{}{
		requester.FieldTokenAccessor: "forged-accessor",
		requester.FieldEntityID:      "forged-entity",
		"entity_id":                  "forged-entity",
		"client_token_accessor":      "forged-accessor",
	}
	if resp := issueAsCaller(t, b, storage, h.IssuePath, forged); resp == nil || resp.IsError() {
		t.Fatalf("the role could not issue, so this case would prove nothing: %v", resp)
	}

	record := soleTrackingRecord(t, storage, h.TrackingPrefix)
	assertRecordField(t, record, requester.FieldTokenAccessor, suiteTokenAccessor)
	assertRecordField(t, record, requester.FieldEntityID, suiteEntityID)
}

// provRequirementIsVisible: an operator can read back what the role demands.
//
// A requirement that is settable but not readable is one nobody can audit: the only way to find out
// what a role accepts would be to present a batch token and see whether it was refused.
func provRequirementIsVisible(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	requireCaller(t, b, storage, h.RolePath, requester.RequireTokenAccessor)

	role := roleDefinition(t, b, storage, h.RolePath)
	got, present := role[requester.FieldRequireCallerIdentity]
	if !present {
		t.Fatalf("the role read reports no %q field, so an operator cannot audit what it accepts",
			requester.FieldRequireCallerIdentity)
	}
	if got != string(requester.RequireTokenAccessor) {
		t.Errorf("the role reports %s=%v, want %q",
			requester.FieldRequireCallerIdentity, got, requester.RequireTokenAccessor)
	}
}

// provRequireAny: `any` refuses a request core resolved no caller for, and issues to one it did.
func provRequireAny(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	requireCaller(t, b, storage, h.RolePath, requester.RequireAny)

	resp := readOrFail(t, b, storage, h.IssuePath)
	assertCode(t, resp, credenvelope.ErrCallerUnidentified,
		"issuing to a caller with neither an entity nor a token accessor from a role requiring one")

	if resp := issueAsCaller(t, b, storage, h.IssuePath, nil); resp == nil || resp.IsError() {
		t.Fatalf("a role requiring %s refused an identified caller: %v", requester.RequireAny, resp)
	}
}

// provRequireAccessor: `token_accessor` refuses a caller with an entity but no accessor.
//
// That shape is a BATCH token, which is what makes this a separate requirement rather than a
// stricter reading of the first: a batch token has no accessor at all, and its entity is the one
// belonging to the service token that created it. So a credential issued to a batch caller is
// attributable to a fleet rather than to a unit, and an operator has to be able to say that is not
// good enough — while the same operator elsewhere legitimately wants batch callers served.
func provRequireAccessor(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	requireCaller(t, b, storage, h.RolePath, requester.RequireTokenAccessor)

	resp := issueWith(t, b, storage, h.IssuePath, &logical.Request{EntityID: suiteEntityID})
	assertCode(t, resp, credenvelope.ErrCallerUnidentified,
		"issuing to a caller with an entity but no token accessor (a batch token) from a role "+
			"requiring an accessor")

	if resp := issueAsCaller(t, b, storage, h.IssuePath, nil); resp == nil || resp.IsError() {
		t.Fatalf("a role requiring %s refused a caller that had one: %v",
			requester.RequireTokenAccessor, resp)
	}
}

// provRefusalMintsNothing: the refusal happens before a minter is selected.
//
// Placement is the whole assertion. A requirement checked after the mint would leave a credential
// upstream that no lease, no tracking record and no reconciler pass knows about — an orphan created
// by a security control.
func provRefusalMintsNothing(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	requireCaller(t, b, storage, h.RolePath, requester.RequireTokenAccessor)

	before := h.ProvisionedCount()
	resp := issueWith(t, b, storage, h.IssuePath, &logical.Request{EntityID: suiteEntityID})
	assertCode(t, resp, credenvelope.ErrCallerUnidentified, "the refused read")

	if after := h.ProvisionedCount(); after != before {
		t.Errorf("a refused read moved the upstream credential count from %d to %d: the "+
			"requirement is being checked after the mint, so every refusal leaves an orphan",
			before, after)
	}
	if h.TrackingPrefix != "" {
		if n := trackingRecords(t, storage, h.TrackingPrefix); n != 0 {
			t.Errorf("a refused read left %d tracking record(s) under %s", n, h.TrackingPrefix)
		}
	}
}

// requireTrackingRecords skips a case that needs a per-read tracking record to inspect, printing
// the reason rather than being silently absent.
func requireTrackingRecords(t *testing.T, h Harness) {
	t.Helper()
	if h.TrackingPrefix == "" {
		t.Skipf("%s declares no TrackingPrefix, so there is no per-credential record to carry "+
			"provenance (a subject serving a pre-provisioned slot writes one at rotation, not "+
			"at read)", h.Cloud)
	}
	if h.SharesOneCredential || h.IssuesFromPreprovisionedSlots {
		t.Skipf("%s serves ONE credential to every reader, so no single caller obtained it: the "+
			"record belongs to the rotation that minted it", h.Cloud)
	}
}

// requireCaller sets the role's requirement through the role's own write path, which is also an
// assertion: a requirement only an operator with the whole role definition to hand can set is not
// one they can add to a role that is already live.
func requireCaller(t *testing.T, b logical.Backend, storage logical.Storage,
	rolePath string, requirement requester.Requirement,
) {
	t.Helper()
	resp := TryWrite(t, b, storage, rolePath, map[string]interface{}{
		requester.FieldRequireCallerIdentity: string(requirement),
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("writing %s=%s to %s was refused: %v", requester.FieldRequireCallerIdentity,
			requirement, rolePath, resp.Error())
	}
}

// issueAsCaller reads the issue path as a caller core resolved both fields for.
func issueAsCaller(t *testing.T, b logical.Backend, storage logical.Storage,
	path string, data map[string]interface{},
) *logical.Response {
	t.Helper()
	return issueWith(t, b, storage, path, &logical.Request{
		ClientTokenAccessor: suiteTokenAccessor,
		EntityID:            suiteEntityID,
		Data:                data,
	})
}

// issueWith reads the issue path with the caller-identifying fields of the supplied request, which
// the caller builds because only core populates them for real.
func issueWith(t *testing.T, b logical.Backend, storage logical.Storage,
	path string, as *logical.Request,
) *logical.Response {
	t.Helper()
	as.Operation = logical.ReadOperation
	as.Path = path
	as.Storage = storage
	resp, err := b.HandleRequest(t.Context(), as)
	if err != nil {
		t.Fatalf("reading %s returned a transport error rather than a response: %v", path, err)
	}
	return resp
}

// soleTrackingRecord returns the one record under the prefix, failing on any other count: a case
// asserting on "the" record must not silently read the first of several.
func soleTrackingRecord(t *testing.T, storage logical.Storage, prefix string) map[string]interface{} {
	t.Helper()
	keys, err := storage.List(t.Context(), prefix)
	if err != nil {
		t.Fatalf("listing %s failed: %v", prefix, err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected exactly one tracking record under %s after one credential read, got %d "+
			"(%v)", prefix, len(keys), keys)
	}
	entry, err := storage.Get(t.Context(), prefix+keys[0])
	if err != nil || entry == nil {
		t.Fatalf("reading tracking record %s%s failed: err=%v entry=%v", prefix, keys[0], err, entry)
	}
	record := map[string]interface{}{}
	if err := json.Unmarshal(entry.Value, &record); err != nil {
		t.Fatalf("tracking record %s%s is not a JSON object: %v", prefix, keys[0], err)
	}
	return record
}

func assertRecordField(t *testing.T, record map[string]interface{}, key, want string) {
	t.Helper()
	got, present := record[key]
	if !present {
		t.Errorf("the tracking record carries no %q, so a credential found upstream names this "+
			"mount and this role and no further. Record: %v", key, record)
		return
	}
	if got != want {
		t.Errorf("the tracking record says %s=%v, want %q", key, got, want)
	}
}
