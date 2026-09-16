package plugintest

import (
	"reflect"
	"slices"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// fieldDisabled is the role field that stops a role issuing without deleting it.
// Every plugin already honoured it at issuance; what this category asserts is that
// an operator can SET it, which is the difference between a control and a comment.
const fieldDisabled = "disabled"

// RunContainmentSuite covers what an operator does when issued credentials are
// believed to have leaked: stop the role issuing more, then destroy what is already
// out. Both levers have to work when the cloud is unhealthy and when the operator
// does not have the role's definition to hand, because that is the situation they
// are for.
//
// Deleting the role is not either lever. It stops nothing: live leases stay
// renewable, and every credential already issued keeps working until its own expiry
// or a lease revoke reaches the cloud.
func RunContainmentSuite(t *testing.T, h Harness) {
	for _, c := range []struct {
		name string
		run  func(*testing.T, Harness)
	}{
		{"DisablingARoleStopsIssuance", containDisableStopsIssuance},
		{"DisablingARoleNeedsNothingButTheFlag", containDisableKeepsDefinition},
		{"ARoleReportsWhetherItIsDisabled", containDisabledIsVisible},
		{"ReEnablingARoleRestoresIssuance", containEnableRestoresIssuance},
		{"DisablingARoleWorksWhileTheCloudRefusesToMint", containDisableWhileMintRefused},
		{"RevokingUpstreamDeletesWhatTheRoleIssued", containPurgeDeletesIssued},
		{"ADryRunOfRevokingUpstreamDeletesNothing", containPurgeDryRunDeletesNothing},
		{"RevokingUpstreamTwiceIsACleanNoOp", containPurgeTwiceIsANoOp},
		{"RevokingUpstreamLeavesTheRoleIssuing", containPurgeLeavesTheRoleIssuing},
		{"RevokingUpstreamWorksOnADisabledRole", containPurgeWorksOnADisabledRole},
		{"RevokingUpstreamReportsOneUniformSchema", containPurgeSchemaIsUniform},
		{"RevokingUpstreamIsRefusedWhereNothingCanBeDeleted", containPurgeUnsupported},
	} {
		t.Run(c.name, func(t *testing.T) { c.run(t, h) })
	}
}

// containDisableStopsIssuance: the flag is reachable through the role's own write
// path, and issuance stops at once.
//
// It issues first, deliberately: a role that could never issue would pass the
// second half of this case for the wrong reason.
func containDisableStopsIssuance(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	if resp := readOrFail(t, b, storage, h.IssuePath); resp == nil || resp.IsError() {
		t.Fatalf("the role could not issue before being disabled, so this case would prove "+
			"nothing: %v", resp)
	}

	disable(t, b, storage, h.RolePath, true)

	resp := readOrFail(t, b, storage, h.IssuePath)
	assertCode(t, resp, credenvelope.ErrRoleDisabled, "issuing from a role that has been disabled")
}

// containDisableKeepsDefinition: disabling is one call carrying one field.
//
// A role write that replaced the whole definition would make the flag useless as a
// containment lever: the operator holding a leaked credential would have to restate
// the role's TTLs, minter set and privilege boundary correctly, from memory, under
// time pressure — and a plugin that requires a field would refuse the write outright.
func containDisableKeepsDefinition(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	before := roleDefinition(t, b, storage, h.RolePath)

	disable(t, b, storage, h.RolePath, true)

	after := roleDefinition(t, b, storage, h.RolePath)
	for key, want := range before {
		if key == fieldDisabled {
			continue
		}
		got, present := after[key]
		if !present {
			t.Errorf("disabling the role dropped its %q field (was %v). A containment write must "+
				"change one thing", key, want)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("disabling the role changed %q from %v to %v", key, want, got)
		}
	}
}

// containDisabledIsVisible: an operator who has just disabled a role, or who is
// asking why one will not issue, reads the role. The answer has to be there.
func containDisabledIsVisible(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	if got := roleDefinition(t, b, storage, h.RolePath)[fieldDisabled]; got != false {
		t.Errorf("a live role reports %s=%v, want false", fieldDisabled, got)
	}

	disable(t, b, storage, h.RolePath, true)

	if got := roleDefinition(t, b, storage, h.RolePath)[fieldDisabled]; got != true {
		t.Errorf("a disabled role reports %s=%v, want true. A role that refuses every read with "+
			"role_disabled while reporting nothing sends the operator to the audit log",
			fieldDisabled, got)
	}
}

// containEnableRestoresIssuance: containment is reversible, so the flag is what an
// operator reaches for rather than deleting and rebuilding the role.
func containEnableRestoresIssuance(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	disable(t, b, storage, h.RolePath, true)
	disable(t, b, storage, h.RolePath, false)

	resp := readOrFail(t, b, storage, h.IssuePath)
	if resp == nil || resp.IsError() {
		t.Fatalf("a re-enabled role still refuses to issue: %v", resp)
	}
}

// containDisableWhileMintRefused: the capability probe must not stand between an
// operator and the flag that stops issuance.
//
// A role write probes the bound set's minters by minting a throwaway credential, and
// the write that DISABLES a role is the one most likely to be made while the cloud is
// refusing us — a compromised minter, a revoked key, an account locked out. A role
// that cannot issue asks nothing of a minter, so there is nothing to prove.
func containDisableWhileMintRefused(t *testing.T, h Harness) {
	if h.DenyMint == nil || h.AllowMint == nil {
		t.Skipf("%s: no mint-refusal knob, so disabling a role while the cloud refuses to mint is "+
			"not asserted for this cloud", h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	denyMint(t, h)

	disable(t, b, storage, h.RolePath, true)

	resp := readOrFail(t, b, storage, h.IssuePath)
	assertCode(t, resp, credenvelope.ErrRoleDisabled,
		"issuing from a role disabled while the cloud was refusing to mint")
}

// Keys of the revoke-upstream progress report, and the two modes its write accepts.
// Spelled out here rather than imported from the implementation: a schema assertion that
// reads the keys from the code it is checking asserts nothing.
const (
	purgeKeyRole      = "role"
	purgeKeyArmed     = "armed"
	purgeKeyCutoff    = "cutoff"
	purgeKeyTracked   = "tracked"
	purgeKeyDeleted   = "deleted"
	purgeKeyRemaining = "remaining"
	purgeKeyFailed    = "failed"
	purgeKeyComplete  = "complete"
	purgeKeyMode      = "mode"

	purgeModeNormal = "normal"
	purgeModeDryRun = "dry_run"
)

// purgeReadKeys is the progress report. purgeWriteKeys is the same report plus the mode
// the call ran in, because a caller that asked for a dry run and got a real purge — or the
// reverse — must be able to tell from the response alone.
var (
	purgeReadKeys = []string{
		purgeKeyRole, purgeKeyArmed, purgeKeyCutoff, purgeKeyTracked,
		purgeKeyDeleted, purgeKeyRemaining, purgeKeyFailed, purgeKeyComplete,
	}
	purgeWriteKeys = append(append([]string{}, purgeReadKeys...), purgeKeyMode)
)

// containPurgeDeletesIssued: the second lever. Disabling a role closes the tap; this is
// what empties the bucket, and without it an operator holding a leaked credential has
// nothing but each lease's TTL and a lease-by-lease revoke they cannot enumerate.
func containPurgeDeletesIssued(t *testing.T, h Harness) {
	requirePurgeable(t, h)
	b, storage := newConfiguredBackend(t, h)

	before := h.ProvisionedCount()
	const reads = 3
	live := credentialsFrom(h, reads)
	for i := range reads {
		if resp := readOrFail(t, b, storage, h.IssuePath); resp == nil || resp.IsError() {
			t.Fatalf("issuing credential %d of %d failed, so there would be nothing to revoke: %v",
				i+1, reads, resp)
		}
	}
	if got := h.ProvisionedCount(); got != before+live {
		t.Fatalf("the cloud holds %d credentials, want %d: this case has to have live credentials "+
			"to revoke or it proves nothing", got, before+live)
	}

	resp := purgeUpstream(t, b, storage, h.RolePath, purgeModeNormal)
	if got := progressCount(t, resp, purgeKeyDeleted); got != live {
		t.Errorf("the purge reported %s=%d, want %d", purgeKeyDeleted, got, live)
	}
	if got := progressCount(t, resp, purgeKeyRemaining); got != 0 {
		t.Errorf("the purge reported %s=%d, want 0", purgeKeyRemaining, got)
	}
	if resp.Data[purgeKeyComplete] != true {
		t.Errorf("the purge reported %s=%v with nothing left to delete", purgeKeyComplete,
			resp.Data[purgeKeyComplete])
	}
	if got := h.ProvisionedCount(); got != before {
		t.Errorf("the cloud still holds %d credentials, want %d: the credentials this role issued "+
			"are still usable by whoever holds them, which is the one thing this call exists to end",
			got, before)
	}
	if n := trackingRecords(t, storage, h.TrackingPrefix); n != 0 {
		t.Errorf("%d tracking records survived the purge. A record naming a credential that no "+
			"longer exists counts against the mount's own per-minter capacity and sends every "+
			"later lease revoke to the cloud for nothing", n)
	}
}

// containPurgeDryRunDeletesNothing: the first call an operator makes is the one that
// tells them how big the incident is. It must not be the one that acts.
func containPurgeDryRunDeletesNothing(t *testing.T, h Harness) {
	requirePurgeable(t, h)
	b, storage := newConfiguredBackend(t, h)

	before := h.ProvisionedCount()
	const reads = 2
	live := credentialsFrom(h, reads)
	for range reads {
		readOrFail(t, b, storage, h.IssuePath)
	}

	resp := purgeUpstream(t, b, storage, h.RolePath, purgeModeDryRun)
	if got := progressCount(t, resp, purgeKeyTracked); got != live {
		t.Errorf("the dry run reported %s=%d, want %d: it has to say what a real one would "+
			"delete", purgeKeyTracked, got, live)
	}
	if got := progressCount(t, resp, purgeKeyDeleted); got != 0 {
		t.Errorf("the dry run reported %s=%d, want 0", purgeKeyDeleted, got)
	}
	if resp.Data[purgeKeyArmed] != false {
		t.Errorf("the dry run reported %s=%v: a dry run must arm nothing, or the background "+
			"worker finishes the purge the operator was only asking about", purgeKeyArmed,
			resp.Data[purgeKeyArmed])
	}
	if got := h.ProvisionedCount(); got != before+live {
		t.Errorf("the cloud holds %d credentials after a dry run, want %d", got, before+live)
	}
	if n := trackingRecords(t, storage, h.TrackingPrefix); n != live {
		t.Errorf("a dry run left %d tracking records, want %d", n, live)
	}
	if progress := readProgress(t, b, storage, h.RolePath); progress.Data[purgeKeyArmed] != false {
		t.Errorf("after a dry run the role reports %s=%v", purgeKeyArmed, progress.Data[purgeKeyArmed])
	}
}

// containPurgeTwiceIsANoOp: an operator under pressure repeats the call, and a second one
// must be free of consequence — no error to interpret, and nothing else deleted.
func containPurgeTwiceIsANoOp(t *testing.T, h Harness) {
	requirePurgeable(t, h)
	b, storage := newConfiguredBackend(t, h)

	before := h.ProvisionedCount()
	readOrFail(t, b, storage, h.IssuePath)
	purgeUpstream(t, b, storage, h.RolePath, purgeModeNormal)

	resp := purgeUpstream(t, b, storage, h.RolePath, purgeModeNormal)
	if got := progressCount(t, resp, purgeKeyDeleted); got != 0 {
		t.Errorf("a repeated purge reported %s=%d, want 0", purgeKeyDeleted, got)
	}
	if got := progressCount(t, resp, purgeKeyFailed); got != 0 {
		t.Errorf("a repeated purge reported %s=%d, want 0: a credential already gone is the "+
			"outcome asked for, not a failure", purgeKeyFailed, got)
	}
	if resp.Data[purgeKeyComplete] != true {
		t.Errorf("a repeated purge reported %s=%v", purgeKeyComplete, resp.Data[purgeKeyComplete])
	}
	if got := h.ProvisionedCount(); got != before {
		t.Errorf("the cloud holds %d credentials, want %d", got, before)
	}
}

// containPurgeLeavesTheRoleIssuing: the two levers are separate, on purpose. A purge that
// also disabled the role would make the pair unusable for the common case — a leak of one
// credential, contained without an outage — and one that never terminated would delete
// every credential issued during the incident response too.
func containPurgeLeavesTheRoleIssuing(t *testing.T, h Harness) {
	requirePurgeable(t, h)
	b, storage := newConfiguredBackend(t, h)

	before := h.ProvisionedCount()
	readOrFail(t, b, storage, h.IssuePath)
	purgeUpstream(t, b, storage, h.RolePath, purgeModeNormal)

	if got := roleDefinition(t, b, storage, h.RolePath)[fieldDisabled]; got != false {
		t.Errorf("revoking upstream left the role reporting %s=%v: emptying the bucket must not "+
			"close the tap, or an operator cannot do one without the other", fieldDisabled, got)
	}
	resp := readOrFail(t, b, storage, h.IssuePath)
	if resp == nil || resp.IsError() {
		t.Fatalf("the role would not issue after a purge: %v", resp)
	}
	if got := h.ProvisionedCount(); got != before+1 {
		t.Errorf("the cloud holds %d credentials, want %d: a credential issued after the purge was "+
			"armed is outside its scope, which is what makes the purge terminate", got, before+1)
	}
	if progress := readProgress(t, b, storage, h.RolePath); progress.Data[purgeKeyComplete] != true {
		t.Errorf("the purge reports %s=%v after finishing; issuing again must not reopen it",
			purgeKeyComplete, progress.Data[purgeKeyComplete])
	}
}

// containPurgeWorksOnADisabledRole: close the tap, then empty the bucket. That order is the
// whole reason both levers exist, and it is the order an operator will use — nobody deletes
// what leaked while the role is still handing out more.
//
// It is asserted because the natural implementation breaks it. Every plugin loads a role
// through its issuance path, which refuses a disabled one with role_disabled; a purge built on
// that loader answers the operator's second call with "this role is disabled", leaving them to
// re-enable the role — reopening issuance during an incident — to destroy what leaked.
func containPurgeWorksOnADisabledRole(t *testing.T, h Harness) {
	requirePurgeable(t, h)
	b, storage := newConfiguredBackend(t, h)

	before := h.ProvisionedCount()
	if resp := readOrFail(t, b, storage, h.IssuePath); resp == nil || resp.IsError() {
		t.Fatalf("issuing before the role was disabled failed, so there would be nothing to "+
			"revoke: %v", resp)
	}
	disable(t, b, storage, h.RolePath, true)

	resp := purgeUpstream(t, b, storage, h.RolePath, purgeModeNormal)
	if got := progressCount(t, resp, purgeKeyDeleted); got != 1 {
		t.Errorf("purging a disabled role reported %s=%d, want 1", purgeKeyDeleted, got)
	}
	if got := h.ProvisionedCount(); got != before {
		t.Errorf("the cloud still holds %d credentials, want %d: a role disabled to stop the "+
			"bleeding has to stay purgeable, or containment needs issuance reopened first", got, before)
	}
	if got := roleDefinition(t, b, storage, h.RolePath)[fieldDisabled]; got != true {
		t.Errorf("after the purge the role reports %s=%v, want it still disabled", fieldDisabled, got)
	}
}

// containPurgeSchemaIsUniform: one report, whichever cloud and whether it is armed. An
// operator's runbook and any automation watching for completion are written once.
func containPurgeSchemaIsUniform(t *testing.T, h Harness) {
	requirePurgeable(t, h)
	b, storage := newConfiguredBackend(t, h)
	readOrFail(t, b, storage, h.IssuePath)

	write := purgeUpstream(t, b, storage, h.RolePath, purgeModeNormal)
	assertExactKeys(t, write.Data, purgeWriteKeys, "the revoke-upstream write response")
	if write.Data[purgeKeyMode] != purgeModeNormal {
		t.Errorf("the write reported %s=%v, want %q", purgeKeyMode, write.Data[purgeKeyMode],
			purgeModeNormal)
	}
	if write.Data[purgeKeyRole] == "" {
		t.Errorf("the write reported an empty %s", purgeKeyRole)
	}
	assertExactKeys(t, readProgress(t, b, storage, h.RolePath).Data, purgeReadKeys,
		"the revoke-upstream read response")
}

// containPurgeUnsupported: on a cloud whose credentials cannot be deleted, the endpoint
// says so rather than reporting a purge that did nothing.
//
// AWS, GCP and OVH mint credentials with no delete API at all, so the role's TTL ceiling
// IS the blast radius of a leak; OCI's lever is rotating the slot. A success response
// listing zero deletions would tell an operator the incident was contained.
func containPurgeUnsupported(t *testing.T, h Harness) {
	if h.DeletesIssuedCredentials {
		t.Skipf("%s can delete a credential it has issued, so revoke-upstream acts rather than refusing",
			h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)

	write := TryWrite(t, b, storage, purgePath(h.RolePath), map[string]interface{}{})
	assertCode(t, write, credenvelope.ErrUnsupported,
		"revoking upstream where the cloud offers nothing to delete")
	assertCode(t, Read(t, b, storage, purgePath(h.RolePath)), credenvelope.ErrUnsupported,
		"reading purge progress where the cloud offers nothing to delete")
}

// requirePurgeable skips a case on the clouds that cannot delete an issued credential.
// Their refusal is asserted by containPurgeUnsupported instead.
func requirePurgeable(t *testing.T, h Harness) {
	t.Helper()
	if !h.DeletesIssuedCredentials {
		t.Skipf("%s cannot delete a credential it has issued, so there is nothing for a purge to do",
			h.Cloud)
	}
	if h.ProvisionedCount == nil || h.TrackingPrefix == "" {
		t.Skipf("%s declares ProvisionedCount=%v TrackingPrefix=%q, so a purge cannot be observed",
			h.Cloud, h.ProvisionedCount != nil, h.TrackingPrefix)
	}
}

// credentialsFrom says how many upstream credentials `reads` credential reads leave behind.
// One per read on nine subjects; exactly one where the role serves a credential SHARED by
// every reader, however many read it. Stated rather than measured, so a subject that
// regressed from one to the other fails here instead of quietly agreeing with itself.
func credentialsFrom(h Harness, reads int) int {
	if h.SharesOneCredential {
		return 1
	}
	return reads
}

// purgePath is where a role's issued credentials are deleted from the cloud.
func purgePath(rolePath string) string {
	return rolePath + "/revoke-upstream"
}

// purgeUpstream runs the endpoint in one mode and fails on anything but a report.
func purgeUpstream(t *testing.T, b logical.Backend, storage logical.Storage, rolePath, mode string) *logical.Response {
	t.Helper()
	resp := TryWrite(t, b, storage, purgePath(rolePath), map[string]interface{}{purgeKeyMode: mode})
	if resp == nil {
		t.Fatalf("%s in mode %s returned no response, so nothing reports what it did",
			purgePath(rolePath), mode)
	}
	if resp.IsError() {
		t.Fatalf("%s in mode %s was refused: %v", purgePath(rolePath), mode, resp.Error())
	}
	return resp
}

// readProgress reads the purge report for a role.
func readProgress(t *testing.T, b logical.Backend, storage logical.Storage, rolePath string) *logical.Response {
	t.Helper()
	resp := Read(t, b, storage, purgePath(rolePath))
	if resp == nil {
		t.Fatalf("reading %s returned nothing: an asynchronous purge nobody can watch is one an "+
			"operator has to assume finished", purgePath(rolePath))
	}
	if resp.IsError() {
		t.Fatalf("reading %s failed: %v", purgePath(rolePath), resp.Error())
	}
	return resp
}

// progressCount reads one count out of a report. The type is not asserted because a
// storage or RPC round trip can widen an int; a report that cannot be read as a number
// at all is the failure.
func progressCount(t *testing.T, resp *logical.Response, key string) int {
	t.Helper()
	switch v := resp.Data[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		t.Fatalf("the purge report has %s=%v (%T), which is not a count", key, v, v)
		return 0
	}
}

// trackingRecords counts the mount's active-credential records.
func trackingRecords(t *testing.T, storage logical.Storage, prefix string) int {
	t.Helper()
	keys, err := storage.List(t.Context(), prefix)
	if err != nil {
		t.Fatalf("listing %s failed: %v", prefix, err)
	}
	return len(keys)
}

// assertExactKeys holds a response to exactly the documented key set, in both directions:
// a missing key breaks a reader, and an extra one is a field nothing documents and
// everything starts depending on.
func assertExactKeys(t *testing.T, data map[string]interface{}, want []string, what string) {
	t.Helper()
	for _, key := range want {
		if _, present := data[key]; !present {
			t.Errorf("%s omits %q", what, key)
		}
	}
	for key := range data {
		if !slices.Contains(want, key) {
			t.Errorf("%s carries %q, which is not part of the uniform report", what, key)
		}
	}
}

// disable writes just the flag to an existing role and fails on anything but success.
func disable(t *testing.T, b logical.Backend, storage logical.Storage, rolePath string, disabled bool) {
	t.Helper()
	resp := TryWrite(t, b, storage, rolePath, map[string]interface{}{fieldDisabled: disabled})
	if resp != nil && resp.IsError() {
		t.Fatalf("writing %s=%v to %s was refused: %v", fieldDisabled, disabled, rolePath, resp.Error())
	}
}

// roleDefinition reads a role and returns its data, failing if it is absent.
func roleDefinition(t *testing.T, b logical.Backend, storage logical.Storage, rolePath string) map[string]interface{} {
	t.Helper()
	resp := Read(t, b, storage, rolePath)
	if resp == nil {
		t.Fatalf("role %s does not exist", rolePath)
	}
	if resp.IsError() {
		t.Fatalf("reading role %s failed: %v", rolePath, resp.Error())
	}
	return resp.Data
}
