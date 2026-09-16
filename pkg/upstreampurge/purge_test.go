package upstreampurge

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	testPrefix = "active-tokens/"
	testRole   = "backups"
	otherRole  = "reports"
)

// newInmemStorage is the storage a case starts from: empty, and holding nothing but what the
// case puts in it.
func newInmemStorage() logical.Storage {
	return &logical.InmemStorage{}
}

// track writes a tracking record the way every plugin writes one: at the upstream id,
// carrying the role, the minter and a creation timestamp.
func track(t *testing.T, storage logical.Storage, id, role string, created time.Time, extra map[string]interface{}) {
	t.Helper()
	record := map[string]interface{}{
		FieldRole:    role,
		FieldMinter:  "minter-1",
		FieldCreated: created.UTC().Format(time.RFC3339),
	}
	for k, v := range extra {
		record[k] = v
	}
	entry, err := logical.StorageEntryJSON(testPrefix+id, record)
	if err != nil {
		t.Fatalf("encoding the tracking record: %v", err)
	}
	if err := storage.Put(t.Context(), entry); err != nil {
		t.Fatalf("writing the tracking record: %v", err)
	}
}

// deleted records what a Deleter was asked to delete, so a case can tell "did nothing"
// from "did the wrong thing".
type deleted struct {
	ids []string
	err error
}

func (d *deleted) delete(_ context.Context, rec Record) error {
	d.ids = append(d.ids, rec.ID)
	return d.err
}

func remainingKeys(t *testing.T, storage logical.Storage) []string {
	t.Helper()
	keys, err := storage.List(t.Context(), testPrefix)
	if err != nil {
		t.Fatalf("listing the tracking records: %v", err)
	}
	return keys
}

// A purge is scoped to one role, and to what existed when it was armed. Both halves
// matter: the first is the isolation boundary between roles, the second is what makes a
// purge terminate on a mount that keeps issuing.
func TestScanTakesOneRolesRecordsUpToTheCutoff(t *testing.T) {
	storage := newInmemStorage()
	cutoff := time.Now()
	track(t, storage, "in-scope", testRole, cutoff.Add(-time.Minute), nil)
	track(t, storage, "another-role", otherRole, cutoff.Add(-time.Minute), nil)
	track(t, storage, "issued-later", testRole, cutoff.Add(time.Minute), nil)

	records, err := Scan(t.Context(), storage, testPrefix, testRole, cutoff)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(records) != 1 || records[0].ID != "in-scope" {
		t.Fatalf("scan selected %v, want just in-scope", ids(records))
	}
	if records[0].Role != testRole || records[0].Minter != "minter-1" {
		t.Errorf("scanned record is %+v, want the role and minter the record carries", records[0])
	}
}

// A record whose timestamp cannot be read is IN scope. It was written by an earlier
// issuance either way, and the alternative — skipping it — leaves a credential the
// operator was told had been destroyed.
func TestScanIncludesARecordWithNoReadableTimestamp(t *testing.T) {
	storage := newInmemStorage()
	entry, err := logical.StorageEntryJSON(testPrefix+"undated", map[string]interface{}{
		FieldRole: testRole, FieldCreated: "not a timestamp",
	})
	if err != nil {
		t.Fatalf("encoding the record: %v", err)
	}
	if err := storage.Put(t.Context(), entry); err != nil {
		t.Fatalf("writing the record: %v", err)
	}

	records, err := Scan(t.Context(), storage, testPrefix, testRole, time.Now())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("scan selected %v, want the undated record", ids(records))
	}
}

// The record carries more than the id on the clouds where the id alone cannot address
// the credential, so a pass must hand the whole record to the deleter.
func TestScanKeepsTheRecordsOtherFields(t *testing.T) {
	storage := newInmemStorage()
	track(t, storage, "key-1", testRole, time.Now().Add(-time.Minute),
		map[string]interface{}{"app_object_id": "app-7"})

	records, err := Scan(t.Context(), storage, testPrefix, testRole, time.Now())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if got := records[0].Fields["app_object_id"]; got != "app-7" {
		t.Errorf("the scanned record reports app_object_id=%v, want app-7: Azure cannot delete a "+
			"password without the application that holds it", got)
	}
}

// A pass is bounded, and says so. An unbounded one would spend a whole account's API
// quota in a single request and take the mount's issuance down with it.
func TestPassStopsAtItsBudgetAndReportsWhatIsLeft(t *testing.T) {
	storage := newInmemStorage()
	cutoff := time.Now()
	for _, id := range []string{"a", "b", "c"} {
		track(t, storage, id, testRole, cutoff.Add(-time.Minute), nil)
	}
	del := &deleted{}

	result, err := Pass(t.Context(), storage, Config{
		Prefix: testPrefix, Role: testRole, Cutoff: cutoff, MaxDeletes: 2,
	}, del.delete)
	if err != nil {
		t.Fatalf("pass failed: %v", err)
	}
	if result.Tracked != 3 || result.Deleted != 2 || result.Remaining != 1 {
		t.Errorf("pass reported %+v, want tracked=3 deleted=2 remaining=1", result)
	}
	if len(del.ids) != 2 {
		t.Errorf("the deleter was called %d times, want 2", len(del.ids))
	}
	if got := remainingKeys(t, storage); len(got) != 1 {
		t.Errorf("%d tracking records survived the pass, want 1", len(got))
	}
}

// The tracking record is deleted only once the credential is gone. Deleting it first
// would lose the id, which is the one thing that makes the credential reachable at all.
func TestPassKeepsTheRecordWhenTheDeleteFails(t *testing.T) {
	storage := newInmemStorage()
	cutoff := time.Now()
	track(t, storage, "stubborn", testRole, cutoff.Add(-time.Minute), nil)
	del := &deleted{err: errors.New("upstream said no")}

	result, err := Pass(t.Context(), storage, Config{
		Prefix: testPrefix, Role: testRole, Cutoff: cutoff, MaxDeletes: 10,
	}, del.delete)
	if err != nil {
		t.Fatalf("a failing delete must be reported in the result, not as an error: %v", err)
	}
	if result.Failed != 1 || result.Deleted != 0 || result.Remaining != 1 {
		t.Errorf("pass reported %+v, want failed=1 deleted=0 remaining=1", result)
	}
	if got := remainingKeys(t, storage); len(got) != 1 {
		t.Errorf("the tracking record was removed although the credential is still upstream "+
			"(%d records left)", len(got))
	}
}

// A throttled pass stops immediately rather than spending the rest of its budget on
// calls the cloud is already refusing — the callers sharing that quota are issuing.
func TestPassStopsWhenTheCloudThrottlesIt(t *testing.T) {
	storage := newInmemStorage()
	cutoff := time.Now()
	for _, id := range []string{"a", "b", "c"} {
		track(t, storage, id, testRole, cutoff.Add(-time.Minute), nil)
	}
	del := &deleted{err: ErrThrottled}

	result, err := Pass(t.Context(), storage, Config{
		Prefix: testPrefix, Role: testRole, Cutoff: cutoff, MaxDeletes: 10,
	}, del.delete)
	if err != nil {
		t.Fatalf("pass failed: %v", err)
	}
	if !result.Throttled {
		t.Error("the result does not report the throttle, so a caller cannot tell a paused purge " +
			"from a stalled one")
	}
	if len(del.ids) != 1 {
		t.Errorf("the deleter was called %d times after a throttle, want 1", len(del.ids))
	}
	if result.Failed != 0 {
		t.Errorf("pass reported failed=%d: a throttle is a reason to wait, not a credential that "+
			"cannot be deleted", result.Failed)
	}
	if result.Remaining != 3 {
		t.Errorf("pass reported remaining=%d, want 3", result.Remaining)
	}
}

// Nothing in scope is the ordinary end state, reached by every purge that finishes and by
// every repeat of one.
func TestPassWithNothingInScopeIsAQuietSuccess(t *testing.T) {
	storage := newInmemStorage()
	del := &deleted{}

	result, err := Pass(t.Context(), storage, Config{
		Prefix: testPrefix, Role: testRole, Cutoff: time.Now(), MaxDeletes: 10,
	}, del.delete)
	if err != nil {
		t.Fatalf("pass failed: %v", err)
	}
	if result.Tracked != 0 || result.Remaining != 0 || result.Deleted != 0 {
		t.Errorf("pass reported %+v, want all zeroes", result)
	}
	if len(del.ids) != 0 {
		t.Errorf("the deleter was called for %v with nothing in scope", del.ids)
	}
}

// The intent is durable, because the whole point is that the operator's one call survives
// the request, a restart, and a failover.
func TestIntentSurvivesStorageAndIsDiscoverable(t *testing.T) {
	storage := newInmemStorage()
	armed := time.Now().UTC().Truncate(time.Second)
	want := &Intent{Role: testRole, ArmedAt: armed, Cutoff: armed, Tracked: 4, Deleted: 1}

	if err := SaveIntent(t.Context(), storage, want); err != nil {
		t.Fatalf("saving the intent: %v", err)
	}
	got, err := LoadIntent(t.Context(), storage, testRole)
	if err != nil {
		t.Fatalf("loading the intent: %v", err)
	}
	if got == nil || got.Tracked != 4 || got.Deleted != 1 || !got.Cutoff.Equal(armed) {
		t.Fatalf("loaded intent is %+v, want %+v", got, want)
	}

	roles, err := ArmedRoles(t.Context(), storage)
	if err != nil {
		t.Fatalf("listing armed roles: %v", err)
	}
	if len(roles) != 1 || roles[0] != testRole {
		t.Errorf("armed roles are %v, want [%s]: a worker that cannot find the intent cannot "+
			"continue the purge", roles, testRole)
	}
}

// A role nobody has purged has no intent, and that is not an error.
func TestLoadIntentReportsNoIntentAsAbsent(t *testing.T) {
	got, err := LoadIntent(t.Context(), newInmemStorage(), testRole)
	if err != nil {
		t.Fatalf("loading a missing intent: %v", err)
	}
	if got != nil {
		t.Errorf("a role with no purge reports %+v, want nothing", got)
	}
}

// The report is what an operator and any automation watching for completion read, so its
// three states have to be distinguishable: never purged, in progress, finished.
func TestReportsDistinguishTheThreeStates(t *testing.T) {
	none := NoIntentReport(testRole)
	if none[keyArmed] != false || none[keyCutoff] != "" || none[keyComplete] != false {
		t.Errorf("a role that was never purged reports %v", none)
	}

	armed := time.Now().UTC()
	running := (&Intent{Role: testRole, ArmedAt: armed, Cutoff: armed, Tracked: 5, Deleted: 2}).Report(3)
	if running[keyArmed] != true || running[keyComplete] != false {
		t.Errorf("a purge with work left reports %v, want armed and incomplete", running)
	}
	if running[keyRemaining] != 3 || running[keyDeleted] != 2 || running[keyTracked] != 5 {
		t.Errorf("a running purge reports %v, want tracked=5 deleted=2 remaining=3", running)
	}
	if running[keyCutoff] != armed.Format(time.RFC3339) {
		t.Errorf("the report gives cutoff=%v, want %s: the operator's question is which "+
			"credentials this covers", running[keyCutoff], armed.Format(time.RFC3339))
	}

	done := (&Intent{Role: testRole, ArmedAt: armed, Cutoff: armed, Tracked: 5, Deleted: 5, Complete: true}).Report(0)
	if done[keyArmed] != false || done[keyComplete] != true {
		t.Errorf("a finished purge reports %v, want complete and no longer armed", done)
	}

	dry := DryRunReport(testRole, armed, 5)
	if dry[keyArmed] != false || dry[keyTracked] != 5 || dry[keyDeleted] != 0 {
		t.Errorf("a dry run reports %v, want nothing armed and 5 credentials named", dry)
	}
}

func ids(records []Record) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.ID)
	}
	return out
}

// Outcome is the mapping every plugin's delete client needs, and getting any of its three
// cases wrong is silent: a 404 read as a failure retries forever against a credential that is
// already gone, and a 429 read as a failure spends the budget the pacing exists to protect.
func TestOutcomeReadsWhatTheCloudSaid(t *testing.T) {
	refused := errors.New("upstream said no")
	for _, c := range []struct {
		name   string
		status int
		err    error
		want   error
	}{
		{"a delete that worked", http.StatusNoContent, nil, nil},
		{"a credential already gone", http.StatusNotFound, refused, nil},
		{"a cloud telling us to slow down", http.StatusTooManyRequests, refused, ErrThrottled},
		{"anything else", http.StatusInternalServerError, refused, refused},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := Outcome(c.status, c.err)
			if !errors.Is(got, c.want) {
				t.Errorf("Outcome(%d, %v) is %v, want %v", c.status, c.err, got, c.want)
			}
		})
	}
}
