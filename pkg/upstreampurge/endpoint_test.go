package upstreampurge

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The uniform report, spelled out here as the contract a plugin's clients read. The same key
// set is asserted per plugin from the conformance suite, so a plugin that adds a field of its
// own fails there rather than shipping a schema only one cloud has.
var (
	reportKeys = []string{
		keyRole, keyArmed, keyCutoff, keyTracked, keyDeleted, keyRemaining, keyFailed, keyComplete,
	}
	writeKeys = append(append([]string{}, reportKeys...), KeyMode)
)

// purgeable is the plugin half of the endpoint: which records belong to a role, and how one of
// its credentials is deleted upstream.
type purgeable struct {
	prefix  string
	missing bool
	err     error
	deleted []string
	budget  int
}

func (p *purgeable) resolve(_ context.Context, _ logical.Storage, role string) (*Target, *logical.Response) {
	if p.missing {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", role)
	}
	return &Target{Prefix: p.prefix, Delete: p.delete}, nil
}

func (p *purgeable) delete(_ context.Context, rec Record) error {
	if p.err != nil {
		return p.err
	}
	p.deleted = append(p.deleted, rec.ID)
	return nil
}

func (p *purgeable) endpoint() Endpoint {
	return Endpoint{
		Cloud:             "testcloud",
		MaxDeletesPerPass: p.budget,
		Resolve:           p.resolve,
	}
}

// newPurgeBackend registers the endpoint in a real framework.Backend, because the schema, the
// mode field and the operations are as much of the contract as the counts are.
func newPurgeBackend(t *testing.T, paths ...*framework.Path) (logical.Backend, logical.Storage) {
	t.Helper()
	b := &framework.Backend{
		BackendType: logical.TypeLogical,
		Paths:       paths,
	}
	storage := newInmemStorage()
	if err := b.Setup(t.Context(), &logical.BackendConfig{StorageView: storage}); err != nil {
		t.Fatalf("setting up the backend: %v", err)
	}
	return b, storage
}

func request(t *testing.T, b logical.Backend, storage logical.Storage, op logical.Operation, data map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: op,
		Path:      "roles/" + testRole + "/revoke-upstream",
		Data:      data,
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("%s on the purge path returned an error: %v", op, err)
	}
	if resp == nil {
		t.Fatalf("%s on the purge path returned no response", op)
	}
	return resp
}

func assertReportKeys(t *testing.T, resp *logical.Response, want []string) {
	t.Helper()
	for _, key := range want {
		if _, present := resp.Data[key]; !present {
			t.Errorf("the report omits %q", key)
		}
	}
	for key := range resp.Data {
		if !slices.Contains(want, key) {
			t.Errorf("the report carries %q, which is not part of the uniform schema", key)
		}
	}
}

// The write is the operator's one call: it arms the purge durably and does as much of the work
// as it safely can before answering, so the answer is progress rather than an acknowledgement.
func TestWriteArmsThePurgeAndDeletesInline(t *testing.T) {
	p := &purgeable{prefix: testPrefix}
	b, storage := newPurgeBackend(t, Path(p.endpoint))
	for _, id := range []string{"a", "b"} {
		track(t, storage, id, testRole, time.Now().Add(-time.Minute), nil)
	}

	resp := request(t, b, storage, logical.UpdateOperation, nil)
	if resp.IsError() {
		t.Fatalf("the purge was refused: %v", resp.Error())
	}
	assertReportKeys(t, resp, writeKeys)
	if resp.Data[keyDeleted] != 2 || resp.Data[keyRemaining] != 0 || resp.Data[keyComplete] != true {
		t.Errorf("the purge reported %v, want two deleted and nothing left", resp.Data)
	}
	if resp.Data[KeyMode] != ModeNormal {
		t.Errorf("the purge reported %s=%v, want %q", KeyMode, resp.Data[KeyMode], ModeNormal)
	}
	if len(p.deleted) != 2 {
		t.Errorf("the cloud was asked to delete %v, want both credentials", p.deleted)
	}
	if n := trackedIDs(t, storage); len(n) != 0 {
		t.Errorf("%v survived the purge as tracking records", n)
	}
}

// The first call an operator makes is the one that tells them how big the incident is. It must
// arm nothing, or the worker finishes the purge they were only asking about.
func TestWriteInDryRunModeChangesNothing(t *testing.T) {
	p := &purgeable{prefix: testPrefix}
	b, storage := newPurgeBackend(t, Path(p.endpoint))
	track(t, storage, "a", testRole, time.Now().Add(-time.Minute), nil)

	resp := request(t, b, storage, logical.UpdateOperation, map[string]interface{}{KeyMode: ModeDryRun})
	if resp.IsError() {
		t.Fatalf("the dry run was refused: %v", resp.Error())
	}
	assertReportKeys(t, resp, writeKeys)
	if resp.Data[keyTracked] != 1 || resp.Data[keyDeleted] != 0 || resp.Data[keyArmed] != false {
		t.Errorf("the dry run reported %v, want one credential named, none deleted, nothing armed",
			resp.Data)
	}
	if len(p.deleted) != 0 {
		t.Errorf("the dry run deleted %v", p.deleted)
	}
	intent, err := LoadIntent(t.Context(), storage, testRole)
	if err != nil {
		t.Fatalf("loading the intent: %v", err)
	}
	if intent != nil {
		t.Errorf("the dry run armed %+v: a background worker would then finish a purge nobody "+
			"asked for", intent)
	}
}

// A mode nobody implements is refused rather than treated as the default. Defaulting an
// unrecognised mode to a real purge would turn a typo in a dry run into an irreversible one.
func TestWriteRefusesAnUnknownMode(t *testing.T) {
	p := &purgeable{prefix: testPrefix}
	b, storage := newPurgeBackend(t, Path(p.endpoint))
	track(t, storage, "a", testRole, time.Now().Add(-time.Minute), nil)

	resp := request(t, b, storage, logical.UpdateOperation, map[string]interface{}{KeyMode: "maybe"})
	if !resp.IsError() {
		t.Fatalf("an unknown mode was accepted: %v", resp.Data)
	}
	if len(p.deleted) != 0 {
		t.Errorf("a refused call deleted %v", p.deleted)
	}
}

// A purge too big for one request is continued by the worker, which is what makes the
// operator's single call enough. Without that the purge silently stops at the first budget.
func TestSweepFinishesWhatTheWriteCouldNot(t *testing.T) {
	p := &purgeable{prefix: testPrefix, budget: 1}
	b, storage := newPurgeBackend(t, Path(p.endpoint))
	for _, id := range []string{"a", "b", "c"} {
		track(t, storage, id, testRole, time.Now().Add(-time.Minute), nil)
	}

	resp := request(t, b, storage, logical.UpdateOperation, nil)
	if resp.Data[keyDeleted] != 1 || resp.Data[keyComplete] != false {
		t.Fatalf("the inline pass reported %v, want one deleted and the purge unfinished", resp.Data)
	}

	for range 3 {
		if err := p.endpoint().Sweep(t.Context(), storage); err != nil {
			t.Fatalf("the sweep failed: %v", err)
		}
	}
	if len(p.deleted) != 3 {
		t.Errorf("the cloud was asked to delete %v, want all three", p.deleted)
	}
	progress := request(t, b, storage, logical.ReadOperation, nil)
	if progress.Data[keyComplete] != true || progress.Data[keyDeleted] != 3 {
		t.Errorf("after the sweep the purge reports %v, want complete with three deleted",
			progress.Data)
	}
}

// The sweep runs on every tick for the life of the mount, so a finished purge must cost
// nothing upstream — an intent is kept after completion precisely so the outcome stays
// readable, and re-reading it as work would delete every credential issued since.
func TestSweepLeavesAFinishedPurgeAlone(t *testing.T) {
	p := &purgeable{prefix: testPrefix}
	b, storage := newPurgeBackend(t, Path(p.endpoint))
	track(t, storage, "a", testRole, time.Now().Add(-time.Minute), nil)
	request(t, b, storage, logical.UpdateOperation, nil)

	track(t, storage, "issued-after", testRole, time.Now(), nil)
	if err := p.endpoint().Sweep(t.Context(), storage); err != nil {
		t.Fatalf("the sweep failed: %v", err)
	}
	if len(p.deleted) != 1 || p.deleted[0] != "a" {
		t.Errorf("the cloud was asked to delete %v, want only the credential in scope", p.deleted)
	}
}

// A sweep that cannot resolve one role's target must still purge the others: the roles are
// unrelated, and one broken role would otherwise strand every other operator's containment.
func TestSweepKeepsGoingPastARoleItCannotResolve(t *testing.T) {
	p := &purgeable{prefix: testPrefix}
	storage := newInmemStorage()
	for _, role := range []string{testRole, otherRole} {
		if _, err := Arm(t.Context(), storage, testPrefix, role, time.Now()); err != nil {
			t.Fatalf("arming %s: %v", role, err)
		}
	}
	track(t, storage, "a", otherRole, time.Now().Add(-time.Hour), nil)
	// The intent armed above found nothing, so re-arm it now that the record exists.
	if _, err := Arm(t.Context(), storage, testPrefix, otherRole, time.Now()); err != nil {
		t.Fatalf("re-arming %s: %v", otherRole, err)
	}
	p.missing = true

	endpoint := p.endpoint()
	endpoint.Resolve = func(ctx context.Context, s logical.Storage, role string) (*Target, *logical.Response) {
		if role == testRole {
			return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "deleted since")
		}
		return &Target{Prefix: testPrefix, Delete: p.delete}, nil
	}
	if err := endpoint.Sweep(t.Context(), storage); err != nil {
		t.Fatalf("the sweep failed: %v", err)
	}
	if len(p.deleted) != 1 || p.deleted[0] != "a" {
		t.Errorf("the cloud was asked to delete %v, want the surviving role's credential", p.deleted)
	}
}

// A throttled sweep waits for the next tick rather than reporting a failure. The pass is
// paced, so being told to slow down is the system working.
func TestSweepTreatsAThrottleAsAPause(t *testing.T) {
	p := &purgeable{prefix: testPrefix, err: ErrThrottled}
	storage := newInmemStorage()
	track(t, storage, "a", testRole, time.Now().Add(-time.Hour), nil)
	if _, err := Arm(t.Context(), storage, testPrefix, testRole, time.Now()); err != nil {
		t.Fatalf("arming the purge: %v", err)
	}

	if err := p.endpoint().Sweep(t.Context(), storage); err != nil {
		t.Fatalf("a throttled sweep reported an error: %v", err)
	}
	intent, err := LoadIntent(t.Context(), storage, testRole)
	if err != nil || intent == nil {
		t.Fatalf("loading the intent: %+v %v", intent, err)
	}
	if intent.Complete || intent.Failed != 0 {
		t.Errorf("after a throttled sweep the intent is %+v, want it still armed with no failure "+
			"recorded", intent)
	}
}

// Reading a role nobody has purged answers the same shape as reading one that has been, so a
// runbook and any automation have one response to parse.
func TestReadReportsProgressAndTheAbsenceOfAPurge(t *testing.T) {
	p := &purgeable{prefix: testPrefix}
	b, storage := newPurgeBackend(t, Path(p.endpoint))

	before := request(t, b, storage, logical.ReadOperation, nil)
	assertReportKeys(t, before, reportKeys)
	if before.Data[keyArmed] != false || before.Data[keyCutoff] != "" {
		t.Errorf("a never-purged role reports %v", before.Data)
	}

	track(t, storage, "a", testRole, time.Now().Add(-time.Minute), nil)
	request(t, b, storage, logical.UpdateOperation, nil)

	after := request(t, b, storage, logical.ReadOperation, nil)
	assertReportKeys(t, after, reportKeys)
	if after.Data[keyComplete] != true || after.Data[keyDeleted] != 1 {
		t.Errorf("after a purge the role reports %v", after.Data)
	}
}

// A role that does not exist is said so, on both operations. Reporting a clean purge of a
// role nobody has would tell an operator an incident was contained.
func TestBothOperationsRefuseARoleThatDoesNotExist(t *testing.T) {
	p := &purgeable{prefix: testPrefix, missing: true}
	b, storage := newPurgeBackend(t, Path(p.endpoint))

	for _, op := range []logical.Operation{logical.UpdateOperation, logical.ReadOperation} {
		resp := request(t, b, storage, op, nil)
		if !resp.IsError() {
			t.Errorf("%s on a role that does not exist succeeded: %v", op, resp.Data)
			continue
		}
		assertErrorCode(t, resp, credenvelope.ErrRoleNotFound)
	}
}

// On a cloud whose credentials cannot be deleted at all, the endpoint refuses. A success
// listing zero deletions would read as containment, when in fact the role's TTL ceiling IS
// the blast radius and there is nothing an operator can do to shorten it.
func TestTheUnsupportedPathRefusesBothOperations(t *testing.T) {
	b, storage := newPurgeBackend(t, UnsupportedPath("STS sessions cannot be revoked", RemedyExpiryOnly))

	for _, op := range []logical.Operation{logical.UpdateOperation, logical.ReadOperation} {
		resp := request(t, b, storage, op, nil)
		if !resp.IsError() {
			t.Errorf("%s on the unsupported path succeeded: %v", op, resp.Data)
			continue
		}
		assertErrorCode(t, resp, credenvelope.ErrUnsupported)
	}
}

// The refusal has to name the containment an operator DOES have, and it is not the same on
// every cloud that cannot delete: where the credential merely expires, the role's max_ttl is
// the whole blast radius, but where a credential occupies a rotation slot, rotating that slot
// invalidates it now. An operator handed the expiry answer on such a cloud would sit out a TTL
// they could have cut short.
func TestTheUnsupportedPathNamesTheRemedyItWasGiven(t *testing.T) {
	remedy := "rotate the slot to replace this credential now"
	b, storage := newPurgeBackend(t, UnsupportedPath("a rotation slot's token is replaced, not deleted", remedy))

	resp := request(t, b, storage, logical.UpdateOperation, nil)
	if !resp.IsError() {
		t.Fatalf("the unsupported path succeeded: %v", resp.Data)
	}
	if message := resp.Error().Error(); !strings.Contains(message, remedy) {
		t.Errorf("the refusal is %q, which does not tell the operator to %q", message, remedy)
	}
}

// A delete the cloud refuses for a reason of its own leaves the credential tracked, so the
// worker tries again. Reporting the failure and forgetting the credential would be the one
// outcome worse than not trying.
func TestAFailedDeleteIsReportedAndRetried(t *testing.T) {
	p := &purgeable{prefix: testPrefix, err: errors.New("upstream said no")}
	b, storage := newPurgeBackend(t, Path(p.endpoint))
	track(t, storage, "a", testRole, time.Now().Add(-time.Minute), nil)

	resp := request(t, b, storage, logical.UpdateOperation, nil)
	if resp.IsError() {
		t.Fatalf("a purge whose delete failed was refused outright: %v", resp.Error())
	}
	if resp.Data[keyFailed] != 1 || resp.Data[keyComplete] != false {
		t.Errorf("the purge reported %v, want one failure and an unfinished purge", resp.Data)
	}
	if ids := trackedIDs(t, storage); len(ids) != 1 {
		t.Errorf("the tracking records are %v, want the credential still tracked for a retry", ids)
	}

	p.err = nil
	if err := p.endpoint().Sweep(t.Context(), storage); err != nil {
		t.Fatalf("the retrying sweep failed: %v", err)
	}
	if len(p.deleted) != 1 {
		t.Errorf("the retry deleted %v, want the credential that had failed", p.deleted)
	}
}

func assertErrorCode(t *testing.T, resp *logical.Response, want credenvelope.ErrorCode) {
	t.Helper()
	message := resp.Error().Error()
	got, known := credenvelope.CodeOf(message)
	if !known {
		t.Errorf("the refusal carries no recognised error_code: %q", message)
		return
	}
	if got != want {
		t.Errorf("the refusal carries error_code %q, want %q (message: %q)", got, want, message)
	}
}

func trackedIDs(t *testing.T, storage logical.Storage) []string {
	t.Helper()
	keys, err := storage.List(t.Context(), testPrefix)
	if err != nil {
		t.Fatalf("listing the tracking records: %v", err)
	}
	return keys
}
