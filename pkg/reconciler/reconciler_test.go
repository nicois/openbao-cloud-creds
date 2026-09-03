package reconciler_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
)

type fakeCloudLister struct {
	entities []reconciler.UpstreamEntity
	// errOnID, when non-empty, makes DeleteEntity return an error for that ID
	// (and leave the entity in place), simulating a non-404 upstream delete
	// failure for one entity.
	errOnID string
	// deleted records ids in the order they were deleted, so a test can assert WHICH entities a
	// bounded pass chose rather than only how many.
	deleted []string
}

func (f *fakeCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	// Return a copy: real listers return a fresh slice from the upstream list
	// call, so the reconciler's iteration must not share a backing array with
	// the store that DeleteEntity mutates.
	out := make([]reconciler.UpstreamEntity, len(f.entities))
	copy(out, f.entities)
	return out, nil
}

func (f *fakeCloudLister) DeleteEntity(ctx context.Context, id string) error {
	if id == f.errOnID {
		return fmt.Errorf("simulated delete failure for %s", id)
	}
	f.deleted = append(f.deleted, id)
	for i, e := range f.entities {
		if e.ID == id {
			f.entities = append(f.entities[:i], f.entities[i+1:]...)
			return nil
		}
	}
	return nil
}

type fakeRegistry struct {
	known     map[string]bool
	callCount int
	err       error
}

func (f *fakeRegistry) OwnedIDs(_ context.Context) (map[string]struct{}, error) {
	f.callCount++
	if f.err != nil {
		return nil, f.err
	}
	set := make(map[string]struct{}, len(f.known))
	for id := range f.known {
		set[id] = struct{}{}
	}
	return set, nil
}

func TestDetectsOrphans(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "known-1", Name: "cloud-creds-role-a-lease1"},
			{ID: "orphan-1", Name: "cloud-creds-role-b-lease2"},
		},
	}
	registry := &fakeRegistry{known: map[string]bool{"known-1": true}}

	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  0,
		DryRun:            false,
	}, cloud, registry)

	result, err := r.Run(t.Context(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.OrphansFound) != 1 {
		t.Fatalf("expected 1 orphan, got %d", len(result.OrphansFound))
	}
	if result.OrphansFound[0] != "orphan-1" {
		t.Fatalf("unexpected orphan: %s", result.OrphansFound[0])
	}
}

func TestDryRunDoesNotDelete(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "orphan-1", Name: "cloud-creds-role-a-lease1"},
		},
	}
	registry := &fakeRegistry{known: map[string]bool{}}

	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  0,
		DryRun:            true,
	}, cloud, registry)

	result, err := r.Run(t.Context(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Deleted != 0 {
		t.Fatalf("expected 0 deletes in dry-run, got %d", result.Deleted)
	}
	if len(cloud.entities) != 1 {
		t.Fatal("entity should not have been deleted in dry-run")
	}
}

func TestRun_OnlyDeletesListedOrphans(t *testing.T) {
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		{ID: "orphan-1", Name: "cloud-creds-role-a-1"},
		{ID: "known-1", Name: "cloud-creds-role-a-2"},
	}}
	reg := &fakeRegistry{known: map[string]bool{"known-1": true}}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10}, cloud, reg)
	res, err := r.Run(t.Context(), time.Now())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(cloud.entities) != 1 || cloud.entities[0].ID != "known-1" {
		t.Fatalf("known entity deleted or orphan survived: %v", cloud.entities)
	}
	if res.Deleted != 1 {
		t.Fatalf("expected 1 delete, got %d", res.Deleted)
	}
}

func TestMaxDeletesPerPass(t *testing.T) {
	entities := make([]reconciler.UpstreamEntity, 15)
	for i := range entities {
		entities[i] = reconciler.UpstreamEntity{
			ID:   fmt.Sprintf("orphan-%d", i),
			Name: fmt.Sprintf("cloud-creds-role-x-lease%d", i),
		}
	}
	cloud := &fakeCloudLister{entities: entities}
	registry := &fakeRegistry{known: map[string]bool{}}

	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  0,
		DryRun:            false,
	}, cloud, registry)

	result, err := r.Run(t.Context(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Deleted != 10 {
		t.Fatalf("expected max 10 deletes, got %d", result.Deleted)
	}
	if !result.HitLimit {
		t.Fatal("expected HitLimit=true")
	}
}

// TestRun_DeleteErrorDoesNotAbortPass proves that a per-entity delete failure
// no longer aborts the whole pass (audit F5 defense-in-depth): the failing ID
// is recorded in Result.Errors and the reconciler continues to delete the
// remaining orphans.
func TestRun_DeleteErrorDoesNotAbortPass(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "orphan-1", Name: "cloud-creds-role-a-1"},
			{ID: "orphan-bad", Name: "cloud-creds-role-a-2"},
			{ID: "orphan-3", Name: "cloud-creds-role-a-3"},
		},
		errOnID: "orphan-bad",
	}
	reg := &fakeRegistry{known: map[string]bool{}}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10}, cloud, reg)

	res, err := r.Run(t.Context(), time.Now())
	if err != nil {
		t.Fatalf("a per-entity delete failure must not return a pass-level error, got: %v", err)
	}
	if res.Deleted != 2 {
		t.Fatalf("expected the 2 deletable orphans deleted, got %d", res.Deleted)
	}
	if len(res.Errors) != 1 || res.Errors[0] != "orphan-bad" {
		t.Fatalf("expected the failing ID in Errors, got %v", res.Errors)
	}
	// The failing entity survives; the other two are gone.
	if len(cloud.entities) != 1 || cloud.entities[0].ID != "orphan-bad" {
		t.Fatalf("expected only orphan-bad to survive, got %v", cloud.entities)
	}
}

// TestRun_FailsClosedWhenAgeUnconfirmable proves that with a ConfirmationHold
// set, an orphan whose CreatedAt is zero (age unconfirmable) is NOT deleted.
// This is the safety core: absent age info, do not delete.
func TestRun_FailsClosedWhenAgeUnconfirmable(t *testing.T) {
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		{ID: "orphan-zerotime", Name: "cloud-creds-role-a-1"}, // CreatedAt zero
	}}
	reg := &fakeRegistry{known: map[string]bool{}}
	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  1 * time.Hour,
	}, cloud, reg)

	res, err := r.Run(t.Context(), time.Now())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Deleted != 0 {
		t.Fatalf("fail-closed: expected 0 deletes for unconfirmable-age orphan, got %d", res.Deleted)
	}
	if len(cloud.entities) != 1 {
		t.Fatal("unconfirmable-age orphan must not be deleted")
	}
}

// TestRun_DeletesConfirmablyOldOrphan proves a CreatedAt older than the hold
// is still deleted (the precision path still works).
func TestRun_DeletesConfirmablyOldOrphan(t *testing.T) {
	now := time.Now()
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		{ID: "old-orphan", Name: "cloud-creds-role-a-1", CreatedAt: now.Add(-2 * time.Hour)},
	}}
	reg := &fakeRegistry{known: map[string]bool{}}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10, ConfirmationHold: 1 * time.Hour}, cloud, reg)
	res, err := r.Run(t.Context(), now)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Deleted != 1 {
		t.Fatalf("expected confirmably-old orphan deleted, got %d", res.Deleted)
	}
}

// TestRun_SkipsRecentConfirmableOrphan: CreatedAt within the hold => skip.
func TestRun_SkipsRecentConfirmableOrphan(t *testing.T) {
	now := time.Now()
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		{ID: "fresh-orphan", Name: "cloud-creds-role-a-1", CreatedAt: now.Add(-5 * time.Minute)},
	}}
	reg := &fakeRegistry{known: map[string]bool{}}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10, ConfirmationHold: 1 * time.Hour}, cloud, reg)
	res, err := r.Run(t.Context(), now)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Deleted != 0 {
		t.Fatalf("expected fresh orphan skipped, got %d", res.Deleted)
	}
}

func TestMinConfirmationHold(t *testing.T) {
	if reconciler.MinConfirmationHold != 5*time.Minute {
		t.Fatalf("MinConfirmationHold: expected 5m, got %v", reconciler.MinConfirmationHold)
	}
}

func TestRun_CallsOwnedIDsExactlyOnce(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "a", Name: "cloud-creds-r-1"},
			{ID: "b", Name: "cloud-creds-r-2"},
			{ID: "c", Name: "cloud-creds-r-3"},
		},
	}
	reg := &fakeRegistry{known: map[string]bool{"a": true}}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10}, cloud, reg)
	if _, err := r.Run(t.Context(), time.Now()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg.callCount != 1 {
		t.Fatalf("OwnedIDs called %d times, want exactly 1 (O(N), not O(N^2))", reg.callCount)
	}
}

func TestRun_OwnedIDsErrorIsFailClosed(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "orphan-1", Name: "cloud-creds-r-1"},
		},
	}
	reg := &fakeRegistry{err: errors.New("storage unreachable")}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10}, cloud, reg)
	res, err := r.Run(t.Context(), time.Now())
	if err == nil {
		t.Fatal("expected Run to return the OwnedIDs error (fail-closed), got nil")
	}
	if res != nil && res.Deleted != 0 {
		t.Fatalf("fail-closed must delete nothing, deleted %d", res.Deleted)
	}
	// fakeCloudLister.DeleteEntity removes the entity from its slice, so a
	// fail-closed pass must leave orphan-1 present (it was never deleted).
	if len(cloud.entities) != 1 {
		t.Fatalf("fail-closed must not delete; entities now %v", cloud.entities)
	}
}

// TestExpiredOrphansDoNotConsumeTheBudgetForLiveOnes: the per-pass cap bounds deletion that was
// INFERRED, and that reasoning does not apply to a credential the cloud has already expired —
// nothing can use it, so deleting it cannot break a workload.
//
// It used to be one shared budget spent in listing order, and a listing is sorted oldest-first, so
// expired credentials come FIRST. A leak of expired clutter therefore consumed the entire budget and
// live orphans — the ones that are actual exposures — waited for the next pass.
func TestExpiredOrphansDoNotConsumeTheBudgetForLiveOnes(t *testing.T) {
	now := time.Now()
	old := now.Add(-24 * time.Hour)

	// Ordered as a lister sorting created_at ascending delivers them: expired first, being oldest.
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		{ID: "expired-1", Name: "cloud-creds-role-x-a", CreatedAt: old, ExpiresAt: now.Add(-2 * time.Hour)},
		{ID: "expired-2", Name: "cloud-creds-role-x-b", CreatedAt: old, ExpiresAt: now.Add(-time.Hour)},
		{ID: "live-1", Name: "cloud-creds-role-x-c", CreatedAt: old, ExpiresAt: now.Add(time.Hour)},
		{ID: "live-2", Name: "cloud-creds-role-x-d", CreatedAt: old},
	}}
	registry := &fakeRegistry{known: map[string]bool{}}

	// A budget of two: enough for the live pair, and the expired pair must not eat into it.
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 2}, cloud, registry)
	result, err := r.Run(t.Context(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Deleted != 4 {
		t.Fatalf("deleted %d of 4 (order %v); two expired orphans must not consume the budget the "+
			"two live ones need", result.Deleted, cloud.deleted)
	}
	if result.Expired != 2 {
		t.Errorf("Expired=%d, want 2; an operator seeing 4 deletions against a cap of 2 needs this "+
			"field to see that half of them could not have broken anything", result.Expired)
	}
	if result.HitLimit {
		t.Errorf("HitLimit was set though every orphan was deleted within its own budget")
	}
	// Oldest-first within the pass: no reordering, just separate accounting.
	want := []string{"expired-1", "expired-2", "live-1", "live-2"}
	if len(cloud.deleted) != len(want) {
		t.Fatalf("deletion order %v, want %v", cloud.deleted, want)
	}
	for i := range want {
		if cloud.deleted[i] != want[i] {
			t.Fatalf("deletion order %v, want the listing's own oldest-first order %v",
				cloud.deleted, want)
		}
	}
}

// TestEachClassIsStillBounded: separate budgets, not an exemption. "Expired" is derived data — a
// clock hours fast, or a lister misreading the upstream's expiry field, reclassifies live
// credentials as inert — so an unbounded exemption would delete them without limit. The runaway
// bound stays; it is just per class.
func TestEachClassIsStillBounded(t *testing.T) {
	now := time.Now()
	old := now.Add(-24 * time.Hour)

	entities := make([]reconciler.UpstreamEntity, 0, 12)
	for i := range 6 {
		entities = append(entities, reconciler.UpstreamEntity{
			ID: fmt.Sprintf("expired-%d", i), Name: fmt.Sprintf("cloud-creds-role-x-e%d", i),
			CreatedAt: old, ExpiresAt: now.Add(-time.Hour),
		})
	}
	for i := range 6 {
		entities = append(entities, reconciler.UpstreamEntity{
			ID: fmt.Sprintf("live-%d", i), Name: fmt.Sprintf("cloud-creds-role-x-l%d", i),
			CreatedAt: old, ExpiresAt: now.Add(time.Hour),
		})
	}
	cloud := &fakeCloudLister{entities: entities}

	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 2},
		cloud, &fakeRegistry{known: map[string]bool{}})
	result, err := r.Run(t.Context(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Deleted != 4 || result.Expired != 2 {
		t.Fatalf("deleted=%d expired=%d (order %v), want 4 and 2 — two per class and no more",
			result.Deleted, result.Expired, cloud.deleted)
	}
	if !result.HitLimit {
		t.Error("HitLimit must be set: eight orphans were left undeleted because both budgets ran out")
	}
	// The scan continues past an exhausted budget, so what remains is still reported.
	if len(result.OrphansFound) != 12 {
		t.Errorf("OrphansFound has %d of 12; a spent budget must not stop the pass counting what is "+
			"left, which is how an operator sees the leak growing", len(result.OrphansFound))
	}
}

// TestUnknownExpiryIsTreatedAsLive pins the direction of the default. Most clouds' listings say
// nothing about expiry, and the four that hard-revoke issue credentials with no upstream expiry at
// all — so treating unknown as inert would put nearly everything on the housekeeping budget and
// quietly drop the distinction this all exists for.
func TestUnknownExpiryIsTreatedAsLive(t *testing.T) {
	now := time.Now()
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		{ID: "unknown-1", Name: "cloud-creds-role-x-a", CreatedAt: now.Add(-time.Hour)},
		{ID: "unknown-2", Name: "cloud-creds-role-x-b", CreatedAt: now.Add(-time.Hour)},
	}}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 1},
		cloud, &fakeRegistry{known: map[string]bool{}})
	result, err := r.Run(t.Context(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Deleted != 1 || result.Expired != 0 || !result.HitLimit {
		t.Errorf("deleted=%d expired=%d hitLimit=%v (order %v); an entity whose expiry is unknown "+
			"must be charged to the LIVE budget, so a cap of one deletes exactly one",
			result.Deleted, result.Expired, result.HitLimit, cloud.deleted)
	}
}

// TestWorkerHoldClearsTheFloor: the timer-driven hold must be at least the floor the operator-facing
// path clamps to. The two are set independently, and a worker with the weaker guard would be the
// dangerous one — it runs unattended, and it is the pass that races a node handover.
func TestWorkerHoldClearsTheFloor(t *testing.T) {
	if reconciler.WorkerConfirmationHold < reconciler.MinConfirmationHold {
		t.Fatalf("WorkerConfirmationHold is %v, below the manual path's floor of %v",
			reconciler.WorkerConfirmationHold, reconciler.MinConfirmationHold)
	}
}

// TestAConfirmationHoldSurvivesTheSeparateBudgets: the two delete budgets changed which entities a
// pass reaches, so the age guard is re-asserted against the new loop. An expired orphan is still an
// orphan the mount inferred, and a young one must be left alone whichever budget would fund it —
// otherwise the housekeeping budget would become a way around the guard.
func TestAConfirmationHoldSurvivesTheSeparateBudgets(t *testing.T) {
	now := time.Now()
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		// Created a minute ago and already expired: a short-lived credential mid-issue, which is
		// exactly what the create-then-track window looks like from the outside.
		{ID: "young-expired", Name: "cloud-creds-role-x-a", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(-time.Second)},
		{ID: "young-live", Name: "cloud-creds-role-x-b", CreatedAt: now.Add(-time.Minute)},
		{ID: "old-expired", Name: "cloud-creds-role-x-c", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
	}}
	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  reconciler.WorkerConfirmationHold,
	}, cloud, &fakeRegistry{known: map[string]bool{}})

	result, err := r.Run(t.Context(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cloud.deleted) != 1 || cloud.deleted[0] != "old-expired" {
		t.Fatalf("deleted %v; only the orphan older than the hold may go — a credential a minute "+
			"old may still be mid-issue on this node or newly tracked on one that just handed over",
			cloud.deleted)
	}
	if result.Expired != 1 {
		t.Errorf("Expired=%d, want 1", result.Expired)
	}
}
