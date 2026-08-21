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

func (f *fakeRegistry) KnownIDs(_ context.Context) (map[string]struct{}, error) {
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

func TestRun_CallsKnownIDsExactlyOnce(t *testing.T) {
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
		t.Fatalf("KnownIDs called %d times, want exactly 1 (O(N), not O(N^2))", reg.callCount)
	}
}

func TestRun_KnownIDsErrorIsFailClosed(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "orphan-1", Name: "cloud-creds-r-1"},
		},
	}
	reg := &fakeRegistry{err: errors.New("storage unreachable")}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10}, cloud, reg)
	res, err := r.Run(t.Context(), time.Now())
	if err == nil {
		t.Fatal("expected Run to return the KnownIDs error (fail-closed), got nil")
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
