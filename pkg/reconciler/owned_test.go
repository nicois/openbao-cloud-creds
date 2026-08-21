package reconciler

import (
	"context"
	"testing"
	"time"
)

type fixedLister struct {
	entities []UpstreamEntity
	deleted  []string
}

func (l *fixedLister) ListTaggedEntities(_ context.Context) ([]UpstreamEntity, error) {
	return l.entities, nil
}

func (l *fixedLister) DeleteEntity(_ context.Context, id string) error {
	l.deleted = append(l.deleted, id)
	return nil
}

type fixedRegistry struct {
	owned map[string]struct{}
	err   error
}

func (r *fixedRegistry) OwnedIDs(_ context.Context) (map[string]struct{}, error) {
	return r.owned, r.err
}

// TestOwnedMinterSurvivesAPass is the regression guard for A1: a rotation
// successor is owner-prefixed, so the lister selects it, and it is NOT a lease —
// so before the owned-set included minters, the reconciler deleted the only
// mint-capable credential the set had.
func TestOwnedMinterSurvivesAPass(t *testing.T) {
	old := time.Now().Add(-24 * time.Hour)
	lister := &fixedLister{entities: []UpstreamEntity{
		{ID: "minter-successor-1", Name: "cloud-creds-minter-primary-rot-abc", CreatedAt: old},
		{ID: "real-orphan-1", Name: "cloud-creds-approle-req99", CreatedAt: old},
	}}
	registry := &fixedRegistry{owned: map[string]struct{}{"minter-successor-1": {}}}

	_, err := New(Config{MaxDeletesPerPass: 10, ConfirmationHold: time.Hour}, lister, registry).
		Run(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, id := range lister.deleted {
		if id == "minter-successor-1" {
			t.Error("the reconciler deleted a minter credential the mount owns. That destroys the " +
				"set's mint-capable credential and stops issuance, rotation and revocation (A1).")
		}
	}
	if len(lister.deleted) != 1 || lister.deleted[0] != "real-orphan-1" {
		t.Errorf("deleted %v, want exactly [real-orphan-1]: a genuine orphan must still be reclaimed, "+
			"or the fix has simply disabled the reconciler", lister.deleted)
	}
}

// TestIncompleteOwnedSetDeletesNothing pins the fail-closed contract that makes
// the fix above safe: if we cannot enumerate what we own, we must not guess.
func TestIncompleteOwnedSetDeletesNothing(t *testing.T) {
	lister := &fixedLister{entities: []UpstreamEntity{
		{ID: "x", Name: "cloud-creds-r-1", CreatedAt: time.Now().Add(-24 * time.Hour)},
	}}
	registry := &fixedRegistry{err: context.DeadlineExceeded}

	if _, err := New(Config{MaxDeletesPerPass: 10}, lister, registry).
		Run(context.Background(), time.Now()); err == nil {
		t.Fatal("Run succeeded with an unusable owned-set; it must abort")
	}
	if len(lister.deleted) != 0 {
		t.Errorf("deleted %v after failing to enumerate the owned-set; must be nothing", lister.deleted)
	}
}
