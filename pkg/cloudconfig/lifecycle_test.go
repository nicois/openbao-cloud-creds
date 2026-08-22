package cloudconfig

import (
	"testing"
	"time"
)

// TestPreserveLifecycleKeepsRetirement is the regression guard for A13. A minter-set
// write reconstructs each minter from the request, which carries no retired /
// retired_at — those are plugin bookkeeping. Persisting the set wholesale therefore
// un-retired a rotated-out minter: it re-entered issuance from a credential
// scheduled for deletion, and the retired-sweep (keyed off RetiredAt) never fired
// again, so the old mint-capable upstream credential lived forever.
func TestPreserveLifecycleKeepsRetirement(t *testing.T) {
	retiredAt := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	created := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC)

	stored := &MinterSet{Name: "primary", Minters: []Minter{{
		ID: "old", NeverExpires: true, CreatedAt: created,
		Retired: true, RetiredAt: retiredAt,
		RotationParams: map[string]string{"token_id": "upstream-old"},
	}}}

	// What a write reconstructs from the request body: no retirement, no created_at.
	incoming := []Minter{{ID: "old", Token: "t", NeverExpires: true}}

	got := PreserveLifecycle(incoming, stored, now)
	if len(got) != 1 {
		t.Fatalf("expected 1 minter, got %d", len(got))
	}
	if !got[0].Retired {
		t.Error("a minter-set write un-retired a rotated-out minter: it becomes selectable again " +
			"from a credential scheduled for deletion (A13)")
	}
	if !got[0].RetiredAt.Equal(retiredAt) {
		t.Errorf("RetiredAt was reset to %v (was %v): the retired-sweep is keyed off it, so the old "+
			"upstream credential would never be deleted", got[0].RetiredAt, retiredAt)
	}
	if !got[0].CreatedAt.Equal(created) {
		t.Errorf("CreatedAt was re-stamped to %v (was %v): the age gauge resets to zero on a minter "+
			"that is years old", got[0].CreatedAt, created)
	}
	if got[0].RotationParams["token_id"] != "upstream-old" {
		t.Error("RotationParams were dropped; the retired-sweep and the reconciler's owned-set both " +
			"read the recorded upstream id from them")
	}
}

// A genuinely new minter is stamped now, so the age gauge starts from the right place.
func TestPreserveLifecycleStampsNewMinters(t *testing.T) {
	now := time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC)
	got := PreserveLifecycle([]Minter{{ID: "fresh", NeverExpires: true}}, nil, now)
	if !got[0].CreatedAt.Equal(now) {
		t.Errorf("new minter CreatedAt is %v, want %v", got[0].CreatedAt, now)
	}
	if got[0].Retired {
		t.Error("a new minter must not be retired")
	}
}

func TestValidateMinterIDs(t *testing.T) {
	if err := ValidateMinterIDs([]Minter{{ID: "a"}, {ID: "a"}}); err == nil {
		t.Error("duplicate minter ids accepted: they satisfy the >=2-expiring rule and then collapse " +
			"to one on load, producing exactly the configuration RSK-005 forbids")
	}
	if err := ValidateMinterIDs([]Minter{{ID: ""}}); err == nil {
		t.Error("an empty minter id accepted")
	}
	if err := ValidateMinterIDs([]Minter{{ID: "<nil>"}}); err == nil {
		t.Error(`the literal "<nil>" accepted — that is what a missing id formats to, and it ` +
			"becomes a real minter id")
	}
	if err := ValidateMinterIDs([]Minter{{ID: "a"}, {ID: "b"}}); err != nil {
		t.Errorf("valid ids rejected: %v", err)
	}
}
