package mintledger

import (
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestLedgerMakesAnOrphanReclaimable is the regression guard for A5. On clouds whose
// list API reports no creation time, the reconciler's fail-closed age guard skipped
// every entity forever — so nothing was ever reclaimable, on two hard-revoke clouds
// whose credentials have no upstream expiry, while /reconcile reported
// orphans_found: 0.
func TestLedgerMakesAnOrphanReclaimable(t *testing.T) {
	storage := &logical.InmemStorage{}
	ctx := t.Context()
	minted := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	if err := Record(ctx, storage, "key-123", minted); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := CreatedAt(ctx, storage, "key-123"); !got.Equal(minted) {
		t.Errorf("CreatedAt = %v, want %v: without it the reconciler cannot confirm the age and will "+
			"never delete this credential", got, minted)
	}
}

// Anything this mount did not mint stays unconfirmable, and therefore survives. That
// is what keeps the owner-tag invariant intact: the ledger adds reclaimability for
// our own credentials without weakening the guard protecting everyone else's.
func TestUnknownEntityStaysUnconfirmable(t *testing.T) {
	storage := &logical.InmemStorage{}
	if got := CreatedAt(t.Context(), storage, "someone-elses-key"); !got.IsZero() {
		t.Errorf("CreatedAt = %v for an id we never minted, want the zero time so the age guard "+
			"protects it", got)
	}
}

// The ledger must NOT be keyed to the lease lifecycle: the leak worth cleaning up is
// exactly the one where the upstream delete failed and the tracking entry went away.
// Pruning is therefore by age alone.
func TestPruneRemovesOnlyExpiredEntries(t *testing.T) {
	storage := &logical.InmemStorage{}
	ctx := t.Context()
	now := time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC)

	if err := Record(ctx, storage, "fresh", now.Add(-time.Hour)); err != nil {
		t.Fatalf("Record fresh: %v", err)
	}
	if err := Record(ctx, storage, "ancient", now.Add(-2*Retention)); err != nil {
		t.Fatalf("Record ancient: %v", err)
	}

	pruned, err := Prune(ctx, storage, now)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 1 {
		t.Errorf("pruned %d entries, want 1", pruned)
	}
	if CreatedAt(ctx, storage, "fresh").IsZero() {
		t.Error("pruned an entry still within retention; a recent credential would become " +
			"unreclaimable again")
	}
	if !CreatedAt(ctx, storage, "ancient").IsZero() {
		t.Error("kept an entry past retention; the keyspace would grow without bound")
	}
}

// Retention must exceed any confirmation hold a caller configures plus the reconcile
// cadence, or an orphan could age out of the ledger before a pass looks at it — which
// silently restores the unreclaimable state the ledger exists to fix.
func TestRetentionOutlivesAnyConfirmationHold(t *testing.T) {
	const longestHoldPlusCadence = 24*time.Hour + time.Hour
	if Retention <= longestHoldPlusCadence {
		t.Errorf("Retention %s does not comfortably exceed %s", Retention, longestHoldPlusCadence)
	}
}
