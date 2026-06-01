package credentialakamai

import (
	"context"
	"net/http"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// sweepRetiredMinters deletes the upstream API client of every minter that has
// been retired longer than minter_retire_grace, then drops it from its set. It
// is keyed strictly off RetiredAt (separate from the conservative orphan
// reconciler) so an operator-initiated rotation reliably reclaims the old
// upstream API client after the grace window — long enough that every raft node
// has reloaded the set and stopped selecting the retired minter.
//
// now is a parameter for testability. The whole sweep runs under rotateSweepMu
// (mirroring the rotate endpoint) so it never interleaves with a rotation's
// read-modify-write of a set; b.mu is taken only inside the small helpers
// (persistSet, clientForMinter), never across the body while rotateSweepMu is
// held, so no AB-BA deadlock with b.mu exists.
//
// client_id-for-retire: deleting the API client needs the OLD client's upstream
// clientId. Rotation successors record their clientId in
// RotationParams[client_id], so once a successor is itself retired it can be
// deleted precisely. An operator-provided ORIGINAL minter may have no recorded
// clientId; for those the sweep cannot delete the upstream client precisely — it
// logs a warning and still drops the minter from the set after the grace (so
// issuance is never affected), leaving the upstream client for manual cleanup.
func (b *backend) sweepRetiredMinters(ctx context.Context, storage logical.Storage, now time.Time) error {
	b.rotateSweepMu.Lock()
	defer b.rotateSweepMu.Unlock()

	grace := b.retireGrace()

	names, err := storage.List(ctx, "minter-sets/")
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := b.sweepSet(ctx, storage, name, now, grace); err != nil {
			b.Logger().Warn("retired-sweep: set failed; continuing",
				"cloud", cloudName, "minter_set", name, "error", err)
		}
	}
	return nil
}

// retireGrace returns the configured retirement grace, defaulting to the
// minimum minter gap when config is unset.
func (b *backend) retireGrace() time.Duration {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.config != nil && b.config.MinterRetireGrace > 0 {
		return b.config.MinterRetireGrace
	}
	return cloudconfig.MinMinterGap
}

// sweepSet processes one set: it deletes the upstream API client and drops every
// minter whose retirement has aged past the grace, then persists if anything
// changed.
func (b *backend) sweepSet(ctx context.Context, storage logical.Storage, name string, now time.Time, grace time.Duration) error {
	set, err := b.readSet(ctx, storage, name)
	if err != nil {
		return err
	}
	if set == nil {
		return nil
	}

	kept := make([]cloudconfig.Minter, 0, len(set.Minters))
	changed := false
	for i := range set.Minters {
		m := set.Minters[i]
		if m.Retired && now.After(m.RetiredAt.Add(grace)) {
			if b.deleteRetiredUpstream(ctx, m) {
				changed = true
				continue // drop from the set
			}
			// delete failed (non-404): keep the entry and retry next pass.
		}
		kept = append(kept, m)
	}

	if !changed {
		return nil
	}
	set.Minters = kept
	return b.persistSet(ctx, storage, set)
}

// deleteRetiredUpstream deletes a retired minter's upstream API client. It
// returns true when the entry may be dropped from the set: the client was
// deleted, was already gone (404), or cannot be deleted precisely (no recorded
// client_id — warn and drop anyway so issuance isn't affected). It returns false
// only on a real delete failure, so the entry is kept for a later retry.
func (b *backend) deleteRetiredUpstream(ctx context.Context, m cloudconfig.Minter) bool {
	clientID := m.RotationParams[fieldClientID]
	if clientID == "" {
		b.Logger().Warn("retired-sweep: minter has no recorded upstream client_id; "+
			"dropping from set after grace, upstream api client needs manual cleanup",
			"cloud", cloudName, "minter_id", m.ID)
		return true
	}

	client, err := b.clientForMinter(m)
	if err != nil {
		b.Logger().Warn("retired-sweep: cannot build client for retired minter; "+
			"dropping from set after grace, upstream api client needs manual cleanup",
			"cloud", cloudName, "minter_id", m.ID, "error", err)
		return true
	}
	status, err := client.DeleteClient(ctx, clientID)
	if err != nil && status != http.StatusNotFound {
		b.Logger().Warn("retired-sweep: upstream delete failed; will retry next pass",
			"cloud", cloudName, "minter_id", m.ID, "status", status, "error", err)
		return false
	}
	b.Logger().Info("retired-sweep: deleted upstream api client of retired minter",
		"cloud", cloudName, "minter_id", m.ID)
	return true
}
