package credentialazure

import (
	"context"
	"net/http"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// sweepRetiredMinters deletes the upstream credential of every minter that has
// been retired longer than minter_retire_grace, then drops it from its set. It
// is keyed strictly off RetiredAt (separate from the conservative orphan
// reconciler) so an operator-initiated rotation reliably reclaims the old
// upstream secret after the grace window — long enough that every raft node has
// reloaded the set and stopped selecting the retired minter.
//
// now is a parameter for testability. The whole sweep runs under rotateSweepMu
// (mirroring the rotate endpoint) so it never interleaves with a rotation's
// read-modify-write of a set; b.mu is taken only inside the small helpers
// (loadMinterSet via persistSet, newClientForMinter), never across the body
// while rotateSweepMu is held, so no AB-BA deadlock with b.mu exists.
//
// keyId-for-retire: removePassword needs the OLD secret's upstream keyId.
// Rotation successors record their keyId in RotationParams[key_id], so once a
// successor is itself retired it can be deleted precisely. An operator-provided
// ORIGINAL minter may have no recorded keyId; for those the sweep cannot delete
// the upstream secret precisely — it logs a warning and still drops the minter
// from the set after the grace (so issuance is never affected), leaving the
// upstream secret for manual cleanup.
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

// sweepSet processes one set: it removes the upstream secret and drops every
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
			// removePassword failed (non-404): keep the entry and retry next pass.
		}
		kept = append(kept, m)
	}

	if !changed {
		return nil
	}
	set.Minters = kept
	return b.persistSet(ctx, storage, set)
}

// deleteRetiredUpstream removes a retired minter's upstream secret. It returns
// true when the entry may be dropped from the set: the secret was deleted, was
// already gone (404), or cannot be deleted precisely (no recorded keyId — warn
// and drop anyway so issuance isn't affected). It returns false only on a real
// removePassword failure, so the entry is kept for a later retry.
func (b *backend) deleteRetiredUpstream(ctx context.Context, m cloudconfig.Minter) bool {
	keyID := m.RotationParams[fieldKeyID]
	appObjectID := m.RotationParams[fieldAppObjectID]
	if keyID == "" || appObjectID == "" {
		b.Logger().Warn("retired-sweep: minter has no recorded upstream keyId; "+
			"dropping from set after grace, upstream secret needs manual cleanup",
			"cloud", cloudName, "minter_id", m.ID)
		return true
	}

	client := b.newClientForMinter(m)
	status, err := client.RemovePassword(ctx, appObjectID, keyID)
	if err != nil && status != http.StatusNotFound {
		b.Logger().Warn("retired-sweep: upstream removePassword failed; will retry next pass",
			"cloud", cloudName, "minter_id", m.ID, "status", status, "error", err)
		return false
	}
	b.Logger().Info("retired-sweep: deleted upstream credential of retired minter",
		"cloud", cloudName, "minter_id", m.ID)
	return true
}
