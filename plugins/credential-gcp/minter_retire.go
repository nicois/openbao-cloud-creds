package credentialgcp

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// sweepRetiredMinters deletes the upstream SA key of every minter that has been
// retired longer than minter_retire_grace, then drops it from its set. It is
// keyed strictly off RetiredAt (separate from the conservative tracking-entry
// prune) so an operator-initiated rotation reliably reclaims the old SA key
// after the grace window — long enough that every raft node has reloaded the set
// and stopped selecting the retired minter.
//
// now is a parameter for testability. The whole sweep runs under rotateSweepMu
// (mirroring the rotate endpoint) so it never interleaves with a rotation's
// read-modify-write of a set; b.mu is taken only inside the small helpers
// (persistSet, buildSAKeyClient), never across the body while rotateSweepMu is
// held, so no AB-BA deadlock with b.mu exists.
//
// key-name-for-retire: DeleteKey needs the OLD key's upstream resource name.
// Rotation successors record their key name in RotationParams[key_name], so once
// a successor is itself retired it can be deleted precisely. An operator-provided
// ORIGINAL minter may have no recorded key name; for those the sweep cannot
// delete the upstream key precisely — it logs a warning and still drops the
// minter from the set after the grace (so issuance is never affected), leaving
// the upstream key for manual cleanup.
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

// retireGrace returns the configured retirement grace, defaulting to the minimum
// minter gap when config is unset.
func (b *backend) retireGrace() time.Duration {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.config != nil && b.config.MinterRetireGrace > 0 {
		return b.config.MinterRetireGrace
	}
	return cloudconfig.MinMinterGap
}

// sweepSet processes one set: it deletes the upstream SA key and drops every
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
			// DeleteKey failed (non-404): keep the entry and retry next pass.
		}
		kept = append(kept, m)
	}

	if !changed {
		return nil
	}
	set.Minters = kept
	return b.persistSet(ctx, storage, set)
}

// deleteRetiredUpstream deletes a retired minter's upstream SA key. It returns
// true when the entry may be dropped from the set: the key was deleted, was
// already gone (404), or cannot be deleted precisely (no recorded key name —
// warn and drop anyway so issuance isn't affected). It returns false only on a
// real DeleteKey failure, so the entry is kept for a later retry.
func (b *backend) deleteRetiredUpstream(ctx context.Context, m cloudconfig.Minter) bool {
	keyName := m.RotationParams[fieldKeyName]
	if keyName == "" {
		b.Logger().Warn("retired-sweep: minter has no recorded upstream SA key name; "+
			"dropping from set after grace, upstream key needs manual cleanup",
			"cloud", cloudName, "minter_id", m.ID)
		return true
	}

	b.mu.RLock()
	client := b.buildSAKeyClient(m)
	b.mu.RUnlock()
	if err := client.DeleteKey(ctx, keyName); err != nil && !isSAKeyNotFound(err) {
		b.Logger().Warn("retired-sweep: upstream DeleteKey failed; will retry next pass",
			"cloud", cloudName, "minter_id", m.ID, "error", err)
		return false
	}
	b.Logger().Info("retired-sweep: deleted upstream SA key of retired minter",
		"cloud", cloudName, "minter_id", m.ID)
	return true
}
