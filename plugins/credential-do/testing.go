package credentialdo

import (
	"context"
	"errors"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// WorkersRunning reports whether this backend's background workers are running.
//
// Exported as a test seam so the shared conformance suite can assert what KI-007
// was actually about. Its guard asserted only that Initialize returned nil twice
// and that issuance then worked — but framework.Backend.Initialize returns nil
// when InitializeFunc is unset, and issuance never needed a worker, so deleting
// InitializeFunc from all ten plugins left the category green (A11 in
// docs/audit-2026-08-22.md). Workers are the only thing that recovers a minter
// from AuthFailing, so "no workers" is not a telemetry gap; it wedges a minter
// permanently.
func WorkersRunning(b logical.Backend) bool {
	backend, ok := b.(*backend)
	if !ok {
		return false
	}
	// workerMgr is guarded by workerLifecycleMu: startWorkers replaces it and
	// stopWorkersLocked clears it, both from a goroutine Initialize spawns. Reading
	// it unlocked is a data race, and the race detector says so.
	backend.workerLifecycleMu.Lock()
	defer backend.workerLifecycleMu.Unlock()
	if backend.workerMgr == nil {
		return false
	}
	return backend.workerMgr.Running()
}

// errNotThisBackend is returned by the seams below when handed something other than this
// plugin's backend — a wrong-plugin harness must fail loudly rather than silently assert
// nothing.
var errNotThisBackend = errors.New("not a credential-do backend")

// The three seams below exist because the rotated Spaces type's whole contract is about the
// passage of DAYS: a credential re-served for 90 days, replaced, and the replaced one deleted
// 48 hours later. Nothing can be asserted about that by waiting, and a fake clock would prove
// the test's arithmetic rather than the plugin's. So a test moves the stored deadlines into
// the past — the same durable state a restart would rehydrate — and then makes the ordinary
// call. Every seam edits storage only; none of them reaches into the rotation logic.

// ForceRotationDue backdates the role's shared key so it is overdue for rotation. Both
// timestamps move, because the schedule is re-clamped to minted_at + rotation_period on every
// read and a stale rotate_at alone would be ignored.
func ForceRotationDue(ctx context.Context, b logical.Backend, storage logical.Storage, roleName string) error {
	backend, ok := b.(*backend)
	if !ok {
		return errNotThisBackend
	}
	backend.sharedSpacesMu.Lock()
	defer backend.sharedSpacesMu.Unlock()

	state, err := loadSharedSpacesState(ctx, storage, roleName)
	if err != nil {
		return err
	}
	if state.Current == nil {
		return errors.New("the role has no shared credential to rotate")
	}
	past := time.Now().Add(-time.Second)
	state.Current.RotateAt = past
	state.Current.MintedAt = past
	return saveSharedSpacesState(ctx, storage, roleName, state)
}

// ForceOverlapExpired brings forward the deletion deadline of every key the role has retired,
// so the next sweep is entitled to delete them.
func ForceOverlapExpired(ctx context.Context, b logical.Backend, storage logical.Storage, roleName string) error {
	backend, ok := b.(*backend)
	if !ok {
		return errNotThisBackend
	}
	backend.sharedSpacesMu.Lock()
	defer backend.sharedSpacesMu.Unlock()

	state, err := loadSharedSpacesState(ctx, storage, roleName)
	if err != nil {
		return err
	}
	if len(state.Retiring) == 0 {
		return errors.New("the role has no retiring credential")
	}
	past := time.Now().Add(-time.Second)
	for i := range state.Retiring {
		state.Retiring[i].DeleteAt = past
	}
	return saveSharedSpacesState(ctx, storage, roleName, state)
}

// SweepSharedSpacesKeys runs exactly one pass of the shared-key worker inline. The same
// function the worker calls on its timer, so a test proves the pass rather than a
// test-only reimplementation of it.
func SweepSharedSpacesKeys(ctx context.Context, b logical.Backend, storage logical.Storage) error {
	backend, ok := b.(*backend)
	if !ok {
		return errNotThisBackend
	}
	return backend.sweepSharedSpacesKeys(ctx, storage)
}
