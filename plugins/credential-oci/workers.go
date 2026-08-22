package credentialoci

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/worker"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) startWorkers(ctx context.Context, storage logical.Storage) {
	b.workerLifecycleMu.Lock()
	defer b.workerLifecycleMu.Unlock()

	b.stopWorkersLocked()

	b.mu.RLock()
	cfg := b.config
	b.mu.RUnlock()

	if cfg == nil {
		// A mount can reach this with no config written: minter-set and role writes
		// succeed without one, endpoints default, and the capability gate treats a
		// nil config as verification-enabled. Returning here meant such a mount
		// issued credentials happily with NO health check, metrics flush, reconciler
		// or retired-sweep — and since a successful health check is the only exit
		// from AuthFailing, one transient blip then withdrew a minter permanently
		// (A14 in docs/audit-2026-08-22.md).
		//
		// Defaults are the honest behaviour: the operator who never wrote config did
		// not ask for "no background work", they just did not express a preference.
		cfg = cloudconfig.DefaultConfig(cloudName)
		b.Logger().Info("starting workers with default intervals: no config has been written",
			"cloud", cloudName, "reconcile_cadence", cfg.ReconcileCadence)
	}

	wm := worker.New(worker.WithErrorHandler(b.workerErrorHandler()))

	wm.Register("health-check", healthCheckInterval, worker.Opts{}, b.healthCheckWorker)

	// Rotation worker: checks all roles for slots needing rotation
	rotationInterval := 1 * time.Hour
	rEntry, err := storage.Get(ctx, "config/rotation_check_interval")
	if err == nil && rEntry != nil {
		var d time.Duration
		if err := json.Unmarshal(rEntry.Value, &d); err == nil && d > 0 {
			rotationInterval = d
		}
	}

	wm.Register("rotation", rotationInterval, worker.Opts{}, func(ctx context.Context) error {
		return b.rotationWorker(ctx, storage)
	})

	// Reconciler (with bootstrap delay to avoid deleting during startup)
	wm.Register("reconciler", cfg.ReconcileCadence, worker.Opts{
		InitialDelay: cfg.BootstrapDelay,
	}, func(ctx context.Context) error {
		return b.reconcileWorker(ctx, storage)
	})

	workerCtx, cancel := context.WithCancel(ctx)

	b.mu.Lock()
	b.workerMgr = wm
	b.workerCancel = cancel
	b.mu.Unlock()

	wm.Start(workerCtx)
}

// stopWorkersLocked tears down the running worker manager. Callers MUST hold
// b.workerLifecycleMu so this never overlaps a concurrent startWorkers that is
// still inside wm.Start().
func (b *backend) stopWorkersLocked() {
	b.mu.Lock()
	cancel := b.workerCancel
	wm := b.workerMgr
	b.workerCancel = nil
	b.workerMgr = nil
	b.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if wm != nil {
		wm.Wait()
	}
}

// stopWorkers drains the worker manager under the lifecycle mutex and cancels
// the backend base context, so worker goroutines cannot outlive the backend.
// Safe to call from framework.Backend.Clean (backend unmount/reload). Lock
// order matches startWorkers: workerLifecycleMu, then (inside
// stopWorkersLocked) b.mu — no AB-BA path exists.
func (b *backend) stopWorkers() {
	b.workerLifecycleMu.Lock()
	defer b.workerLifecycleMu.Unlock()
	b.stopWorkersLocked()
	if b.baseCancel != nil {
		b.baseCancel()
	}
}

// rotationWorker checks all roles for slots whose next_rotation_at has passed,
// and rotates them.
func (b *backend) rotationWorker(ctx context.Context, storage logical.Storage) error {
	roleNames, err := storage.List(ctx, "roles/")
	if err != nil {
		return err
	}

	now := time.Now()
	rolesChecked := 0

	for _, roleName := range roleNames {
		role, ok := loadRole(ctx, storage, roleName)
		if !ok || role.Disabled {
			continue
		}

		rolesChecked++
		b.rotateDueSlots(ctx, storage, role, now)
	}

	emitRotationCheckCompleted(rolesChecked)
	return nil
}

// rotateDueSlots rotates every active slot of the role whose next_rotation_at
// is in the past as of now. Rotation failures are logged and skipped, matching
// the original inline behavior.
func (b *backend) rotateDueSlots(ctx context.Context, storage logical.Storage, role *ociRole, now time.Time) {
	for i := 0; i < role.SlotCount; i++ {
		s, err := loadSlot(ctx, storage, role.Name, i)
		if err != nil || s == nil {
			continue
		}
		if s.State == slotActive && now.After(s.NextRotationAt) {
			if err := b.rotateSlot(ctx, storage, role, i); err != nil {
				b.Logger().Warn("rotation worker: failed to rotate slot",
					"role", role.Name,
					"slot", i,
					"error", err,
				)
			}
		}
	}
}

// reconcileWorker runs the reconciliation logic from the background worker.
func (b *backend) reconcileWorker(ctx context.Context, storage logical.Storage) error {
	roleNames, err := storage.List(ctx, "roles/")
	if err != nil {
		return err
	}

	res := b.runReconcilePass(ctx, storage, roleNames, false)

	emitOrphansFound(res.orphansFound)
	return nil
}
