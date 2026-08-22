package credentialdo

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
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

func (b *backend) reconcileWorker(ctx context.Context, storage logical.Storage) error {
	client, err := b.anyHealthyMinter()
	if err != nil {
		return err
	}

	instanceID, err := b.ownerInstanceID(ctx, storage)
	if err != nil {
		return err
	}
	lister := &doCloudLister{client: client, instanceID: instanceID}
	registry := &leaseRegistry{storage: storage}

	b.mu.RLock()
	maxDeletes := maxDeletesPerPass
	if b.config != nil {
		maxDeletes = b.config.MaxDeletesPerPass
	}
	b.mu.RUnlock()

	cfg := reconciler.Config{
		MaxDeletesPerPass: maxDeletes,
		ConfirmationHold:  1 * time.Hour,
		DryRun:            false,
	}

	_, err = reconciler.New(cfg, lister, registry).WithLogger(cloudName, b.Logger()).Run(ctx, time.Now())
	return err
}
