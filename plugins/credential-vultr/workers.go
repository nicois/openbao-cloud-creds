package credentialvultr

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/mintledger"
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
		InitialDelay: b.remainingBootstrapDelay(cfg.BootstrapDelay),
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
	if wm != nil && !wm.WaitFor(worker.DrainTimeout) {
		// Do not hold the SDK's process-wide lock behind one mount's in-flight
		// upstream call: the goroutines are already cancelled and on their way out.
		b.Logger().Warn("worker drain did not finish within the deadline; continuing shutdown",
			fieldCloud, cloudName, "deadline", worker.DrainTimeout)
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
	// Housekeeping that must run whether or not the pass below can: an expired
	// capability verdict is dead weight, and clearing entries when the TTL is zero
	// is what makes capability_cache_ttl=0 mean "off" rather than "off from now on"
	// (A29).
	capability.SweepCache(ctx, storage, cloudName, b.Logger(), b.gate().CacheTTL)

	client, err := b.anyHealthyMinter()
	if err != nil {
		return err
	}

	instanceID, err := b.ownerInstanceID(ctx, storage)
	if err != nil {
		return err
	}
	lister := &vultrCloudLister{client: client, storage: storage, instanceID: instanceID}
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

	if _, err = reconciler.New(cfg, lister, registry).WithLogger(cloudName, b.Logger()).
		Run(ctx, time.Now()); err != nil {
		return err
	}

	// Keep the ledger bounded. Pruned by AGE, never by revocation: an entry that
	// followed the tracking entry would be gone exactly when a leaked credential
	// needed it (A5).
	if pruned, pruneErr := mintledger.Prune(ctx, storage, time.Now()); pruneErr != nil {
		b.Logger().Warn("could not prune the mint ledger", "cloud", cloudName, "error", pruneErr)
	} else if pruned > 0 {
		b.Logger().Info("pruned mint-ledger entries past retention",
			"cloud", cloudName, "pruned", pruned)
	}
	return nil
}

// remainingBootstrapDelay is what is LEFT of the reconciler's hold-off, measured
// from the first time this process started workers rather than from this call.
//
// The hold-off exists so a freshly (re)started mount does not treat leases issued
// just before the restart as orphans. It was passed straight through as
// InitialDelay — and startWorkers re-runs on every config write, every minter-set
// write and every plugin reload, so a write every 23h re-armed a 24h delay forever
// and the orphan backstop never ran once (A29 in docs/audit-2026-08-22.md).
func (b *backend) remainingBootstrapDelay(total time.Duration) time.Duration {
	b.mu.Lock()
	if b.bootstrapAt.IsZero() {
		b.bootstrapAt = time.Now()
	}
	startedAt := b.bootstrapAt
	b.mu.Unlock()

	if remaining := total - time.Since(startedAt); remaining > 0 {
		return remaining
	}
	return 0
}
