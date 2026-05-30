package credentialexoscale

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/nicois/openbao-cloud-creds/pkg/worker"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) startWorkers(ctx context.Context, storage logical.Storage) {
	b.stopWorkers()

	b.mu.RLock()
	cfg := b.config
	b.mu.RUnlock()

	if cfg == nil {
		return
	}

	wm := worker.New()

	wm.Register("health-check", 5*time.Minute, worker.Opts{}, b.healthCheckWorker)

	wm.Register("metrics-flush", cfg.FlushInterval, worker.Opts{}, func(ctx context.Context) error {
		return b.accessTracker.Flush(ctx, time.Now())
	})

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

func (b *backend) stopWorkers() {
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

func (b *backend) reconcileWorker(ctx context.Context, storage logical.Storage) error {
	client, err := b.anyHealthyMinter()
	if err != nil {
		return err
	}

	lister := &exoscaleCloudLister{client: client}
	registry := &leaseRegistry{storage: storage, ctx: ctx}

	b.mu.RLock()
	maxDeletes := 10
	if b.config != nil {
		maxDeletes = b.config.MaxDeletesPerPass
	}
	b.mu.RUnlock()

	cfg := reconciler.Config{
		MaxDeletesPerPass: maxDeletes,
		ConfirmationHold:  1 * time.Hour,
		DryRun:            false,
	}

	_, err = reconciler.New(cfg, lister, registry).Run(ctx, time.Now())
	return err
}
