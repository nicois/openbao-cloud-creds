package credentialovh

import (
	"context"
	"time"

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
		return
	}

	wm := worker.New(worker.WithErrorHandler(b.workerErrorHandler()))

	wm.Register("health-check", healthCheckInterval, worker.Opts{}, b.healthCheckWorker)

	wm.Register("metrics-flush", cfg.FlushInterval, worker.Opts{}, func(ctx context.Context) error {
		return b.accessTracker.Flush(ctx, time.Now())
	})

	// OVH access tokens auto-expire, so the reconciler is minimal:
	// it only cleans up tracking entries for expired credentials.
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

// reconcileWorker for OVH is simple since access tokens auto-expire.
// It cleans up stale tracking entries from storage.
func (b *backend) reconcileWorker(ctx context.Context, storage logical.Storage) error {
	entries, err := storage.List(ctx, "active-tokens/")
	if err != nil {
		return err
	}

	now := time.Now()
	cleaned := 0
	for _, key := range entries {
		entry, err := storage.Get(ctx, "active-tokens/"+key)
		if err != nil {
			continue
		}
		if entry == nil {
			continue
		}

		var data map[string]interface{}
		if err := entry.DecodeJSON(&data); err != nil {
			continue
		}

		// Remove tracking entries for expired credentials
		if expiresStr, ok := data["expires_at"].(string); ok {
			expiresAt, err := time.Parse(time.RFC3339, expiresStr)
			if err == nil && now.After(expiresAt) {
				_ = storage.Delete(ctx, "active-tokens/"+key)
				cleaned++
			}
		}
	}

	emitOrphansFound(cleaned)
	return nil
}
