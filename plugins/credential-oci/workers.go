package credentialoci

import (
	"context"
	"encoding/json"
	"time"

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
		roleEntry, err := storage.Get(ctx, "roles/"+roleName)
		if err != nil {
			continue
		}
		if roleEntry == nil {
			continue
		}

		var role ociRole
		if err := json.Unmarshal(roleEntry.Value, &role); err != nil {
			continue
		}

		if role.Disabled {
			continue
		}

		rolesChecked++

		for i := 0; i < role.SlotCount; i++ {
			s, err := loadSlot(ctx, storage, roleName, i)
			if err != nil || s == nil {
				continue
			}

			if s.State == slotActive && now.After(s.NextRotationAt) {
				if err := b.rotateSlot(ctx, storage, &role, i); err != nil {
					b.Logger().Warn("rotation worker: failed to rotate slot",
						"role", roleName,
						"slot", i,
						"error", err,
					)
				}
			}
		}
	}

	emitRotationCheckCompleted(rolesChecked)
	return nil
}

// reconcileWorker runs the reconciliation logic from the background worker.
func (b *backend) reconcileWorker(ctx context.Context, storage logical.Storage) error {
	client := b.getClient()
	if client == nil {
		return nil
	}

	roleNames, err := storage.List(ctx, "roles/")
	if err != nil {
		return err
	}

	// Collect known token IDs
	knownTokenIDs := make(map[string]bool)
	for _, roleName := range roleNames {
		roleEntry, err := storage.Get(ctx, "roles/"+roleName)
		if err != nil {
			continue
		}
		if roleEntry == nil {
			continue
		}
		var role ociRole
		if err := json.Unmarshal(roleEntry.Value, &role); err != nil {
			continue
		}
		slots, err := loadAllSlots(ctx, storage, roleName, role.SlotCount)
		if err != nil {
			continue
		}
		for _, s := range slots {
			if s.TokenID != "" {
				knownTokenIDs[s.TokenID] = true
			}
		}
	}

	// Find and delete orphans
	orphansFound := 0
	maxDeletes := 10
	b.mu.RLock()
	if b.config != nil {
		maxDeletes = b.config.MaxDeletesPerPass
	}
	b.mu.RUnlock()

	deleted := 0
	for _, roleName := range roleNames {
		roleEntry, err := storage.Get(ctx, "roles/"+roleName)
		if err != nil {
			continue
		}
		if roleEntry == nil {
			continue
		}
		var role ociRole
		if err := json.Unmarshal(roleEntry.Value, &role); err != nil {
			continue
		}

		tokens, err := client.ListAuthTokens(ctx, role.UserOCID)
		if err != nil {
			continue
		}

		for _, t := range tokens {
			if !isOwnedToken(t.Description) {
				continue
			}
			if !knownTokenIDs[t.ID] {
				orphansFound++
				if deleted < maxDeletes {
					if err := client.DeleteAuthToken(ctx, role.UserOCID, t.ID); err == nil {
						deleted++
					}
				}
			}
		}
	}

	emitOrphansFound(orphansFound)
	return nil
}

// isOwnedToken checks if a token description matches the owner-tag scheme.
func isOwnedToken(description string) bool {
	return len(description) >= len(ociTokenPrefix) && description[:len(ociTokenPrefix)] == ociTokenPrefix
}
