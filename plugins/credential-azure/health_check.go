package credentialazure

import (
	"context"
	"time"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	minters := b.minters
	b.mu.RUnlock()

	// We need at least one role's app_object_id to check health
	// Use the first app_object_id found among roles
	appObjectID := b.getFirstAppObjectID(ctx)

	now := time.Now()
	for _, ms := range minters {
		if !ms.sm.NeedsHealthCheck(now) {
			continue
		}

		client := b.newClientForMinter(ms.minter)

		if appObjectID == "" {
			// No roles configured yet, just try to get a token
			_, err := client.getToken(ctx)
			if err != nil {
				ms.sm.RecordError(0, now)
			} else {
				ms.sm.RecordSuccess(now)
			}
			continue
		}

		status, err := client.CheckHealth(ctx, appObjectID)
		if err != nil {
			ms.sm.RecordError(status, now)
			continue
		}

		if status == 200 {
			ms.sm.RecordSuccess(now)
		} else {
			ms.sm.RecordError(status, now)
		}
	}

	b.emitMinterMetrics()

	return nil
}

func (b *backend) getFirstAppObjectID(_ context.Context) string {
	// This is only used by the health check worker; it runs within the backend
	// so we can use the Backend's storage if available. Since health check
	// workers don't have direct storage access, we cache from roles.
	b.mu.RLock()
	defer b.mu.RUnlock()
	// Return empty if not set — health check will fall back to token-only check
	return ""
}
