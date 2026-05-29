package credentialoci

import (
	"context"
	"time"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	minters := b.minters
	b.mu.RUnlock()

	client := b.getClient()
	if client == nil {
		return nil
	}

	now := time.Now()
	for _, ms := range minters {
		if !ms.sm.NeedsHealthCheck(now) {
			continue
		}

		// Use the first role's user OCID for health check
		// In practice, GetUser checks that the minter credentials are valid
		err := client.GetUser(ctx, ms.minter.ID)
		if err != nil {
			ms.sm.RecordError(401, now)
		} else {
			ms.sm.RecordSuccess(now)
		}
	}

	b.emitMinterMetrics()

	return nil
}
