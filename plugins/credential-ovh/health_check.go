package credentialovh

import (
	"context"
	"time"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	minters := b.minters
	b.mu.RUnlock()

	now := time.Now()
	for _, ms := range minters {
		if !ms.sm.NeedsHealthCheck(now) {
			continue
		}

		client := b.buildTokenClient(ms.minter)
		err := client.TestConnection(ctx)
		if err != nil {
			ms.sm.RecordError(classifyOVHError(err), now)
		} else {
			ms.sm.RecordSuccess(now)
		}
	}

	b.emitMinterMetrics()

	return nil
}
