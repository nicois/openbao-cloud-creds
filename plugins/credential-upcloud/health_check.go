package credentialupcloud

import (
	"context"
	"time"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	minters := b.minters
	apiURL := b.upcloudAPIURL()
	username := b.username
	b.mu.RUnlock()

	now := time.Now()
	for _, ms := range minters {
		if !ms.sm.NeedsHealthCheck(now) {
			continue
		}

		client := newUpCloudClient(apiURL, username, ms.minter.Token)
		status, err := client.CheckHealth(ctx)
		if err != nil {
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
