package credentialakamai

import (
	"context"
	"time"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	minters := b.minters
	apiURL := b.akamaiAPIURL()
	host := b.host
	b.mu.RUnlock()

	now := time.Now()
	for _, ms := range minters {
		if !ms.sm.NeedsHealthCheck(now) {
			continue
		}

		cred, err := parseEdgeGridToken(ms.minter.Token)
		if err != nil {
			continue
		}
		cred.Host = host

		client := newAkamaiClient(apiURL, cred)
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
