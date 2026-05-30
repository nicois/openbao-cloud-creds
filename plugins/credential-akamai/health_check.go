package credentialakamai

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	type probe struct {
		client *akamaiClient
		sm     *recovery.StateMachine
	}
	var probes []probe
	for _, states := range b.minterSets {
		for _, ms := range states {
			if !ms.sm.NeedsHealthCheck(time.Now()) {
				continue
			}
			client, err := b.clientFor(ms)
			if err != nil {
				continue
			}
			probes = append(probes, probe{client, ms.sm})
		}
	}
	b.mu.RUnlock()

	now := time.Now()
	for _, p := range probes {
		status, err := p.client.CheckHealth(ctx)
		if err != nil {
			continue
		}
		if status == 200 {
			p.sm.RecordSuccess(now)
		} else {
			p.sm.RecordError(status, now)
		}
	}

	b.emitMinterMetrics()

	return nil
}
