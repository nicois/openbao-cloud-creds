package credentialvultr

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	type probe struct {
		set, id, token string
		sm             *recovery.StateMachine
	}
	var probes []probe
	apiURL := b.vultrAPIURL()
	for setName, states := range b.minterSets {
		for id, ms := range states {
			if ms.sm.NeedsHealthCheck(time.Now()) {
				probes = append(probes, probe{setName, id, ms.minter.Token, ms.sm})
			}
		}
	}
	b.mu.RUnlock()

	now := time.Now()
	for _, p := range probes {
		client := newVultrClient(apiURL, p.token)
		status, err := client.CheckHealth(ctx)
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
