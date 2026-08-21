package credentialgcp

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	type probe struct {
		sm     *recovery.StateMachine
		client IAMCredentialsClient
	}
	var probes []probe
	now := time.Now()
	for _, states := range b.minterSets {
		for _, ms := range states {
			if ms.sm.NeedsHealthCheck(now) {
				probes = append(probes, probe{sm: ms.sm, client: b.buildIAMClient(ms.minter)})
			}
		}
	}
	b.mu.RUnlock()

	for _, p := range probes {
		err := p.client.TestConnection(ctx)
		if err != nil {
			p.sm.RecordUpstream(classifyGCPError(err), err, now)
		} else {
			p.sm.RecordSuccess(now)
		}
	}

	b.emitMinterMetrics()

	return nil
}
