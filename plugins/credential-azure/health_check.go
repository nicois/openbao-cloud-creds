package credentialazure

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	now := time.Now()

	// Build each minter's client while holding the read lock so endpoint
	// fields aren't read concurrently with a config write. Each minter gets
	// its own *azureClient, so its Graph token cache stays isolated to that
	// minter's client_secret — no cross-minter token bleed.
	b.mu.RLock()
	type probe struct {
		client *azureClient
		sm     *recovery.StateMachine
	}
	var probes []probe
	for _, states := range b.minterSets {
		for _, ms := range states {
			if ms.sm.NeedsHealthCheck(now) {
				probes = append(probes, probe{b.newClientForMinter(ms.minter), ms.sm})
			}
		}
	}
	b.mu.RUnlock()

	for _, p := range probes {
		// We have no per-set app_object_id here, so health is a token-only
		// probe: can this minter authenticate to Graph at all?
		if _, tokenStatus, err := p.client.getToken(ctx); err != nil {
			p.sm.RecordUpstream(tokenStatus, err, now)
		} else {
			p.sm.RecordSuccess(now)
		}
	}

	b.emitMinterMetrics()

	return nil
}
