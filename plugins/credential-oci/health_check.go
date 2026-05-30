package credentialoci

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
		client := b.newOCIClient(p.token)
		// GetUser verifies the minter credentials are valid. The minter ID is the
		// configured credential identifier, used as a stand-in user reference.
		if err := client.GetUser(ctx, p.id); err != nil {
			p.sm.RecordError(401, now)
		} else {
			p.sm.RecordSuccess(now)
		}
	}

	b.emitMinterMetrics()

	return nil
}
