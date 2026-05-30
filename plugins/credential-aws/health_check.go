package credentialaws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	type probe struct {
		sm     *recovery.StateMachine
		client STSClient
	}
	var probes []probe
	now := time.Now()
	for _, states := range b.minterSets {
		for _, ms := range states {
			if ms.sm.NeedsHealthCheck(now) {
				probes = append(probes, probe{sm: ms.sm, client: b.buildSTSClient(ms.minter)})
			}
		}
	}
	b.mu.RUnlock()

	for _, p := range probes {
		_, err := p.client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			p.sm.RecordError(classifyAWSError(err), now)
		} else {
			p.sm.RecordSuccess(now)
		}
	}

	b.emitMinterMetrics()

	return nil
}
