package credentialaws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
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

		client := b.buildSTSClient(ms.minter)
		_, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			ms.sm.RecordError(classifyAWSError(err), now)
		} else {
			ms.sm.RecordSuccess(now)
		}
	}

	b.emitMinterMetrics()

	return nil
}
