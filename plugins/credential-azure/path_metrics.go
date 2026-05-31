package credentialazure

import (
	"github.com/openbao/openbao/sdk/v2/framework"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
	"github.com/nicois/openbao-cloud-creds/pkg/metricspath"
)

// defaultStaleAfterSeconds is the default "older_than" window for the stale
// metrics query, in seconds (framework.TypeDurationSecond).
const defaultStaleAfterSeconds = 604800 // 7d

func (b *backend) metricsPaths() []*framework.Path {
	return metricspath.Paths(func() *metrics.AccessTracker {
		b.mu.RLock()
		defer b.mu.RUnlock()
		return b.accessTracker
	}, defaultStaleAfterSeconds)
}
