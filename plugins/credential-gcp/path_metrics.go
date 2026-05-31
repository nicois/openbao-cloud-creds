package credentialgcp

import (
	"github.com/openbao/openbao/sdk/v2/framework"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
	"github.com/nicois/openbao-cloud-creds/pkg/metricspath"
)

func (b *backend) metricsPaths() []*framework.Path {
	return metricspath.Paths(func() *metrics.AccessTracker {
		b.mu.RLock()
		defer b.mu.RUnlock()
		return b.accessTracker
	}, defaultStaleAfterSeconds)
}
