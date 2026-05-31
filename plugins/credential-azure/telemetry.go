package credentialazure

import (
	"time"

	"github.com/hashicorp/go-metrics"

	"github.com/nicois/openbao-cloud-creds/pkg/worker"
)

func emitGauge(key []string, val float32, labels []metrics.Label) {
	metrics.SetGaugeWithLabels(key, val, labels)
}

func emitCounter(key []string, labels []metrics.Label) {
	metrics.IncrCounterWithLabels(key, 1, labels)
}

func (b *backend) emitMinterMetrics() {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	for setName, states := range b.minterSets {
		for id, ms := range states {
			labels := []metrics.Label{
				{Name: fieldCloud, Value: cloudName},
				{Name: fieldMinterSet, Value: setName},
				{Name: "cred_id", Value: id},
			}

			state := string(ms.sm.State())
			emitGauge([]string{metricNamespace, "upstream_state"}, 1, append(labels, metrics.Label{Name: "state", Value: state}))

			emitGauge([]string{metricNamespace, "upstream_consecutive_failures"}, float32(ms.sm.ConsecutiveFailures()), labels)

			lastSuccess := ms.sm.LastSuccessAt()
			if !lastSuccess.IsZero() {
				emitGauge([]string{metricNamespace, "upstream_last_success_seconds_ago"}, float32(now.Sub(lastSuccess).Seconds()), labels)
			}

			if !ms.minter.ExpiresAt.IsZero() {
				expiresIn := ms.minter.ExpiresAt.Sub(now).Seconds()
				emitGauge([]string{metricNamespace, "upstream_expires_in_seconds"}, float32(expiresIn), labels)
			}
		}
	}
}

func emitLeaseIssued(role string) {
	emitCounter([]string{metricNamespace, "lease_issued_total"}, []metrics.Label{
		{Name: fieldCloud, Value: cloudName},
		{Name: fieldRole, Value: role},
	})
}

func emitLeaseRevokeFailed(role string) {
	emitCounter([]string{metricNamespace, "lease_revoke_failures_total"}, []metrics.Label{
		{Name: fieldCloud, Value: cloudName},
		{Name: fieldRole, Value: role},
	})
}

func emitOrphansFound(count int) {
	emitGauge([]string{metricNamespace, "orphans_found"}, float32(count), []metrics.Label{
		{Name: fieldCloud, Value: cloudName},
	})
}

// workerErrorHandler returns a handler that logs and counts periodic worker
// errors and recovered panics.
func (b *backend) workerErrorHandler() worker.ErrorHandler {
	return func(name string, err error) {
		b.Logger().Warn("worker error", "worker", name, "error", err)
		emitCounter([]string{metricNamespace, "worker_errors_total"},
			[]metrics.Label{{Name: fieldCloud, Value: cloudName}, {Name: "worker", Value: name}})
	}
}
