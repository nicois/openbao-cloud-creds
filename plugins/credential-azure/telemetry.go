package credentialazure

import (
	"time"

	metrics "github.com/hashicorp/go-metrics"

	"github.com/nicois/openbao-cloud-creds/pkg/telemetry"
	"github.com/nicois/openbao-cloud-creds/pkg/worker"
)

// emit is this plugin's shared metrics emitter (cloud identity + namespace).
var emit = telemetry.Emitter{Cloud: cloudName, Namespace: metricNamespace}

func emitLeaseIssued(role string)       { emit.LeaseIssued(role) }
func emitLeaseRevokeFailed(role string) { emit.LeaseRevokeFailed(role) }
func emitOrphansFound(count int)        { emit.OrphansFound(count) }

// emitMinterMetrics stays here: it reaches into b.minterSets / state machines.
func (b *backend) emitMinterMetrics() {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	for setName, states := range b.minterSets {
		for id, ms := range states {
			labels := []metrics.Label{
				emit.CloudLabel(),
				{Name: fieldMinterSet, Value: setName},
				{Name: "cred_id", Value: id},
			}

			state := string(ms.sm.State())
			emit.Gauge("upstream_state", 1, append(labels, metrics.Label{Name: "state", Value: state}))
			emit.Gauge("upstream_consecutive_failures", float32(ms.sm.ConsecutiveFailures()), labels)

			lastSuccess := ms.sm.LastSuccessAt()
			if !lastSuccess.IsZero() {
				emit.Gauge("upstream_last_success_seconds_ago", float32(now.Sub(lastSuccess).Seconds()), labels)
			}

			if !ms.minter.ExpiresAt.IsZero() {
				expiresIn := ms.minter.ExpiresAt.Sub(now).Seconds()
				emit.Gauge("upstream_expires_in_seconds", float32(expiresIn), labels)
			}
		}
	}
}

func (b *backend) workerErrorHandler() worker.ErrorHandler {
	return func(name string, err error) {
		b.Logger().Warn("worker error", "worker", name, "error", err)
		emit.WorkerError(name, err)
	}
}
