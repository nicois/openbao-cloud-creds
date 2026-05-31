package credentialoci

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
				{Name: "cloud", Value: "oci"},
				{Name: "minter_set", Value: setName},
				{Name: "cred_id", Value: id},
			}

			state := string(ms.sm.State())
			emitGauge([]string{"cloud_creds", "upstream_state"}, 1, append(labels, metrics.Label{Name: "state", Value: state}))

			emitGauge([]string{"cloud_creds", "upstream_consecutive_failures"}, float32(ms.sm.ConsecutiveFailures()), labels)

			lastSuccess := ms.sm.LastSuccessAt()
			if !lastSuccess.IsZero() {
				emitGauge([]string{"cloud_creds", "upstream_last_success_seconds_ago"}, float32(now.Sub(lastSuccess).Seconds()), labels)
			}

			if !ms.minter.ExpiresAt.IsZero() {
				expiresIn := ms.minter.ExpiresAt.Sub(now).Seconds()
				emitGauge([]string{"cloud_creds", "upstream_expires_in_seconds"}, float32(expiresIn), labels)
			}
		}
	}
}

func emitLeaseIssued(role string) {
	emitCounter([]string{"cloud_creds", "lease_issued_total"}, []metrics.Label{
		{Name: "cloud", Value: "oci"},
		{Name: "role", Value: role},
	})
}

func emitSlotRotated(role string, slotIndex int) {
	emitCounter([]string{"cloud_creds", "slot_rotated_total"}, []metrics.Label{
		{Name: "cloud", Value: "oci"},
		{Name: "role", Value: role},
	})
	_ = slotIndex
}

func emitOrphansFound(count int) {
	emitGauge([]string{"cloud_creds", "orphans_found"}, float32(count), []metrics.Label{
		{Name: "cloud", Value: "oci"},
	})
}

func emitRotationCheckCompleted(rolesChecked int) {
	emitCounter([]string{"cloud_creds", "rotation_check_completed"}, []metrics.Label{
		{Name: "cloud", Value: "oci"},
	})
	_ = rolesChecked
}

// workerErrorHandler returns a handler that logs and counts periodic worker
// errors and recovered panics.
func (b *backend) workerErrorHandler() worker.ErrorHandler {
	return func(name string, err error) {
		b.Logger().Warn("worker error", "worker", name, "error", err)
		emitCounter([]string{"cloud_creds", "worker_errors_total"},
			[]metrics.Label{{Name: "cloud", Value: "oci"}, {Name: "worker", Value: name}})
	}
}
