package credentialgcp

import (
	"time"

	metrics "github.com/hashicorp/go-metrics"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/telemetry"
	"github.com/nicois/openbao-cloud-creds/pkg/worker"
)

// emit is this plugin's shared metrics emitter (cloud identity + namespace).
var emit = telemetry.Emitter{Cloud: cloudName, Namespace: metricNamespace}

func emitLeaseIssued(role string) { emit.LeaseIssued(role) }
func emitOrphansFound(count int)  { emit.OrphansFound(count) }

// emitMinterRotated counts a successful operator-initiated minter rotation,
// labelled by the minter set it occurred in.
func emitMinterRotated(set string) {
	emit.Counter("minter_rotated_total", []metrics.Label{
		emit.CloudLabel(),
		{Name: fieldMinterSet, Value: set},
	})
}

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
			labels = withCloudKey(labels, cloudconfig.CloudKeyID(ms.minter, fieldKeyName))

			b.emitMinterAge(ms.minter, labels, setName, id)

			state := string(ms.sm.State())
			emit.Gauge("upstream_state", 1, append(labels, metrics.Label{Name: "state", Value: state}))
			emit.Gauge("upstream_consecutive_failures", float32(ms.sm.ConsecutiveFailures()), labels)

			lastSuccess := ms.sm.LastSuccessAt()
			if !lastSuccess.IsZero() {
				emit.Gauge("upstream_last_success_seconds_ago", float32(now.Sub(lastSuccess).Seconds()), labels)
			}

			if !ms.minter.ExpiresAt.IsZero() {
				expiresIn := ms.minter.ExpiresAt.Sub(now)
				emit.Gauge("upstream_expires_in_seconds", float32(expiresIn.Seconds()), labels)

				warnThreshold := cloudconfig.MinMinterGap
				if b.config != nil && b.config.MinterExpiryWarn > 0 {
					warnThreshold = b.config.MinterExpiryWarn
				}
				if expiresIn > 0 && expiresIn < warnThreshold {
					b.Logger().Warn("minter nearing expiry",
						"cloud", cloudName,
						"cloud_key_id", cloudconfig.CloudKeyID(ms.minter, fieldKeyName), "minter_set", setName, "minter_id", id,
						"expires_in_seconds", int(expiresIn.Seconds()),
						"warn_threshold_seconds", int(warnThreshold.Seconds()))
				}
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

// withCloudKey appends the identifier the CLOUD knows a minter by, which is what an
// escalation quotes — cred_id is the operator's own name for it and appears in no cloud
// audit log (A23). Omitted rather than emitted empty when the cloud gives us none.
func withCloudKey(labels []metrics.Label, cloudKey string) []metrics.Label {
	if cloudKey == "" {
		return labels
	}
	return append(labels, metrics.Label{Name: "cloud_key_id", Value: cloudKey})
}

// emitMinterAge publishes a minter's age, or explains why it cannot.
//
// An absent CreatedAt is a MISSING fact, not an age. Subtracting the zero time
// published ~2e9 seconds — 63 years — so a dashboard or an alert on minter age read a
// pre-lifecycle or version-skewed entry as the oldest credential in the fleet (A30 in
// docs/audit-2026-08-22.md). Emitting nothing is honest: the series is absent rather
// than wrong, and absent is a condition an alert can express.
func (b *backend) emitMinterAge(minter cloudconfig.Minter, labels []metrics.Label, setName, id string) {
	if minter.CreatedAt.IsZero() {
		b.Logger().Warn("minter has no created_at, so its age cannot be reported",
			fieldCloud, cloudName, fieldMinterSet, setName, "minter_id", id)
		return
	}
	emit.Gauge("minter_age_seconds", float32(time.Since(minter.CreatedAt).Seconds()), labels)
}
