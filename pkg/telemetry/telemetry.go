// Package telemetry emits cloud-creds metrics for the credential plugins,
// centralizing the per-plugin emit helpers that were previously duplicated.
// The label KEYS are fixed by the response-envelope contract (identical across
// all clouds); only the cloud VALUE and metric namespace vary, carried on the
// Emitter.
package telemetry

import (
	metrics "github.com/hashicorp/go-metrics"
)

// Metric label keys, fixed across all plugins by the envelope contract.
const (
	labelCloud  = "cloud"
	labelRole   = "role"
	labelWorker = "worker"
)

// Emitter emits metrics for one plugin, carrying its cloud identity and the
// metric-key namespace. The zero value is unusable; set both fields.
type Emitter struct {
	Cloud     string // value of the "cloud" label, e.g. "do"
	Namespace string // leading metric-key segment, e.g. "cloud_creds"
}

// Gauge sets a gauge <namespace>.<name> with the given labels.
func (e Emitter) Gauge(name string, val float32, labels []metrics.Label) {
	metrics.SetGaugeWithLabels([]string{e.Namespace, name}, val, labels)
}

// Counter increments a counter <namespace>.<name> by 1 with the given labels.
func (e Emitter) Counter(name string, labels []metrics.Label) {
	metrics.IncrCounterWithLabels([]string{e.Namespace, name}, 1, labels)
}

// CloudLabel returns the standard {cloud=<e.Cloud>} label, for building label
// slices in plugin code (e.g. emitMinterMetrics).
func (e Emitter) CloudLabel() metrics.Label {
	return metrics.Label{Name: labelCloud, Value: e.Cloud}
}

// LeaseIssued counts a credential issuance for the given role.
func (e Emitter) LeaseIssued(role string) {
	e.Counter("lease_issued_total", []metrics.Label{
		{Name: labelCloud, Value: e.Cloud},
		{Name: labelRole, Value: role},
	})
}

// LeaseRevokeFailed counts a failed lease revocation for the given role.
func (e Emitter) LeaseRevokeFailed(role string) {
	e.Counter("lease_revoke_failures_total", []metrics.Label{
		{Name: labelCloud, Value: e.Cloud},
		{Name: labelRole, Value: role},
	})
}

// OrphansFound records the orphan count from a reconcile pass.
func (e Emitter) OrphansFound(count int) {
	e.Gauge("orphans_found", float32(count), []metrics.Label{
		{Name: labelCloud, Value: e.Cloud},
	})
}

// WorkerError counts a periodic-worker error or recovered panic. The error
// text is not labeled (cardinality); callers log it separately.
func (e Emitter) WorkerError(worker string, _ error) {
	e.Counter("worker_errors_total", []metrics.Label{
		{Name: labelCloud, Value: e.Cloud},
		{Name: labelWorker, Value: worker},
	})
}

// IssuanceAttempt identifies one credential-issuance attempt for logging.
//
// It exists because the issuance-failure log line named only the cloud, the status
// and the error — so on a mount with many roles an operator learned that "something
// on this cloud got a 403" and nothing more, though the role, set, minter and
// request id were all in scope at the call site (A26 in
// docs/audit-2026-08-22.md). Passed as one value rather than four parameters so the
// failure helper stays within the argument limit, and defined once here rather than
// nine times so the field NAMES cannot drift between clouds — an operator grepping
// `minter_id=` should find every cloud.
type IssuanceAttempt struct {
	Cloud     string
	Role      string
	MinterSet string
	MinterID  string
	RequestID string
}

// LogFields renders the attempt as structured log key/values, with the upstream
// status and error appended.
func (a IssuanceAttempt) LogFields(status int, err error) []interface{} {
	return []interface{}{
		labelCloud, a.Cloud,
		"role", a.Role,
		"minter_set", a.MinterSet,
		"minter_id", a.MinterID,
		"request_id", a.RequestID,
		"status", status,
		"error", err,
	}
}
