package credentialazure

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "azure"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName        = "name"
	fieldRole        = "role"
	fieldMinterSet   = "minter_set"
	fieldCloud       = "cloud"
	fieldTenantID    = "tenant_id"
	fieldClientID    = "client_id"
	fieldAppObjectID = "app_object_id"
)

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"
