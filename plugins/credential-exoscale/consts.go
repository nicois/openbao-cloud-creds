package credentialexoscale

import "time"

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "exoscale"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName      = "name"
	fieldRole      = "role"
	fieldRoleID    = "role_id"
	fieldMinterSet = "minter_set"
	fieldCloud     = "cloud"
)

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"

// Schema TTL/duration defaults, in seconds. Same values as before; named so
// mnd has a single source of truth.
const (
	defaultRoleTTLSeconds          = 900
	defaultReconcileCadenceSeconds = 21600
	defaultRoleMaxTTLSeconds       = 3600
	defaultStaleAfterSeconds       = 604800
	defaultFlushIntervalSeconds    = 900
)

// Worker and reconciler timing/count constants.
const (
	reconcilerBootstrapDelay = 24 * time.Hour
	healthCheckInterval      = 5 * time.Minute
	authFailThreshold        = 30 * time.Second
	httpTimeout              = 30 * time.Second
	maxDeletesPerPass        = 10
)
