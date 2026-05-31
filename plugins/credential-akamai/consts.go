package credentialakamai

import "time"

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "akamai"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName      = "name"
	fieldRole      = "role"
	fieldCloud     = "cloud"
	fieldHost      = "host"
	fieldGroupID   = "group_id"
	fieldAPIAccess = "api_access"
	fieldMinterSet = "minter_set"
)

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"

// TTL defaults (seconds), surfaced in path field schemas. Values unchanged.
const (
	defaultFlushIntervalSeconds    = 900    // metrics flush interval
	defaultReconcileCadenceSeconds = 21600  // reconciliation cadence
	defaultRoleTTLSeconds          = 900    // role default lease TTL
	defaultRoleMaxTTLSeconds       = 3600   // role maximum lease TTL
	defaultStaleOlderThanSeconds   = 604800 // metrics/stale default window
)

// Operational timing constants.
const (
	reconcilerBootstrapDelay = 24 * time.Hour   // delay before first reconcile pass
	healthCheckInterval      = 5 * time.Minute  // minter health-check cadence
	authFailThreshold        = 30 * time.Second // recovery state-machine auth-fail window
	httpTimeout              = 30 * time.Second // upstream HTTP client timeout
)

// maxDeletesPerPass caps how many orphans the reconciler deletes per pass.
const maxDeletesPerPass = 10

// nonceBytes is the number of random bytes in an EdgeGrid request nonce.
const nonceBytes = 16

// leaseShortIDLen is the number of leading lease-ID characters used to build a
// human-readable upstream API-client name.
const leaseShortIDLen = 8
