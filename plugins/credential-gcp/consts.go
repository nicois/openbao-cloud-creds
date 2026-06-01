package credentialgcp

import "time"

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "gcp"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName                = "name"
	fieldRole                = "role"
	fieldCloud               = "cloud"
	fieldMinterSet           = "minter_set"
	fieldServiceAccountEmail = "service_account_email"
)

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"

// TTL defaults (seconds) used in schema Default values. Names mirror the DO
// reference plugin; values are unchanged from the original literals.
const (
	// defaultFlushIntervalSeconds is the default metrics flush interval (15m).
	defaultFlushIntervalSeconds = 900
	// defaultReconcileCadenceSeconds is the default reconciliation cadence (6h).
	defaultReconcileCadenceSeconds = 21600
	// defaultMinterExpiryWarnSeconds is the default near-expiry warn threshold (7d),
	// matching cloudconfig.MinMinterGap.
	defaultMinterExpiryWarnSeconds = 604800
	// defaultRoleTTLSeconds is the default/maximum role token lifetime (1h);
	// GCP caps access-token lifetime at 3600s by default.
	defaultRoleTTLSeconds = 3600
	// defaultStaleAfterSeconds is the default "older than" window for the
	// stale-entity metrics query (7d).
	defaultStaleAfterSeconds = 604800
)

// Operational tuning constants. Values unchanged from the original literals.
const (
	// reconcilerBootstrapDelay delays the first reconciler pass after start.
	reconcilerBootstrapDelay = 24 * time.Hour
	// healthCheckInterval is how often the health-check worker runs.
	healthCheckInterval = 5 * time.Minute
	// authFailThreshold is how long auth failures persist before a minter is
	// classified as hard-failing.
	authFailThreshold = 30 * time.Second
	// maxDeletesPerPass caps how many orphans the reconciler removes per pass.
	maxDeletesPerPass = 10
	// credentialIDPrefixLen is the number of leading token characters hashed to
	// derive the opaque credential ID (avoids hashing the full secret token).
	credentialIDPrefixLen = 16
)
