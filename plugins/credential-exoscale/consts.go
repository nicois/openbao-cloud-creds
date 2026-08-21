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

	// fieldDefaultTTL / fieldMaxTTL are the role TTL field names.
	fieldDefaultTTL = "default_ttl"
	fieldMaxTTL     = "max_ttl"
	fieldCloud      = "cloud"

	// fieldMinterID is the rotate-endpoint field naming the minter to rotate.
	fieldMinterID = "minter_id"
	// fieldMinterRetireGrace is the config field/response key for the retirement
	// grace (seconds before a retired minter's upstream key is swept).
	fieldMinterRetireGrace = "minter_retire_grace"
	// fieldVerifyCapability is the config field toggling the capability probe
	// (a throwaway mint-and-delete) run at minter-set and role write.
	fieldVerifyCapability = "verify_minter_capability"
	// fieldRotationParams is the per-minter rotation metadata map key. It carries
	// role_id (the minter's key-management IAM role, needed to mint a mint-capable
	// successor) and, after rotation, key_id (the successor's upstream key-id used
	// by the retired-sweep to delete it).
	fieldRotationParams = "rotation_params"
	// fieldKeyID is the rotation_params entry holding a minter's upstream Exoscale
	// API key-id (set on rotation successors; absent on operator-provided
	// originals).
	fieldKeyID = "key_id"
)

// pathConfig is the bare config endpoint path (operational + cloud settings).
const pathConfig = "config"

// successorKeyNamePrefix is the upstream key-name prefix for a rotation
// successor (the owner-tag prefix the reconciler recognises, plus the successor
// minter id).
const successorKeyNamePrefix = "cloud-creds-minter-"

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
	// defaultMinterExpiryWarnSeconds is the default near-expiry warn threshold (7d),
	// matching cloudconfig.MinMinterGap.
	defaultMinterExpiryWarnSeconds = 604800
	// defaultMinterRetireGraceSeconds is the default grace (7d, = cloudconfig.MinMinterGap)
	// between marking a minter retired and the retired-sweep deleting its upstream
	// key. The grace must exceed the worst-case interval before every raft node
	// has reloaded the set, so no node's in-memory snapshot still selects a minter
	// whose upstream key has been deleted.
	defaultMinterRetireGraceSeconds = 604800
)

// defaultMinterSecretLifetime is how long a rotation successor key is treated as
// valid when the original minter expires (NeverExpires=false). Exoscale API keys
// do not themselves expire upstream, so this only sets the successor's locally
// tracked ExpiresAt; a year keeps it well clear of the next operator-driven
// rotation. NeverExpires originals yield NeverExpires successors.
const defaultMinterSecretLifetime = 365 * 24 * time.Hour

// Worker and reconciler timing/count constants.
const (
	reconcilerBootstrapDelay = 24 * time.Hour
	healthCheckInterval      = 5 * time.Minute
	authFailThreshold        = 30 * time.Second
	httpTimeout              = 30 * time.Second
	maxDeletesPerPass        = 10
)

// Operational interval field names, constified because they appear in the schema,
// the write handler, the interval validation and the read response.
const (
	fieldFlushInterval    = "flush_interval"
	fieldReconcileCadence = "reconcile_cadence"
	fieldMinterExpiryWarn = "minter_expiry_warn"
)
