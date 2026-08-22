package credentialupcloud

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "upcloud"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName      = "name"
	fieldRole      = "role"
	fieldScopes    = "scopes"
	fieldMinterSet = "minter_set"

	// fieldDefaultTTL / fieldMaxTTL are the role TTL field names.
	fieldDefaultTTL = "default_ttl"
	fieldMaxTTL     = "max_ttl"
	fieldCloud      = "cloud"
	fieldUsername   = "username"

	// fieldMinterID is the rotate-endpoint field naming the minter to rotate.
	fieldMinterID = "minter_id"
	// fieldMinterRetireGrace is the config field/response key for the retirement
	// grace (seconds before a retired minter's upstream token is swept).
	fieldMinterRetireGrace = "minter_retire_grace"
	// fieldVerifyCapability is the config field toggling the capability probe
	// (a throwaway mint-and-delete) run at minter-set and role write.
	fieldVerifyCapability = "verify_minter_capability"
	// fieldRotationParams is the per-minter rotation metadata map key (after
	// rotation it carries the successor's upstream token_id used by the
	// retired-sweep to delete it).
	fieldRotationParams = "rotation_params"
	// fieldTokenID is the rotation_params entry holding a minter's upstream
	// UpCloud token id (set on rotation successors; absent on operator-provided
	// originals).
	fieldTokenID = "token_id"
)

// pathConfig is the bare config endpoint path (operational + cloud settings).
const pathConfig = "config"

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"

// Operational interval field names, constified because they appear in the schema,
// the write handler, the interval validation and the read response.
const (
	fieldFlushInterval    = "flush_interval"
	fieldReconcileCadence = "reconcile_cadence"
	fieldMinterExpiryWarn = "minter_expiry_warn"
)

// Reconcile modes. Constified because they appear in the schema description, the
// mode validation and the response.
const (
	modeNormal = "normal"
	modeDryRun = "dry_run"
)

// Minter-set field names, constified because they appear in the schema, the
// write parser and the read response.
const (
	fieldMintersKey = "minters"
	neverExpiresKey = "never_expires"
)
