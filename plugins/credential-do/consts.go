package credentialdo

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "do"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName      = "name"
	fieldRole      = "role"
	fieldScopes    = "scopes"
	fieldMinterSet = "minter_set"
	fieldCloud     = "cloud"
	// fieldMinterID names the minter targeted by the rotate endpoint.
	fieldMinterID = "minter_id"
	// fieldMinterRetireGrace is the config field/response key for the retirement
	// grace; present for a uniform config surface across all clouds (DO never
	// marks a minter retired, so no sweep ever consumes it).
	fieldMinterRetireGrace = "minter_retire_grace"
	// fieldVerifyCapability is the config field gating the capability probe (a
	// throwaway mint-and-delete proving a minter can mint, not merely
	// authenticate). See capability.go.
	fieldVerifyCapability = "verify_minter_capability"
)

// Path and field keys reused across schemas, request handlers, and tests.
// Constified so the linter (goconst) has a single source of truth.
const (
	pathConfigKey    = "config"
	fieldDOAPIURLKey = "do_api_url"
	fieldMintersKey  = "minters"
)

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"
