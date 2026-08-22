package credentialovh

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "ovh"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName      = "name"
	fieldRole      = "role"
	fieldRegion    = "region"
	fieldMinterSet = "minter_set"
	fieldCloud     = "cloud"
	// fieldMinterID names the minter targeted by the rotate endpoint.
	fieldMinterID = "minter_id"
	// fieldMinterRetireGrace is the config field/response key for the retirement
	// grace; present for a uniform config surface across all clouds (OVH never
	// marks a minter retired, so no sweep ever consumes it).
	fieldMinterRetireGrace = "minter_retire_grace"
	// fieldVerifyCapability is the config field toggling the capability probe
	// (a throwaway mint-and-delete) run at minter-set and role write.
	fieldVerifyCapability = "verify_minter_capability"
)

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
