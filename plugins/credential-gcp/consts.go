package credentialgcp

import "time"

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "gcp"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName      = "name"
	fieldRole      = "role"
	fieldCloud     = "cloud"
	fieldMinterSet = "minter_set"

	// fieldDefaultTTL / fieldMaxTTL are the role TTL field names.
	fieldDefaultTTL          = "default_ttl"
	fieldMaxTTL              = "max_ttl"
	fieldServiceAccountEmail = "service_account_email"
	fieldScopes              = "scopes"

	// fieldMinterID is the rotate-endpoint field naming the minter to rotate.
	fieldMinterID = "minter_id"
	// fieldMinterRetireGrace is the config field/response key for the retirement
	// grace (seconds before a retired minter's upstream SA key is swept).
	fieldMinterRetireGrace = "minter_retire_grace"
	// fieldVerifyCapability is the config field toggling the capability probe
	// (a throwaway mint-and-delete) run at minter-set and role write.
	fieldVerifyCapability = "verify_minter_capability"

	// fieldCapabilityCacheTTL is the config field bounding how long a successful
	// capability probe is reused. Probes are real mints against the cloud, so an
	// unremembered fan-out re-minted on every configuration write (A29).
	fieldCapabilityCacheTTL = "capability_cache_ttl"
	// fieldRotationParams is the per-minter rotation metadata map key (after
	// rotation it carries the successor's upstream SA key resource name used by
	// the retired-sweep to delete it).
	fieldRotationParams = "rotation_params"
	// fieldKeyName is the rotation_params entry holding a minter's upstream SA key
	// resource name (set on rotation successors; absent on operator-provided
	// originals).
	fieldKeyName = "key_name"
)

// pathConfig is the bare config endpoint path (operational + cloud settings).
const pathConfig = "config"

// configMetaKey holds the cloud-specific config settings that do not live in
// cloudconfig.PluginConfig, persisted so a reloaded backend can rehydrate them
// before any config write happens (KI-001).
const configMetaKey = "config_meta"

// fieldProject is the config field naming the GCP project, also its key inside
// configMetaKey.
const fieldProject = "project"

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"

// TTL defaults (seconds) used in schema Default values. Names mirror the DO
// reference plugin; values are unchanged from the original literals.
const (
	// defaultReconcileCadenceSeconds is the default reconciliation cadence (6h).
	defaultReconcileCadenceSeconds = 21600
	// defaultMinterExpiryWarnSeconds is the default near-expiry warn threshold (7d),
	// matching cloudconfig.MinMinterGap.
	defaultMinterExpiryWarnSeconds = 604800
	// defaultMinterRetireGraceSeconds is the default grace (7d, = cloudconfig.MinMinterGap)
	// between marking a minter retired and the retired-sweep deleting its upstream
	// SA key. The grace must exceed the worst-case interval before every raft node
	// reloads the set, so no node's in-memory snapshot still selects a minter whose
	// upstream key has been deleted.
	defaultMinterRetireGraceSeconds = 604800

	// defaultCapabilityCacheTTLSeconds is how long a successful capability probe
	// stands in for a fresh one (1h). See capability.DefaultCacheTTL for the trade:
	// without a cache, every configuration write re-mints the whole probe fan-out.
	defaultCapabilityCacheTTLSeconds = 3600
	// defaultRoleTTLSeconds is the default/maximum role token lifetime (1h);
	// GCP caps access-token lifetime at 3600s by default.
	// The role TTL defaults are deliberately the SAME on every cloud that can honour
	// them — 15m default, 1h maximum — because short-lived credentials are the product
	// and a default is what most roles will actually run with. They used to vary by up
	// to 400x across ten plugins with identical documentation (A28 in
	// docs/audit-2026-08-22.md). Only OVH (a fixed 1h token, so exactly 3600 either
	// way) and OCI (whose lease TTL is derived from the rotation period) differ, and
	// both are forced by the cloud rather than chosen.
	defaultRoleTTLSeconds = 900 // 15m
	// defaultRoleMaxTTLSeconds is 1h. max_ttl used to default to defaultRoleTTLSeconds,
	// which meant the ceiling and the default were the same value and moved together.
	defaultRoleMaxTTLSeconds = 3600
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
)

// Operational interval field names, constified because they appear in the schema,
// the write handler, the interval validation and the read response.
const (
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
