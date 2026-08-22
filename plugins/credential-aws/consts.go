package credentialaws

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "aws"

// defaultRegion is the STS region used when none is configured. It is a region
// value (not a field name), used both as a schema default and a runtime
// fallback.
const defaultRegion = "us-east-1"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName       = "name"
	fieldRole       = "role"
	fieldMinterSet  = "minter_set"
	fieldCloud      = "cloud"
	fieldIAMRoleARN = "iam_role_arn"

	// fieldDefaultTTL / fieldMaxTTL are the role TTL field names.
	fieldDefaultTTL = "default_ttl"
	fieldMaxTTL     = "max_ttl"

	// fieldMinterID is the rotate-endpoint field naming the minter to rotate.
	fieldMinterID = "minter_id"
	// fieldMinterRetireGrace is the config field/response key for the retirement
	// grace (seconds before a retired minter's upstream access key is swept).
	fieldMinterRetireGrace = "minter_retire_grace"
	// fieldVerifyCapability is the config field toggling the capability probe
	// (a throwaway mint-and-delete) run at minter-set and role write.
	fieldVerifyCapability = "verify_minter_capability"
	// fieldRotationParams is the per-minter rotation metadata map key (after
	// rotation it carries the successor's upstream access_key_id used by the
	// retired-sweep to delete it).
	fieldRotationParams = "rotation_params"
	// fieldAccessKeyID is the rotation_params entry holding a minter's upstream
	// IAM access key id (set on rotation successors; absent on operator-provided
	// originals).
	fieldAccessKeyID = "access_key_id"

	// elemAccessKeyID is AWS's own spelling of the same thing: the query parameter
	// DeleteAccessKey takes, and the element AssumeRole answers with. Constified
	// because goconst counts occurrences package-wide *including* _test.go files,
	// so the real-cloud tests' use of the element name otherwise reports as a
	// finding against this production package.
	elemAccessKeyID = "AccessKeyId"
)

// pathConfig is the bare config endpoint path (operational + cloud settings).
const pathConfig = "config"

// configMetaKey holds the cloud-specific config settings that do not live in
// cloudconfig.PluginConfig, persisted so a reloaded backend can rehydrate them
// before any config write happens (KI-001).
const configMetaKey = "config_meta"

// Cloud-specific config field names, also the keys inside configMetaKey.
const (
	fieldRegion      = "region"
	fieldSTSEndpoint = "sts_endpoint"
)

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"

// maxSessionNameLen is the maximum length of an STS RoleSessionName. AWS caps
// session names at 64 characters (alphanumeric plus =,.@-_); longer names are
// truncated before the AssumeRole call.
const maxSessionNameLen = 64

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

// Session-policy role fields. These narrow an issued session below the target IAM
// role's own permissions; see validateSessionPolicies and A22.
const (
	fieldPolicyARNs   = "policy_arns"
	fieldInlinePolicy = "inline_policy"

	// maxSessionPolicyARNs is STS's documented limit on managed session policies.
	maxSessionPolicyARNs = 10
)

// Minter-set field names, constified because they appear in the schema, the
// write parser and the read response.
const (
	fieldMintersKey = "minters"
	neverExpiresKey = "never_expires"
)
