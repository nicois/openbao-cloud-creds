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
)

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"

// maxSessionNameLen is the maximum length of an STS RoleSessionName. AWS caps
// session names at 64 characters (alphanumeric plus =,.@-_); longer names are
// truncated before the AssumeRole call.
const maxSessionNameLen = 64
