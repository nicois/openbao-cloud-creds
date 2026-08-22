package credentialaws

import "github.com/nicois/openbao-cloud-creds/pkg/credenvelope"

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

	// fieldCapabilityCacheTTL is the config field bounding how long a successful
	// capability probe is reused. Probes are real mints against the cloud, so an
	// unremembered fan-out re-minted on every configuration write (A29).
	fieldCapabilityCacheTTL = "capability_cache_ttl"
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
// session names at 64 characters; a longer name is fitted (not tail-truncated)
// before the AssumeRole call — see sessionNameFor.
const maxSessionNameLen = 64

// sessionNameExtraChars is the non-alphanumeric part of AWS's session-name
// character class (`[\w+=,.@-]`).
const sessionNameExtraChars = "+=,.@-_"

// sessionRequestIDKeepLen is how much of the request id survives into a session
// name that will not otherwise fit. Thirteen characters of an OpenBao request id
// is the first twelve hex digits of its UUID plus the following hyphen: enough to
// distinguish leases, and still a literal substring of the id the audit device
// records, so a session name in CloudTrail can be grepped straight back to the
// request that caused it.
const sessionRequestIDKeepLen = 13

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

// servedCredentialKind is the shape of the `credential` block this plugin emits, and
// what a client may pin with `credential_kind` on a credential read.
//
// A constant because this cloud serves exactly one shape today. When a cloud gains a
// second — AWS SES over SMTP is the live example, since the SMTP protocol has nowhere
// to put a session token — this becomes a function of the ROLE, and the pin check
// below is already the place that enforces it.
const servedCredentialKind = credenvelope.KindSigV4Session

// fieldCredentialKind is the optional request field a client uses to pin the shape it
// can parse. Omitting it still works and still tells the client what it got, in
// metadata.credential_kind.
const fieldCredentialKind = "credential_kind"
