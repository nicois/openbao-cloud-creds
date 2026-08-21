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

	// fieldRotationParams is the per-minter rotation metadata map key (carries
	// the authorizing username and, after rotation, the upstream client_id used
	// by the retired-sweep to delete the old API client).
	fieldRotationParams = "rotation_params"
	// fieldUsername is the rotation_params entry naming the Identity-Management
	// user that authorizes (and is the authorizedUser of) a minter's API client;
	// the per-account apiId is resolved from this user's allowed-apis.
	fieldUsername = "username"
	// fieldClientID is the rotation_params entry holding a minter's upstream API
	// client id (set on rotation successors; absent on operator-provided
	// originals), used by the retired-sweep to delete the upstream client.
	fieldClientID = "client_id"
	// fieldGroupID is the rotation_params entry carrying the groupId the
	// successor's API client should be granted (optional).
	fieldGroupIDParam = "group_id"
	// fieldMinterID is the rotate-endpoint field naming the minter to rotate.
	fieldMinterID = "minter_id"
	// fieldMinterRetireGrace is the config field/response key for the retirement
	// grace (seconds before a retired minter's upstream API client is swept).
	fieldMinterRetireGrace = "minter_retire_grace"
	// fieldVerifyCapability is the config field toggling the capability probe
	// (a throwaway mint-and-delete) run at minter-set and role write.
	fieldVerifyCapability = "verify_minter_capability"
)

// pathConfig is the bare config endpoint path (operational + cloud settings).
const pathConfig = "config"

// fieldAPIURL is the config field that overrides the Akamai API base URL.
const fieldAPIURL = "akamai_api_url"

// jsonKeyAPIs / jsonKeyGroups and the per-entry keys are the apiAccess /
// groupAccess request-body keys shared by issuance (roleAccess) and rotation
// (RotateMinter / successorGrants).
const (
	jsonKeyAPIs        = "apis"
	jsonKeyGroups      = "groups"
	jsonKeyAPIID       = "apiId"
	jsonKeyAccessLevel = "accessLevel"
	jsonKeyGroupID     = "groupId"
)

// fieldDefaultTTL / fieldMaxTTL are the role TTL field names.
const (
	fieldDefaultTTL = "default_ttl"
	fieldMaxTTL     = "max_ttl"
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
	// defaultMinterExpiryWarnSeconds is the default near-expiry warn threshold (7d),
	// matching cloudconfig.MinMinterGap.
	defaultMinterExpiryWarnSeconds = 604800 // 7d
	// defaultMinterRetireGraceSeconds is the default grace (7d, = cloudconfig.MinMinterGap)
	// between marking a minter retired and the retired-sweep deleting its upstream
	// API client. The grace must exceed the worst-case interval before every raft
	// node reloads the set, so no node's in-memory snapshot still selects a minter
	// whose upstream client has been deleted.
	defaultMinterRetireGraceSeconds = 604800 // 7d
)

// minterSecretLifetime is the assumed validity of a rotation successor's
// upstream credential. Akamai API-client credentials are long-lived; this value
// is used only to construct the synthetic successor for the pre-mint
// validation, so it matches the lifetime the real successor inherits (its
// originator's expiry, or never-expires).
const minterSecretLifetime = 2 * 365 * 24 * time.Hour

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

// Operational interval field names, constified because they appear in the schema,
// the write handler, the interval validation and the read response.
const (
	fieldFlushInterval    = "flush_interval"
	fieldReconcileCadence = "reconcile_cadence"
	fieldMinterExpiryWarn = "minter_expiry_warn"
)
