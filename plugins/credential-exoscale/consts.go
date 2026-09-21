package credentialexoscale

import (
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/lineage"
	"github.com/nicois/openbao-cloud-creds/pkg/requester"
)

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
	// fieldDisabled is the role field that stops a role issuing without deleting it.
	// Deleting a role stops nothing: live leases stay renewable and every credential
	// already issued keeps working, so this is the only lever that closes the tap.
	fieldDisabled = "disabled"

	// fieldRequireCallerIdentity is the role field demanding a caller this mount can
	// name before anything is minted. Aliased from pkg/requester rather than spelled
	// again, so every cloud's roles answer to one field name and a report joining
	// credentials to identities cannot miss this one.
	fieldRequireCallerIdentity = requester.FieldRequireCallerIdentity
	// fieldRequireCallerLineage is the role field that refuses to issue to a caller whose
	// PARENT this mount cannot establish. Aliased from pkg/lineage for the same reason:
	// one spelling per plugin, so a report reads one vocabulary across ten clouds.
	fieldRequireCallerLineage = lineage.FieldRequireCallerLineage

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

	// fieldCapabilityCacheTTL is the config field bounding how long a successful
	// capability probe is reused. Probes are real mints against the cloud, so an
	// unremembered fan-out re-minted on every configuration write (A29).
	fieldCapabilityCacheTTL = "capability_cache_ttl"
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
	// defaultMinterExpiryWarnSeconds is the default near-expiry warn threshold (7d),
	// matching cloudconfig.MinMinterGap.
	defaultMinterExpiryWarnSeconds = 604800
	// defaultMinterRetireGraceSeconds is the default grace (7d, = cloudconfig.MinMinterGap)
	// between marking a minter retired and the retired-sweep deleting its upstream
	// key. The grace must exceed the worst-case interval before every raft node
	// has reloaded the set, so no node's in-memory snapshot still selects a minter
	// whose upstream key has been deleted.
	defaultMinterRetireGraceSeconds = 604800

	// defaultCapabilityCacheTTLSeconds is how long a successful capability probe
	// stands in for a fresh one (1h). See capability.DefaultCacheTTL for the trade:
	// without a cache, every configuration write re-mints the whole probe fan-out.
	defaultCapabilityCacheTTLSeconds = 3600
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

// servedCredentialKind is the shape of the `credential` block this plugin emits, and
// what a client may pin with `credential_kind` on a credential read.
//
// A constant because this cloud serves exactly one shape today. When a cloud gains a
// second — AWS SES over SMTP is the live example, since the SMTP protocol has nowhere
// to put a session token — this becomes a function of the ROLE, and the pin check
// below is already the place that enforces it.
const servedCredentialKind = credenvelope.KindKeySecret

// fieldCredentialKind is the optional request field a client uses to pin the shape it
// can parse. Omitting it still works and still tells the client what it got, in
// metadata.credential_kind.
const fieldCredentialKind = "credential_kind"
