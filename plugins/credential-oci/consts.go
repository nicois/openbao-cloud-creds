package credentialoci

import (
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/requester"
)

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "oci"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName      = "name"
	fieldRole      = "role"
	fieldCloud     = "cloud"
	fieldMinterSet = "minter_set"
	// fieldDisabled is the role field that stops a role issuing without deleting it.
	// Deleting a role stops nothing: live leases stay renewable and every credential
	// already issued keeps working, so this is the only lever that closes the tap.
	fieldDisabled  = "disabled"
	fieldSlotIndex = "slot_index"
	fieldSlotCount = "slot_count"
	fieldUserOCID  = "user_ocid"
	fieldRotation  = "rotation_period"
	// fieldMinterID names the minter targeted by the rotate endpoint.
	fieldMinterID = "minter_id"
	// fieldMinterRetireGrace is the config field/response key for the retirement
	// grace; present for a uniform config surface across all clouds. OCI uses
	// phased slot rotation and never marks a minter retired, so no sweep ever
	// consumes it.
	fieldMinterRetireGrace = "minter_retire_grace"
	// fieldVerifyCapability is the config field toggling the capability probe
	// (a throwaway mint-and-delete) run at minter-set and role write.
	fieldVerifyCapability = "verify_minter_capability"

	// fieldCapabilityCacheTTL is the config field bounding how long a successful
	// capability probe is reused. Probes are real mints against the cloud, so an
	// unremembered fan-out re-minted on every configuration write (A29).
	fieldCapabilityCacheTTL = "capability_cache_ttl"

	// fieldRequireCallerIdentity is the role field demanding a caller this mount can
	// name before it will serve a slot credential. Taken from pkg/requester rather
	// than spelled again here, so a report joining credentials to identities finds
	// the same field name on every cloud.
	fieldRequireCallerIdentity = requester.FieldRequireCallerIdentity
)

// descRoleName is the shared field description for the role-name parameter.
const descRoleName = "Name of the role"

// pathConfig is the bare config endpoint path, and the storage key the
// operational config is written under.
const pathConfig = "config"

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"

const (
	// healthCheckInterval is how often the health-check worker probes minters,
	// and the recovery state machine's re-probe cadence.
	healthCheckInterval = 5 * time.Minute

	// authFailThreshold is how long upstream auth must keep failing before the
	// recovery state machine declares a minter hard-failed.
	authFailThreshold = 30 * time.Second
)

// Operational interval field names, constified because they appear in the schema,
// the write handler, the interval validation and the read response.
const (
	fieldReconcileCadence      = "reconcile_cadence"
	fieldMinterExpiryWarn      = "minter_expiry_warn"
	fieldRotationCheckInterval = "rotation_check_interval"
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
const servedCredentialKind = credenvelope.KindOCIAuthToken

// fieldCredentialKind is the optional request field a client uses to pin the shape it
// can parse. Omitting it still works and still tells the client what it got, in
// metadata.credential_kind.
const fieldCredentialKind = "credential_kind"
