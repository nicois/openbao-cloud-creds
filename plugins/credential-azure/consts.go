package credentialazure

import (
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/lineage"
	"github.com/nicois/openbao-cloud-creds/pkg/requester"
)

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "azure"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName      = "name"
	fieldRole      = "role"
	fieldMinterSet = "minter_set"
	// fieldDisabled is the role field that stops a role issuing without deleting it.
	// Deleting a role stops nothing: live leases stay renewable and every credential
	// already issued keeps working, so this is the only lever that closes the tap.
	fieldDisabled = "disabled"
	// fieldRequireCallerIdentity is the role field demanding that a credential is only
	// issued to a caller this mount can name, refused before anything is minted. Aliased
	// from pkg/requester rather than respelled so every cloud answers to one field name.
	fieldRequireCallerIdentity = requester.FieldRequireCallerIdentity
	// fieldRequireCallerLineage is the role field that refuses to issue to a caller whose
	// PARENT this mount cannot establish. Aliased from pkg/lineage for the same reason:
	// one spelling per plugin, so a report reads one vocabulary across ten clouds.
	fieldRequireCallerLineage = lineage.FieldRequireCallerLineage
	fieldCloud                = "cloud"
	fieldTenantID             = "tenant_id"
	fieldClientID             = "client_id"
	fieldAppObjectID          = "app_object_id"

	// fieldDefaultTTL / fieldMaxTTL are the role TTL field names.
	fieldDefaultTTL = "default_ttl"
	fieldMaxTTL     = "max_ttl"

	// fieldRotationParams is the per-minter rotation metadata map key (carries
	// app_object_id and, after rotation, the upstream key_id used by the
	// retired-sweep to removePassword the old secret).
	fieldRotationParams = "rotation_params"
	// fieldKeyID is the rotation_params entry holding a minter's upstream Graph
	// password keyId (set on rotation successors; absent on operator-provided
	// originals).
	fieldKeyID = "key_id"
	// fieldMinterID is the rotate-endpoint field naming the minter to rotate.
	fieldMinterID = "minter_id"
	// fieldMinterRetireGrace is the config field/response key for the retirement
	// grace (seconds before a retired minter's upstream credential is swept).
	fieldMinterRetireGrace = "minter_retire_grace"
	// fieldVerifyCapability is the config field toggling the capability probe
	// (a throwaway mint-and-delete) run at minter-set and role write.
	fieldVerifyCapability = "verify_minter_capability"

	// fieldCapabilityCacheTTL is the config field bounding how long a successful
	// capability probe is reused. Probes are real mints against the cloud, so an
	// unremembered fan-out re-minted on every configuration write (A29).
	fieldCapabilityCacheTTL = "capability_cache_ttl"
)

// pathConfig is the bare config endpoint path (operational + cloud settings).
const pathConfig = "config"

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"

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
const servedCredentialKind = credenvelope.KindAzureClientSecret

// fieldCredentialKind is the optional request field a client uses to pin the shape it
// can parse. Omitting it still works and still tells the client what it got, in
// metadata.credential_kind.
const fieldCredentialKind = "credential_kind"
