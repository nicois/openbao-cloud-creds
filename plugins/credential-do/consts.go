package credentialdo

import "github.com/nicois/openbao-cloud-creds/pkg/credenvelope"

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "do"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName   = "name"
	fieldRole   = "role"
	fieldScopes = "scopes"
	// minterTokenKey is the field a DO PAT arrives under in a minter object, and the
	// key an issued token is returned under in the credential block. The same spelling
	// in two places; constified because goconst counts a literal package-wide,
	// including the test files.
	minterTokenKey = "token"
	fieldMinterSet = "minter_set"
	fieldCloud     = "cloud"
	// fieldDisabled is the role field that stops a role issuing without deleting it.
	// Deleting a role stops nothing: live leases stay renewable and every credential
	// already issued keeps working, so this is the only lever that closes the tap.
	fieldDisabled = "disabled"
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

	// fieldCapabilityCacheTTL is the config field bounding how long a successful
	// capability probe is reused. Probes are real mints against the cloud, so an
	// unremembered fan-out re-minted on every configuration write (A29).
	fieldCapabilityCacheTTL = "capability_cache_ttl"
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
	neverExpiresKey = "never_expires"
)

// The two credential types this plugin issues, selected per ROLE by `credential_type`.
//
//   - credentialTypeToken is a personal access token: the original shape, and the one
//     that CANNOT be minted against real DigitalOcean, because /v2/tokens is refused at
//     the edge gateway for every PAT (KI-009). Kept because it is the code-shape
//     reference the conformance and e2e layers are built on.
//   - credentialTypeSpacesKey is an S3-compatible Spaces access key: /v2/spaces/keys IS
//     reachable with a bearer PAT, so this is what the plugin can actually issue.
//
// Token is the DEFAULT, because every role written before this field existed omits it
// and must keep issuing exactly what it issued before.
const (
	credentialTypeToken     = "token"
	credentialTypeSpacesKey = "spaces_key"
)

// Role fields belonging to the Spaces credential type. Region and endpoint are role
// fields rather than config fields because one account's keys may serve buckets in
// several regions, and the endpoint is part of the credential a client is handed.
const (
	fieldCredentialType = "credential_type"
	fieldGrants         = "grants"
	fieldRegion         = "region"
	fieldEndpoint       = "endpoint"
)

// credentialKindFor names the shape of the `credential` block a role emits, which is
// what a client may pin with `credential_kind` on a credential read.
//
// A function of the ROLE rather than a constant: a cloud that gains a second credential
// type stops having "which cloud" determine "which shape", and the pin check in
// pathCredsRead is where that is enforced.
func credentialKindFor(credentialType string) credenvelope.CredentialKind {
	if credentialType == credentialTypeSpacesKey {
		return credenvelope.KindS3Credentials
	}
	return credenvelope.KindScopedToken
}

// The two lease secret types. They are distinct because their revokes are distinct — one
// deletes a token by id, the other a Spaces key by access key — and OpenBao dispatches
// revoke on the secret type, so collapsing them would send every revoke down one path.
const (
	secretTypeToken     = "do_token"
	secretTypeSpacesKey = "do_spaces_key"
)

// Keys of the S3 credential block. Named by the credential KIND rather than by this
// cloud, because credenvelope.KindS3Credentials is a shared shape: a second plugin
// serving it must emit these same four spellings, which is what the registry-wide
// one-kind-one-key-set conformance test enforces.
const (
	credKeyAccessKeyID     = "access_key_id"
	credKeySecretAccessKey = "secret_access_key"
	credKeyEndpoint        = "endpoint"
	credKeyRegion          = "region"
)

// internalKeyAccessKey is the lease internal_data key holding the issued Spaces key's
// access key — the only identifier DigitalOcean gives it, so it is what revoke deletes by.
const internalKeyAccessKey = "upstream_access_key"

// issuedBy stamps metadata.issued_by. One constant, both credential types: it identifies
// the mount's software, not the credential shape.
const issuedBy = "cloud-creds-do/v0.1"

// fieldCredentialKind is the optional request field a client uses to pin the shape it
// can parse. Omitting it still works and still tells the client what it got, in
// metadata.credential_kind.
const fieldCredentialKind = "credential_kind"
