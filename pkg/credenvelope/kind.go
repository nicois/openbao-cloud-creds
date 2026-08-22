package credenvelope

import "github.com/openbao/openbao/sdk/v2/logical"

// CredentialKind names the SHAPE of the `credential` block — which keys are in it
// and what a client must do with them.
//
// # Why the shape is named rather than inferred
//
// The block is deliberately cloud-specific: an AWS session is three fields, an
// EdgeGrid credential is four, a GCP token is two. A client therefore had exactly
// one way to know what it was about to parse — knowing which cloud it had asked, and
// hard-coding the shape for it. That works until a cloud gains a SECOND shape, and
// clouds do: AWS SES over SMTP needs `{username, password}` derived from a static
// IAM key, because the SMTP protocol has nowhere to put a session token, so it
// cannot be served by the same AssumeRole path as everything else on that cloud.
// The moment that exists, "which cloud" stops determining "which shape", and every
// client that assumed otherwise misparses a payload it was never told had changed.
//
// So the kind is stated in the envelope (`metadata.credential_kind`) and a client
// may PIN it on the request (`credential_kind=<kind>` on a credential read). A
// mismatch is a specific, non-retryable error naming both kinds, which is what makes
// adding a shape backwards-compatible: an older client keeps working because it
// keeps getting the shape it asked for, or an error it can act on — never a payload
// it silently cannot read.
//
// # One kind means one key set
//
// Kinds describe the payload, not the cloud, so two clouds emitting the same keys
// share a kind (GCP and OVH both emit `{access_token, token_type}`). That is
// enforced rather than promised: the conformance registry declares each cloud's kind
// AND its key set, and a test requires every cloud sharing a kind to declare an
// identical key set. Where a shape is genuinely cloud-specific the name says so,
// because inventing a generic name for EdgeGrid's four fields would describe nothing.
type CredentialKind string

const (
	// KindSigV4Session: `{access_key_id, secret_access_key, session_token}` — an AWS
	// STS session. The session token is what makes it unusable over protocols with
	// only two credential fields.
	KindSigV4Session CredentialKind = "sigv4_session"

	// KindOAuth2Bearer: `{access_token, token_type}` — send as an Authorization
	// header. GCP and OVH both issue exactly this.
	KindOAuth2Bearer CredentialKind = "oauth2_bearer"

	// KindBasicAuth: `{username, password}` — HTTP basic auth (UpCloud). This is
	// also the shape SMTP-style credentials would take.
	KindBasicAuth CredentialKind = "basic_auth"

	// KindBearerToken: `{api_key}` — a single opaque token sent as a bearer (Vultr).
	KindBearerToken CredentialKind = "bearer_token"

	// KindScopedToken: `{token, scopes}` — a single opaque token that also reports
	// the scopes it was granted (DigitalOcean).
	KindScopedToken CredentialKind = "scoped_token"

	// KindKeySecret: `{key, secret}` — an id/secret pair used to sign requests
	// (Exoscale).
	KindKeySecret CredentialKind = "key_secret"

	// KindAzureClientSecret: `{client_id, client_secret, tenant_id}`, plus
	// `subscription_id` when the role names one — an Azure service-principal secret.
	KindAzureClientSecret CredentialKind = "azure_client_secret"

	// KindEdgeGrid: `{client_token, access_token, client_secret, host}` — Akamai's
	// EdgeGrid signing quadruple. The host is part of the credential because
	// EdgeGrid signs it.
	KindEdgeGrid CredentialKind = "edgegrid"

	// KindOCIAuthToken: `{auth_token, user_id}` — an OCI auth token used as a
	// password alongside the user it belongs to.
	KindOCIAuthToken CredentialKind = "oci_auth_token"
)

// AllCredentialKinds is the closed vocabulary. Adding one is additive and does NOT
// break a client that pins a different kind — which is the entire point of pinning.
func AllCredentialKinds() []CredentialKind {
	return []CredentialKind{
		KindSigV4Session, KindOAuth2Bearer, KindBasicAuth, KindBearerToken,
		KindScopedToken, KindKeySecret, KindAzureClientSecret, KindEdgeGrid,
		KindOCIAuthToken,
	}
}

// ValidCredentialKind reports whether kind is in the closed vocabulary.
func ValidCredentialKind(kind CredentialKind) bool {
	for _, k := range AllCredentialKinds() {
		if k == kind {
			return true
		}
	}
	return false
}

// RequireCredentialKind enforces a client's pin against what this role actually
// serves. It returns nil when the client did not pin (an unpinned read still LEARNS
// the kind, from metadata.credential_kind in the response) or when the pin matches.
//
// Called before anything is loaded or minted, deliberately: a client that cannot
// parse what this mount emits gets the cheapest possible refusal, and a pin mismatch
// must never leave a credential minted upstream for a caller that then rejected it.
func RequireCredentialKind(requested string, served CredentialKind) *logical.Response {
	if requested == "" || CredentialKind(requested) == served {
		return nil
	}
	if !ValidCredentialKind(CredentialKind(requested)) {
		return ErrorResponse(ErrCredentialKindUnsupported,
			"credential_kind %q is not a known credential shape; this role serves %q "+
				"(known shapes: %v)", requested, served, AllCredentialKinds())
	}
	return ErrorResponse(ErrCredentialKindUnsupported,
		"this role serves credential_kind %q, not the %q you asked for — ask for %q, or use a "+
			"role that serves %q", served, requested, served, requested)
}
