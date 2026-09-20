package credenvelope

import (
	"slices"

	"github.com/openbao/openbao/sdk/v2/logical"
)

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

	// KindS3Credentials: `{access_key_id, secret_access_key, endpoint, region}`, plus
	// `session_token` when the issuing cloud grants a temporary one — everything needed
	// to construct an S3 client, and nothing else.
	//
	// Named for the PROTOCOL rather than for a cloud, because the S3 API is a de-facto
	// standard and this shape is deliberately expected to be served by several plugins:
	// DigitalOcean Spaces today, and equally Exoscale SOS, Linode/Akamai Object Storage,
	// Cloudflare R2, MinIO or AWS S3 itself. A client that can parse it is configured for
	// object storage, not for a vendor, which is the whole reason to standardise it.
	//
	// Why `endpoint` and `region` are in the CREDENTIAL block rather than in metadata:
	// an S3 client cannot be constructed without them, and they are not derivable from
	// the key material. Every S3-compatible vendor uses a different host, and SigV4
	// signs a region string whether or not the vendor routes on it — so a client that
	// had to infer either would be back to hard-coding per-cloud knowledge, which is
	// precisely what naming a shape is for. They are therefore REQUIRED of every plugin
	// declaring this kind, even where the cloud's own API does not return them (DO does
	// not; the plugin derives them from the role's region).
	//
	// Why it is distinct from KindSigV4Session, which is also SigV4: that shape is an
	// expiring STS session — three fields, a session token, no endpoint. This one is a
	// long-lived object-storage key with no session token and its own endpoint. They are
	// not substitutable in either direction, so a client must be able to refuse the one
	// it cannot use.
	//
	// Why the keys are `access_key_id` and `secret_access_key` rather than the `aws_`-prefixed
	// spellings much S3 tooling uses: this shape is named for a protocol that is not AWS's, and
	// most vendors serving it are not AWS. A client wanting the prefixed names renames two
	// strings; the alternative is every non-AWS plugin emitting AWS-flavoured field names
	// permanently. Same reasoning for one `endpoint` URL rather than a host/port pair — a URL is
	// what an S3 client takes, and splitting it makes every plugin reassemble a vendor's address.
	//
	// Why `bucket_name` and `prefix` are absent, though config formats built on this shape often
	// carry them: they are the caller's configuration, not credential material. One key may be
	// used against several buckets, nothing here knows which the caller will reach for, and a
	// credential block carrying them would describe intent rather than what was issued.
	//
	// These names are load-bearing once a SECOND plugin declares this kind, because
	// TestOneCredentialKindMeansOneKeySet then holds both to the same set and renaming a key
	// becomes an api_version change. Recorded here rather than left to the first adopter.
	KindS3Credentials CredentialKind = "s3_credentials"
)

// AllCredentialKinds is the closed vocabulary. Adding one is additive and does NOT
// break a client that pins a different kind — which is the entire point of pinning.
func AllCredentialKinds() []CredentialKind {
	return []CredentialKind{
		KindSigV4Session, KindOAuth2Bearer, KindBasicAuth, KindBearerToken,
		KindScopedToken, KindKeySecret, KindAzureClientSecret, KindEdgeGrid,
		KindOCIAuthToken, KindS3Credentials,
	}
}

// ValidCredentialKind reports whether kind is in the closed vocabulary.
func ValidCredentialKind(kind CredentialKind) bool {
	return slices.Contains(AllCredentialKinds(), kind)
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
