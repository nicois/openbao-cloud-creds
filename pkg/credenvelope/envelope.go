// Package credenvelope provides the uniform response envelope and error codes
// for all cloud credential plugins.
package credenvelope

import "time"

// APIVersion is the current envelope schema version. Clients pin to this.
//
//	v2 added minter_set / minter_id provenance to metadata.
//	v3 added metadata.scope_kind, because metadata.scope alone meant ten different
//	   things and a client had no way to tell which (see ScopeKind).
const APIVersion = "3"

// ScopeKind says how to READ metadata.scope. It exists because `scope` was one
// field name carrying ten different meanings — a fine-grained scope list on DO, an
// ACL list on Vultr, an IAM role ARN on AWS, a service-account email on GCP, an app
// object id on Azure, a user OCID on OCI, and the literal string "all" on OVH. A
// client that wanted to display or check the privilege of a credential had to know
// which cloud it was talking to and hard-code the interpretation, which is precisely
// the coupling a uniform API is for (A28 in docs/audit-2026-08-22.md).
//
// The vocabulary is closed and small. It describes the SHAPE of the privilege
// boundary, not the cloud: two clouds with the same shape get the same kind, and a
// cloud that offers no per-credential boundary at all says so rather than inventing
// a value.
type ScopeKind string

const (
	// ScopeKindScopes: scope is a list of permission scopes the credential carries
	// (DO's `<resource>:<verb>` scopes, Akamai's apiAccess).
	ScopeKindScopes ScopeKind = "scopes"
	// ScopeKindACL: scope is a list of coarse access-control categories (Vultr).
	ScopeKindACL ScopeKind = "acl"
	// ScopeKindRole: scope names an upstream ROLE whose permissions the credential
	// assumes (AWS's IAM role ARN, Exoscale's IAM role id). The credential is not
	// that role; it acts as it.
	ScopeKindRole ScopeKind = "role"
	// ScopeKindIdentity: scope names the upstream PRINCIPAL whose credential this is
	// (GCP's service account, Azure's app registration, OCI's user). Its privilege
	// is whatever that principal has, which is not visible from here.
	ScopeKindIdentity ScopeKind = "identity"
	// ScopeKindAccount: the cloud offers no per-credential scoping — the credential
	// can do whatever the minting account can. scope is EMPTY for this kind, because
	// there is no narrowing to report and reporting one would be a lie (UpCloud, OVH).
	ScopeKindAccount ScopeKind = "account"
)

// AllScopeKinds is the closed vocabulary, for validation and for the docs. Adding
// one is an API change: a client switching on scope_kind must be able to treat an
// unknown kind as "privilege unknown" rather than mis-reading it.
func AllScopeKinds() []ScopeKind {
	return []ScopeKind{
		ScopeKindScopes, ScopeKindACL, ScopeKindRole, ScopeKindIdentity, ScopeKindAccount,
	}
}

// ValidScopeKind reports whether kind is in the closed vocabulary.
func ValidScopeKind(kind ScopeKind) bool {
	for _, k := range AllScopeKinds() {
		if k == kind {
			return true
		}
	}
	return false
}

// Metadata holds per-response metadata that clients use for version pinning
// and auditing.
type Metadata struct {
	// Scope is the privilege boundary, read according to ScopeKind. Empty when
	// ScopeKind is ScopeKindAccount.
	Scope string `json:"scope"`
	// ScopeKind says how to read Scope. Added in api_version 3.
	ScopeKind  ScopeKind `json:"scope_kind"`
	IssuedBy   string    `json:"issued_by"`
	APIVersion string    `json:"api_version"`
	// MinterSet and MinterID record which minting credential issued this
	// credential, for audit provenance.
	MinterSet string `json:"minter_set"`
	MinterID  string `json:"minter_id"`
}

// Envelope is the uniform response shape returned by all cloud credential
// plugins, regardless of strategy (native, JIT, phased rotation).
type Envelope struct {
	Cloud        string                 `json:"cloud"`
	Role         string                 `json:"role"`
	Credential   map[string]interface{} `json:"credential"`
	ExpiresAt    time.Time              `json:"expires_at"`
	TTLSeconds   int                    `json:"ttl_seconds"`
	Renewable    bool                   `json:"renewable"`
	CredentialID string                 `json:"credential_id"`
	Metadata     Metadata               `json:"metadata"`
}

// EnvelopeParams collects the inputs needed to construct an Envelope.
type EnvelopeParams struct {
	Cloud        string
	Role         string
	Credential   map[string]interface{}
	ExpiresAt    time.Time
	TTLSeconds   int
	Renewable    bool
	CredentialID string
	Scope        string
	ScopeKind    ScopeKind
	IssuedBy     string
	MinterSet    string
	MinterID     string
}

// NewEnvelope constructs an Envelope from the given parameters, stamping the
// current api_version.
func NewEnvelope(p EnvelopeParams) *Envelope {
	return &Envelope{
		Cloud:        p.Cloud,
		Role:         p.Role,
		Credential:   p.Credential,
		ExpiresAt:    p.ExpiresAt,
		TTLSeconds:   p.TTLSeconds,
		Renewable:    p.Renewable,
		CredentialID: p.CredentialID,
		Metadata: Metadata{
			Scope:      p.Scope,
			ScopeKind:  p.ScopeKind,
			IssuedBy:   p.IssuedBy,
			APIVersion: APIVersion,
			MinterSet:  p.MinterSet,
			MinterID:   p.MinterID,
		},
	}
}

// ToMap converts the Envelope to a map[string]interface{} suitable for use as
// an OpenBao logical.Response Data field.
func (e *Envelope) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"cloud":         e.Cloud,
		"role":          e.Role,
		"credential":    e.Credential,
		"expires_at":    e.ExpiresAt.UTC().Format(time.RFC3339),
		"ttl_seconds":   e.TTLSeconds,
		"renewable":     e.Renewable,
		"credential_id": e.CredentialID,
		"metadata": map[string]interface{}{
			"scope":       e.Metadata.Scope,
			"scope_kind":  string(e.Metadata.ScopeKind),
			"issued_by":   e.Metadata.IssuedBy,
			"api_version": e.Metadata.APIVersion,
			"minter_set":  e.Metadata.MinterSet,
			"minter_id":   e.Metadata.MinterID,
		},
	}
}
