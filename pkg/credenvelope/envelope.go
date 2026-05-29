// Package credenvelope provides the uniform response envelope and error codes
// for all cloud credential plugins.
package credenvelope

import "time"

// Metadata holds per-response metadata that clients use for version pinning
// and auditing.
type Metadata struct {
	Scope      string `json:"scope"`
	IssuedBy   string `json:"issued_by"`
	APIVersion string `json:"api_version"`
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
	IssuedBy     string
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
			IssuedBy:   p.IssuedBy,
			APIVersion: "1",
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
			"issued_by":   e.Metadata.IssuedBy,
			"api_version": e.Metadata.APIVersion,
		},
	}
}
