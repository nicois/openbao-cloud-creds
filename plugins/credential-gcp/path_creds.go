package credentialgcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) credsPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("role"),
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsRead},
			},
		},
	}
}

func (b *backend) secretGCP() *framework.Secret {
	return &framework.Secret{
		Type:   "gcp_access_token",
		Revoke: b.pathCredsRevoke,
		Renew:  b.pathCredsRenew,
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)

	// Load role from storage
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("role_not_found: role %q does not exist", roleName), nil
	}

	var role gcpRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	if role.Disabled {
		return logical.ErrorResponse("role_disabled: role %q is disabled", roleName), nil
	}

	// Select a healthy minter
	minterID, client, err := b.selectMinter()
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	now := time.Now()
	accessToken, expiresAt, err := client.GenerateAccessToken(ctx, role.ServiceAccountEmail, role.Scopes, role.DefaultTTL)
	if err != nil {
		b.recordMinterError(minterID, classifyGCPError(err), now)
		return logical.ErrorResponse("upstream error: %v", err), nil
	}
	b.recordMinterSuccess(minterID, now)

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	ttlSeconds := int(time.Until(expiresAt).Seconds())

	// Generate a credential ID from a hash of the token prefix (for tracking without exposing the token)
	credentialID := hashTokenPrefix(accessToken)

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: "gcp",
		Role:  roleName,
		Credential: map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "Bearer",
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   ttlSeconds,
		Renewable:    false,
		CredentialID: credentialID,
		Scope:        role.ServiceAccountEmail,
		IssuedBy:     "cloud-creds-gcp/v0.1",
	})

	// Track active credential for metrics (no upstream entity to clean up)
	activeEntry, _ := logical.StorageEntryJSON("active-tokens/"+credentialID, map[string]interface{}{
		"role":       roleName,
		"minter":     minterID,
		"created":    now.UTC().Format(time.RFC3339),
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			b.Logger().Warn("failed to track active credential", "credential_id", credentialID, "error", err)
		}
	}

	resp := b.Secret("gcp_access_token").Response(env.ToMap(), map[string]interface{}{
		"credential_id": credentialID,
		"role":          roleName,
		"minter_id":     minterID,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

// pathCredsRevoke is a no-op for GCP access tokens — they expire naturally.
// We just remove the tracking entry.
func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	credentialID, _ := req.Secret.InternalData["credential_id"].(string)
	if credentialID != "" {
		if err := req.Storage.Delete(ctx, "active-tokens/"+credentialID); err != nil {
			b.Logger().Warn("failed to remove active credential tracking", "credential_id", credentialID, "error", err)
		}
	}
	// GCP access tokens cannot be revoked — they expire at the time GCP set.
	return nil, nil
}

// pathCredsRenew returns an error — GCP access tokens cannot be renewed.
func (b *backend) pathCredsRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return logical.ErrorResponse("gcp access tokens cannot be renewed; issue a new credential instead"), nil
}

func (b *backend) selectMinter() (string, IAMCredentialsClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.config == nil {
		return "", nil, fmt.Errorf("upstream_auth_failed: plugin not configured")
	}

	for _, ms := range b.minters {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			client := b.buildIAMClient(ms.minter)
			return ms.minter.ID, client, nil
		}
	}

	return "", nil, fmt.Errorf("upstream_auth_failed: all minters are failing")
}

// buildIAMClient creates an IAM Credentials client from a minter.
// The token field stores the full service account JSON key.
func (b *backend) buildIAMClient(m cloudconfig.Minter) IAMCredentialsClient {
	if b.iamClientFn != nil {
		return b.iamClientFn(m.Token)
	}
	return newRealIAMClient(m.Token)
}

func (b *backend) recordMinterSuccess(id string, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if ms, ok := b.minters[id]; ok {
		ms.sm.RecordSuccess(at)
	}
}

func (b *backend) recordMinterError(id string, httpStatus int, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if ms, ok := b.minters[id]; ok {
		ms.sm.RecordError(httpStatus, at)
	}
}

// classifyGCPError maps GCP API errors to HTTP status codes for the state machine.
func classifyGCPError(err error) int {
	if err == nil {
		return 200
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "403") || strings.Contains(errMsg, "PERMISSION_DENIED") {
		return 403
	}
	if strings.Contains(errMsg, "401") || strings.Contains(errMsg, "UNAUTHENTICATED") || strings.Contains(errMsg, "invalid_grant") {
		return 401
	}
	if strings.Contains(errMsg, "429") || strings.Contains(errMsg, "RESOURCE_EXHAUSTED") {
		return 429
	}
	return 500
}

// hashTokenPrefix generates a short identifier from the first 8 chars of a token.
func hashTokenPrefix(token string) string {
	prefix := token
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	h := sha256.Sum256([]byte(prefix))
	return fmt.Sprintf("%x", h[:8])
}
