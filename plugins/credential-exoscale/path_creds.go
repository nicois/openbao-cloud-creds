package credentialexoscale

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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

func (b *backend) secretExoscale() *framework.Secret {
	return &framework.Secret{
		Type:   "exoscale_api_key",
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

	var role exoscaleRole
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

	// Mint API key via Exoscale API
	keyName := fmt.Sprintf("cloud-creds-%s-%s", roleName, req.ID)

	now := time.Now()
	keyResp, httpStatus, err := client.CreateAPIKey(ctx, keyName, role.RoleID)
	if err != nil {
		b.recordMinterError(minterID, httpStatus, now)
		return logical.ErrorResponse("upstream error: %v", err), nil
	}
	b.recordMinterSuccess(minterID, now)

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	// Exoscale keys don't have native TTL, so we compute expiry from default_ttl
	expiresAt := now.Add(role.DefaultTTL)

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: "exoscale",
		Role:  roleName,
		Credential: map[string]interface{}{
			"key": keyResp.Key,
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   int(role.DefaultTTL.Seconds()),
		Renewable:    true,
		CredentialID: keyResp.KeyID,
		Scope:        role.RoleID,
		IssuedBy:     "cloud-creds-exoscale/v0.1",
	})

	// Track active key for reconciler
	activeEntry, _ := logical.StorageEntryJSON("active-tokens/"+keyResp.KeyID, map[string]interface{}{
		"role":    roleName,
		"minter":  minterID,
		"created": now.UTC().Format(time.RFC3339),
	})
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			b.Logger().Warn("failed to track active key", "key_id", keyResp.KeyID, "error", err)
		}
	}

	resp := b.Secret("exoscale_api_key").Response(env.ToMap(), map[string]interface{}{
		"upstream_key_id": keyResp.KeyID,
		"role":            roleName,
		"minter_id":       minterID,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keyID, ok := req.Secret.InternalData["upstream_key_id"].(string)
	if !ok || keyID == "" {
		return nil, fmt.Errorf("missing upstream_key_id in internal_data")
	}

	minterID, _ := req.Secret.InternalData["minter_id"].(string)
	_, client, err := b.getMinter(minterID)
	if err != nil {
		return nil, err
	}

	roleName, _ := req.Secret.InternalData["role"].(string)

	now := time.Now()
	httpStatus, err := client.DeleteAPIKey(ctx, keyID)
	if err != nil {
		b.recordMinterError(minterID, httpStatus, now)
		emitLeaseRevokeFailed(roleName)
		return nil, fmt.Errorf("revoke failed: %v", err)
	}
	b.recordMinterSuccess(minterID, now)

	// Remove from active tokens
	if err := req.Storage.Delete(ctx, "active-tokens/"+keyID); err != nil {
		b.Logger().Warn("failed to remove active key tracking", "key_id", keyID, "error", err)
	}

	return nil, nil
}

func (b *backend) pathCredsRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = req.Secret.TTL
	resp.Secret.MaxTTL = req.Secret.MaxTTL
	return resp, nil
}

func (b *backend) selectMinter() (string, *exoscaleClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.config == nil {
		return "", nil, fmt.Errorf("upstream_auth_failed: plugin not configured")
	}

	apiURL := b.exoscaleAPIURL()

	for _, ms := range b.minters {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			return ms.minter.ID, newExoscaleClient(apiURL, ms.minter.Token), nil
		}
	}

	return "", nil, fmt.Errorf("upstream_auth_failed: all minters are failing")
}

func (b *backend) getMinter(id string) (string, *exoscaleClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.config == nil {
		return "", nil, fmt.Errorf("plugin not configured")
	}

	apiURL := b.exoscaleAPIURL()

	if ms, ok := b.minters[id]; ok {
		return id, newExoscaleClient(apiURL, ms.minter.Token), nil
	}

	// Fallback to any healthy minter
	for _, ms := range b.minters {
		if ms.sm.State() == recovery.Healthy {
			return ms.minter.ID, newExoscaleClient(apiURL, ms.minter.Token), nil
		}
	}
	return "", nil, fmt.Errorf("no healthy minter available")
}

func (b *backend) exoscaleAPIURL() string {
	if b.apiURL != "" {
		return b.apiURL
	}
	return "https://api-ch-gva-2.exoscale.com"
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
