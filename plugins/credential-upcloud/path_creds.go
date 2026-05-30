package credentialupcloud

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

func (b *backend) secretUpCloud() *framework.Secret {
	return &framework.Secret{
		Type:   "upcloud_token",
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

	var role upcloudRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	if role.Disabled {
		return logical.ErrorResponse("role_disabled: role %q is disabled", roleName), nil
	}

	// Select a healthy minter from the role's bound set
	setName, minterID, client, err := b.selectMinter(role.MinterSet)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Mint token via UpCloud API
	tokenName := fmt.Sprintf("cloud-creds-%s-%s", roleName, req.ID)
	expiresIn := fmt.Sprintf("%ds", int(role.DefaultTTL.Seconds()))

	now := time.Now()
	tokenResp, httpStatus, err := client.CreateToken(ctx, tokenName, expiresIn)
	if err != nil {
		b.recordMinterError(setName, minterID, httpStatus, now)
		return logical.ErrorResponse("upstream error: %v", err), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(setName+"/"+minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	// Parse expires_at from UpCloud response
	expiresAt, err := time.Parse(time.RFC3339, tokenResp.ExpiresAt)
	if err != nil {
		// Fallback to computed expiry
		expiresAt = now.Add(role.DefaultTTL)
	}

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: "upcloud",
		Role:  roleName,
		Credential: map[string]interface{}{
			"username": client.username,
			"password": tokenResp.Token,
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   int(role.DefaultTTL.Seconds()),
		Renewable:    true,
		CredentialID: tokenResp.ID,
		Scope:        role.Scopes,
		IssuedBy:     "cloud-creds-upcloud/v0.1",
		MinterSet:    setName,
		MinterID:     minterID,
	})

	// Track active token for reconciler
	activeEntry, _ := logical.StorageEntryJSON("active-tokens/"+tokenResp.ID, map[string]interface{}{
		"role":    roleName,
		"minter":  minterID,
		"created": now.UTC().Format(time.RFC3339),
	})
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			b.Logger().Warn("failed to track active token", "token_id", tokenResp.ID, "error", err)
		}
	}

	resp := b.Secret("upcloud_token").Response(env.ToMap(), map[string]interface{}{
		"upstream_token_id": tokenResp.ID,
		"role":              roleName,
		"minter_set":        setName,
		"minter_id":         minterID,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenID, ok := req.Secret.InternalData["upstream_token_id"].(string)
	if !ok || tokenID == "" {
		return nil, fmt.Errorf("missing upstream_token_id in internal_data")
	}

	minterSet, _ := req.Secret.InternalData["minter_set"].(string)
	minterID, _ := req.Secret.InternalData["minter_id"].(string)
	client, err := b.getMinter(minterSet, minterID)
	if err != nil {
		return nil, err
	}

	roleName, _ := req.Secret.InternalData["role"].(string)

	now := time.Now()
	httpStatus, err := client.DeleteToken(ctx, tokenID)
	if err != nil {
		b.recordMinterError(minterSet, minterID, httpStatus, now)
		emitLeaseRevokeFailed(roleName)
		return nil, fmt.Errorf("revoke failed: %v", err)
	}
	b.recordMinterSuccess(minterSet, minterID, now)

	// Remove from active tokens
	if err := req.Storage.Delete(ctx, "active-tokens/"+tokenID); err != nil {
		b.Logger().Warn("failed to remove active token tracking", "token_id", tokenID, "error", err)
	}

	return nil, nil
}

func (b *backend) pathCredsRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = req.Secret.TTL
	resp.Secret.MaxTTL = req.Secret.MaxTTL
	return resp, nil
}

func (b *backend) selectMinter(setName string) (setID, minterID string, client *upcloudClient, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return "", "", nil, fmt.Errorf("upstream_auth_failed: minter set %q not loaded", setName)
	}
	apiURL := b.upcloudAPIURL()
	username := b.username
	for id, ms := range states {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			return setName, id, newUpCloudClient(apiURL, username, ms.minter.Token), nil
		}
	}
	return "", "", nil, fmt.Errorf("upstream_auth_failed: all minters in set %q are failing", setName)
}

// anyHealthyMinter returns a client for any healthy minter across all sets.
// Used by the reconciler, which lists owner-tagged tokens regardless of set.
func (b *backend) anyHealthyMinter() (*upcloudClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	apiURL := b.upcloudAPIURL()
	username := b.username
	for _, states := range b.minterSets {
		for _, ms := range states {
			if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
				return newUpCloudClient(apiURL, username, ms.minter.Token), nil
			}
		}
	}
	return nil, fmt.Errorf("upstream_auth_failed: no healthy minter available")
}

func (b *backend) getMinter(setName, id string) (*upcloudClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	apiURL := b.upcloudAPIURL()
	username := b.username
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			return newUpCloudClient(apiURL, username, ms.minter.Token), nil
		}
	}
	return nil, fmt.Errorf("minter %q not found in set %q", id, setName)
}

// upcloudAPIURL returns the configured API base URL. Callers MUST hold b.mu
// (read or write). It performs no locking of its own.
func (b *backend) upcloudAPIURL() string {
	if b.apiURL != "" {
		return b.apiURL
	}
	return "https://api.upcloud.com"
}

func (b *backend) recordMinterSuccess(setName, id string, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			ms.sm.RecordSuccess(at)
		}
	}
}

func (b *backend) recordMinterError(setName, id string, httpStatus int, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			ms.sm.RecordError(httpStatus, at)
		}
	}
}
