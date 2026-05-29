package credentialazure

import (
	"context"
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

func (b *backend) secretAzure() *framework.Secret {
	return &framework.Secret{
		Type:   "azure_client_secret",
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

	var role azureRole
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

	// Create password credential via Graph API
	displayName := fmt.Sprintf("cloud-creds-%s-%s", roleName, req.ID)
	endDateTime := time.Now().Add(role.DefaultTTL)

	now := time.Now()
	pwResp, httpStatus, err := client.AddPassword(ctx, role.AppObjectID, displayName, endDateTime)
	if err != nil {
		b.recordMinterError(minterID, httpStatus, now)
		return logical.ErrorResponse("upstream error: %v", err), nil
	}
	b.recordMinterSuccess(minterID, now)

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	// Parse the actual endDateTime from response
	expiresAt := endDateTime
	if pwResp.EndDateTime != "" {
		if parsed, parseErr := time.Parse(time.RFC3339, pwResp.EndDateTime); parseErr == nil {
			expiresAt = parsed
		}
	}

	// Build credential map
	credential := map[string]interface{}{
		"client_id":     role.ClientID,
		"client_secret": pwResp.SecretText,
		"tenant_id":     b.getTenantID(),
	}
	if role.SubscriptionID != "" {
		credential["subscription_id"] = role.SubscriptionID
	}

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud:        "azure",
		Role:         roleName,
		Credential:   credential,
		ExpiresAt:    expiresAt,
		TTLSeconds:   int(role.DefaultTTL.Seconds()),
		Renewable:    true,
		CredentialID: pwResp.KeyID,
		Scope:        role.AppObjectID,
		IssuedBy:     "cloud-creds-azure/v0.1",
	})

	// Track active credential for reconciler
	activeEntry, _ := logical.StorageEntryJSON("active-tokens/"+pwResp.KeyID, map[string]interface{}{
		"role":          roleName,
		"minter":        minterID,
		"app_object_id": role.AppObjectID,
		"created":       now.UTC().Format(time.RFC3339),
	})
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			b.Logger().Warn("failed to track active credential", "key_id", pwResp.KeyID, "error", err)
		}
	}

	resp := b.Secret("azure_client_secret").Response(env.ToMap(), map[string]interface{}{
		"upstream_key_id": pwResp.KeyID,
		"role":            roleName,
		"minter_id":       minterID,
		"app_object_id":   role.AppObjectID,
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

	appObjectID, _ := req.Secret.InternalData["app_object_id"].(string)
	if appObjectID == "" {
		return nil, fmt.Errorf("missing app_object_id in internal_data")
	}

	minterID, _ := req.Secret.InternalData["minter_id"].(string)
	_, client, err := b.getMinter(minterID)
	if err != nil {
		return nil, err
	}

	roleName, _ := req.Secret.InternalData["role"].(string)

	now := time.Now()
	httpStatus, err := client.RemovePassword(ctx, appObjectID, keyID)
	if err != nil {
		b.recordMinterError(minterID, httpStatus, now)
		emitLeaseRevokeFailed(roleName)
		return nil, fmt.Errorf("revoke failed: %v", err)
	}
	b.recordMinterSuccess(minterID, now)

	// Remove from active tokens
	if err := req.Storage.Delete(ctx, "active-tokens/"+keyID); err != nil {
		b.Logger().Warn("failed to remove active credential tracking", "key_id", keyID, "error", err)
	}

	return nil, nil
}

func (b *backend) pathCredsRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = req.Secret.TTL
	resp.Secret.MaxTTL = req.Secret.MaxTTL
	return resp, nil
}

func (b *backend) selectMinter() (string, *azureClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.config == nil {
		return "", nil, fmt.Errorf("upstream_auth_failed: plugin not configured")
	}

	for _, ms := range b.minters {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			return ms.minter.ID, b.newClientForMinter(ms.minter), nil
		}
	}

	return "", nil, fmt.Errorf("upstream_auth_failed: all minters are failing")
}

func (b *backend) getMinter(id string) (string, *azureClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.config == nil {
		return "", nil, fmt.Errorf("plugin not configured")
	}

	if ms, ok := b.minters[id]; ok {
		return id, b.newClientForMinter(ms.minter), nil
	}

	// Fallback to any healthy minter
	for _, ms := range b.minters {
		if ms.sm.State() == recovery.Healthy {
			return ms.minter.ID, b.newClientForMinter(ms.minter), nil
		}
	}
	return "", nil, fmt.Errorf("no healthy minter available")
}

func (b *backend) newClientForMinter(m cloudconfig.Minter) *azureClient {
	parts := strings.SplitN(m.Token, ":", 2)
	clientID := parts[0]
	clientSecret := ""
	if len(parts) > 1 {
		clientSecret = parts[1]
	}
	return newAzureClient(b.tenantID, clientID, clientSecret, b.getGraphEndpoint(), b.getLoginEndpoint())
}

func (b *backend) getTenantID() string {
	if b.tenantID != "" {
		return b.tenantID
	}
	return ""
}

func (b *backend) getGraphEndpoint() string {
	if b.graphEndpoint != "" {
		return b.graphEndpoint
	}
	return "https://graph.microsoft.com"
}

func (b *backend) getLoginEndpoint() string {
	if b.loginEndpoint != "" {
		return b.loginEndpoint
	}
	return "https://login.microsoftonline.com"
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
