package credentialvultr

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

func (b *backend) secretVultr() *framework.Secret {
	return &framework.Secret{
		Type:   "vultr_user",
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

	var role vultrRole
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

	// Build user name and email using lease ID
	leaseShortID := req.ID
	if len(leaseShortID) > 8 {
		leaseShortID = leaseShortID[:8]
	}
	userName := fmt.Sprintf("cloud-creds-%s-%s", roleName, leaseShortID)
	emailDomain := role.EmailDomain
	if emailDomain == "" {
		emailDomain = "managed.local"
	}
	userEmail := fmt.Sprintf("cloud-creds-%s-%s@%s", roleName, leaseShortID, emailDomain)

	// Parse ACLs
	acls := strings.Split(role.ACLs, ",")
	for i := range acls {
		acls[i] = strings.TrimSpace(acls[i])
	}

	// Create sub-user via Vultr API
	now := time.Now()
	userResp, httpStatus, err := client.CreateUser(ctx, userName, userEmail, acls)
	if err != nil {
		b.recordMinterError(minterID, httpStatus, now)
		return logical.ErrorResponse("upstream error: %v", err), nil
	}
	b.recordMinterSuccess(minterID, now)

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	expiresAt := now.Add(role.DefaultTTL)
	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: "vultr",
		Role:  roleName,
		Credential: map[string]interface{}{
			"api_key": userResp.User.APIKey,
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   int(role.DefaultTTL.Seconds()),
		Renewable:    true,
		CredentialID: userResp.User.ID,
		Scope:        role.ACLs,
		IssuedBy:     "cloud-creds-vultr/v0.1",
	})

	// Track active user for reconciler
	activeEntry, _ := logical.StorageEntryJSON("active-users/"+userResp.User.ID, map[string]interface{}{
		"role":    roleName,
		"minter":  minterID,
		"created": now.UTC().Format(time.RFC3339),
	})
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			b.Logger().Warn("failed to track active user", "user_id", userResp.User.ID, "error", err)
		}
	}

	resp := b.Secret("vultr_user").Response(env.ToMap(), map[string]interface{}{
		"upstream_user_id": userResp.User.ID,
		"role":             roleName,
		"minter_id":        minterID,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	userID, ok := req.Secret.InternalData["upstream_user_id"].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("missing upstream_user_id in internal_data")
	}

	minterID, _ := req.Secret.InternalData["minter_id"].(string)
	_, client, err := b.getMinter(minterID)
	if err != nil {
		return nil, err
	}

	roleName, _ := req.Secret.InternalData["role"].(string)

	now := time.Now()
	httpStatus, err := client.DeleteUser(ctx, userID)
	if err != nil {
		b.recordMinterError(minterID, httpStatus, now)
		emitLeaseRevokeFailed(roleName)
		return nil, fmt.Errorf("revoke failed: %v", err)
	}
	b.recordMinterSuccess(minterID, now)

	// Remove from active users
	if err := req.Storage.Delete(ctx, "active-users/"+userID); err != nil {
		b.Logger().Warn("failed to remove active user tracking", "user_id", userID, "error", err)
	}

	return nil, nil
}

func (b *backend) pathCredsRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = req.Secret.TTL
	resp.Secret.MaxTTL = req.Secret.MaxTTL
	return resp, nil
}

func (b *backend) selectMinter() (string, *vultrClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.config == nil {
		return "", nil, fmt.Errorf("upstream_auth_failed: plugin not configured")
	}

	apiURL := b.vultrAPIURL()

	for _, ms := range b.minters {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			return ms.minter.ID, newVultrClient(apiURL, ms.minter.Token), nil
		}
	}

	return "", nil, fmt.Errorf("upstream_auth_failed: all minters are failing")
}

func (b *backend) getMinter(id string) (string, *vultrClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.config == nil {
		return "", nil, fmt.Errorf("plugin not configured")
	}

	apiURL := b.vultrAPIURL()

	if ms, ok := b.minters[id]; ok {
		return id, newVultrClient(apiURL, ms.minter.Token), nil
	}

	// Fallback to any healthy minter
	for _, ms := range b.minters {
		if ms.sm.State() == recovery.Healthy {
			return ms.minter.ID, newVultrClient(apiURL, ms.minter.Token), nil
		}
	}
	return "", nil, fmt.Errorf("no healthy minter available")
}

func (b *backend) vultrAPIURL() string {
	if b.apiURL != "" {
		return b.apiURL
	}
	return "https://api.vultr.com"
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
