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
		return credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName), nil
	}

	var role vultrRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	if role.Disabled {
		return credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName), nil
	}

	// Select a healthy minter from the role's bound set
	setName, minterID, client, err := b.selectMinter(role.MinterSet)
	if err != nil {
		// selectMinter fails when the set is unloaded or every minter in it is
		// failing — both surface to the client as an upstream auth failure.
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "%s", err.Error()), nil
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
		b.recordMinterError(setName, minterID, httpStatus, now)
		// We can't reliably classify the upstream failure (status/quota/timeout)
		// at this layer, so ErrInternal is the honest, stable code to return.
		return credenvelope.ErrorResponse(credenvelope.ErrInternal, "upstream error: %v", err), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(setName+"/"+minterID, roleName, now)
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
		MinterSet:    setName,
		MinterID:     minterID,
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
		"minter_set":       setName,
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

	minterSet, _ := req.Secret.InternalData["minter_set"].(string)
	minterID, _ := req.Secret.InternalData["minter_id"].(string)
	client, err := b.getMinter(minterSet, minterID)
	if err != nil {
		client, err = b.anyHealthyMinterInSet(minterSet)
		if err != nil {
			b.Logger().Warn("revoke: issuing minter gone and no fallback in set; "+
				"leaving credential to expire via TTL",
				"minter_set", minterSet, "minter_id", minterID)
			_ = req.Storage.Delete(ctx, "active-users/"+userID)
			return nil, nil
		}
	}

	roleName, _ := req.Secret.InternalData["role"].(string)

	now := time.Now()
	httpStatus, err := client.DeleteUser(ctx, userID)
	if err != nil && httpStatus != 404 {
		b.recordMinterError(minterSet, minterID, httpStatus, now)
		emitLeaseRevokeFailed(roleName)
		return nil, fmt.Errorf("revoke failed: %v", err)
	}
	// 404 = already deleted upstream; treat as success.
	b.recordMinterSuccess(minterSet, minterID, now)

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

func (b *backend) selectMinter(setName string) (setID, minterID string, client *vultrClient, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return "", "", nil, fmt.Errorf("upstream_auth_failed: minter set %q not loaded", setName)
	}
	apiURL := b.vultrAPIURL()
	for id, ms := range states {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			return setName, id, newVultrClient(apiURL, ms.minter.Token), nil
		}
	}
	return "", "", nil, fmt.Errorf("upstream_auth_failed: all minters in set %q are failing", setName)
}

// anyHealthyMinter returns a client for any healthy minter across all sets.
// Used by the reconciler, which lists owner-tagged sub-users regardless of set.
func (b *backend) anyHealthyMinter() (*vultrClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	apiURL := b.vultrAPIURL()
	for _, states := range b.minterSets {
		for _, ms := range states {
			if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
				return newVultrClient(apiURL, ms.minter.Token), nil
			}
		}
	}
	return nil, fmt.Errorf("upstream_auth_failed: no healthy minter available")
}

// anyHealthyMinterInSet returns a client for any healthy minter in the given
// set. Used by revoke when the issuing minter was removed after issuance.
func (b *backend) anyHealthyMinterInSet(setName string) (*vultrClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	apiURL := b.vultrAPIURL()
	if states, ok := b.minterSets[setName]; ok {
		for _, ms := range states {
			if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
				return newVultrClient(apiURL, ms.minter.Token), nil
			}
		}
	}
	return nil, fmt.Errorf("no healthy minter in set %q", setName)
}

func (b *backend) getMinter(setName, id string) (*vultrClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	apiURL := b.vultrAPIURL()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			return newVultrClient(apiURL, ms.minter.Token), nil
		}
	}
	return nil, fmt.Errorf("minter %q not found in set %q", id, setName)
}

// vultrAPIURL returns the configured API base URL. Callers MUST hold b.mu
// (read or write). It performs no locking of its own.
func (b *backend) vultrAPIURL() string {
	if b.apiURL != "" {
		return b.apiURL
	}
	return "https://api.vultr.com"
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
