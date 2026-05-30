package credentialakamai

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

func (b *backend) secretAkamai() *framework.Secret {
	return &framework.Secret{
		Type:   "akamai_client",
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

	var role akamaiRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	if role.Disabled {
		return credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName), nil
	}

	// Select a healthy minter from the role's bound set
	setName, minterID, client, err := b.selectMinter(role.MinterSet)
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "%s", err.Error()), nil
	}

	// Build client name using lease ID
	leaseShortID := req.ID
	if len(leaseShortID) > 8 {
		leaseShortID = leaseShortID[:8]
	}
	clientName := fmt.Sprintf("cloud-creds-%s-%s", roleName, leaseShortID)

	// Build API access and group access from role config
	var apiAccess interface{}
	if role.APIAccess != "" {
		if err := json.Unmarshal([]byte(role.APIAccess), &apiAccess); err != nil {
			apiAccess = map[string]interface{}{"apis": []interface{}{}}
		}
	} else {
		apiAccess = map[string]interface{}{"apis": []interface{}{}}
	}

	var groupAccess interface{}
	if role.GroupID > 0 {
		groupAccess = map[string]interface{}{
			"groups": []interface{}{
				map[string]interface{}{"groupId": role.GroupID},
			},
		}
	} else {
		groupAccess = map[string]interface{}{"groups": []interface{}{}}
	}

	// Create API client via Akamai API
	now := time.Now()
	clientResp, httpStatus, err := client.CreateClient(ctx, clientName, apiAccess, groupAccess)
	if err != nil {
		b.recordMinterError(setName, minterID, httpStatus, now)
		return credenvelope.ErrorResponse(credenvelope.ErrInternal, "upstream error: %v", err), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	if len(clientResp.Credentials) == 0 {
		return credenvelope.ErrorResponse(credenvelope.ErrInternal, "no credentials returned from Akamai"), nil
	}

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(setName+"/"+minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	cred := clientResp.Credentials[0]
	b.mu.RLock()
	host := b.host
	b.mu.RUnlock()

	expiresAt := now.Add(role.DefaultTTL)
	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: "akamai",
		Role:  roleName,
		Credential: map[string]interface{}{
			"client_token":  cred.ClientToken,
			"access_token":  cred.AccessToken,
			"client_secret": cred.ClientSecret,
			"host":          host,
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   int(role.DefaultTTL.Seconds()),
		Renewable:    true,
		CredentialID: clientResp.ClientID,
		Scope:        role.APIAccess,
		IssuedBy:     "cloud-creds-akamai/v0.1",
		MinterSet:    setName,
		MinterID:     minterID,
	})

	// Track active client for reconciler
	activeEntry, _ := logical.StorageEntryJSON("active-clients/"+clientResp.ClientID, map[string]interface{}{
		"role":       roleName,
		"minter_set": setName,
		"minter":     minterID,
		"created":    now.UTC().Format(time.RFC3339),
	})
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			b.Logger().Warn("failed to track active client", "client_id", clientResp.ClientID, "error", err)
		}
	}

	resp := b.Secret("akamai_client").Response(env.ToMap(), map[string]interface{}{
		"upstream_client_id": clientResp.ClientID,
		"role":               roleName,
		"minter_set":         setName,
		"minter_id":          minterID,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	clientID, ok := req.Secret.InternalData["upstream_client_id"].(string)
	if !ok || clientID == "" {
		return nil, fmt.Errorf("missing upstream_client_id in internal_data")
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
			_ = req.Storage.Delete(ctx, "active-clients/"+clientID)
			return nil, nil
		}
	}

	roleName, _ := req.Secret.InternalData["role"].(string)

	now := time.Now()
	httpStatus, err := client.DeleteClient(ctx, clientID)
	if err != nil && httpStatus != 404 {
		b.recordMinterError(minterSet, minterID, httpStatus, now)
		emitLeaseRevokeFailed(roleName)
		return nil, fmt.Errorf("revoke failed: %v", err)
	}
	// 404 = already deleted upstream; treat as success.
	b.recordMinterSuccess(minterSet, minterID, now)

	// Remove from active clients
	if err := req.Storage.Delete(ctx, "active-clients/"+clientID); err != nil {
		b.Logger().Warn("failed to remove active client tracking", "client_id", clientID, "error", err)
	}

	return nil, nil
}

func (b *backend) pathCredsRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = req.Secret.TTL
	resp.Secret.MaxTTL = req.Secret.MaxTTL
	return resp, nil
}

// clientFor builds an EdgeGrid-signing Akamai client from a specific minter's
// triple plus the configured host. Callers MUST hold b.mu (read or write).
func (b *backend) clientFor(ms *minterState) (*akamaiClient, error) {
	cred, err := parseEdgeGridToken(ms.minter.Token)
	if err != nil {
		return nil, err
	}
	cred.Host = b.host
	return newAkamaiClient(b.akamaiAPIURL(), cred), nil
}

func (b *backend) selectMinter(setName string) (setID, minterID string, client *akamaiClient, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return "", "", nil, fmt.Errorf("upstream_auth_failed: minter set %q not loaded", setName)
	}
	for id, ms := range states {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			c, err := b.clientFor(ms)
			if err != nil {
				continue
			}
			return setName, id, c, nil
		}
	}
	return "", "", nil, fmt.Errorf("upstream_auth_failed: all minters in set %q are failing", setName)
}

// anyHealthyMinter returns a client for any healthy minter across all sets.
// Used by the reconciler, which lists owner-tagged clients regardless of set.
func (b *backend) anyHealthyMinter() (*akamaiClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, states := range b.minterSets {
		for _, ms := range states {
			if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
				c, err := b.clientFor(ms)
				if err != nil {
					continue
				}
				return c, nil
			}
		}
	}
	return nil, fmt.Errorf("upstream_auth_failed: no healthy minter available")
}

// anyHealthyMinterInSet returns a client for any healthy minter in the given
// set. Used by revoke when the issuing minter was removed after issuance.
func (b *backend) anyHealthyMinterInSet(setName string) (*akamaiClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if states, ok := b.minterSets[setName]; ok {
		for _, ms := range states {
			if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
				c, err := b.clientFor(ms)
				if err != nil {
					continue
				}
				return c, nil
			}
		}
	}
	return nil, fmt.Errorf("no healthy minter in set %q", setName)
}

func (b *backend) getMinter(setName, id string) (*akamaiClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			return b.clientFor(ms)
		}
	}
	return nil, fmt.Errorf("minter %q not found in set %q", id, setName)
}

func (b *backend) akamaiAPIURL() string {
	if b.apiURL != "" {
		return b.apiURL
	}
	return "https://" + b.host
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
