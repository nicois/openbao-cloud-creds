package credentialexoscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) credsPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("role"),
			Fields: map[string]*framework.FieldSchema{
				fieldRole: {
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
	roleName := d.Get(fieldRole).(string)

	// Load role from storage
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName), nil
	}

	var role exoscaleRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	if role.Disabled {
		return credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName), nil
	}

	now := time.Now()

	// Select a healthy minter from the role's bound set
	sel, err := b.selectMinter(role.MinterSet, now)
	if err != nil {
		// selectMinter fails when the set is unloaded or every minter in it is
		// failing — both surface to the client as an upstream auth failure.
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "%s", err.Error()), nil
	}
	setName, minterID, client := sel.setID, sel.minterID, sel.client

	// Mint API key via Exoscale API
	keyName := fmt.Sprintf("cloud-creds-%s-%s", roleName, req.ID)

	keyResp, httpStatus, err := client.CreateAPIKey(ctx, keyName, role.RoleID)
	if err != nil {
		b.recordMinterError(setName, minterID, httpStatus, err, now)
		return b.issuanceError(httpStatus, err), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(setName+"/"+minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	// Exoscale keys don't have native TTL, so we compute expiry from default_ttl
	expiresAt := now.Add(role.DefaultTTL)

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: cloudName,
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
		MinterSet:    setName,
		MinterID:     minterID,
	})

	// Track active key for reconciler; compensate (revoke) on write failure.
	if errResp := b.trackActiveKey(ctx, req, trackArgs{
		client:   client,
		roleName: roleName,
		minterID: minterID,
		keyID:    keyResp.KeyID,
		now:      now,
	}); errResp != nil {
		return errResp, nil
	}

	resp := b.Secret("exoscale_api_key").Response(env.ToMap(), map[string]interface{}{
		"upstream_key_id": keyResp.KeyID,
		fieldRole:         roleName,
		fieldMinterSet:    setName,
		"minter_id":       minterID,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

// trackArgs bundles the inputs to trackActiveKey so it stays under the
// argument-count limit.
type trackArgs struct {
	client   *exoscaleClient
	roleName string
	minterID string
	keyID    string
	now      time.Time
}

// trackActiveKey persists the active-key tracking record the reconciler relies
// on. If the write fails it revokes the just-minted upstream key (best-effort)
// and returns an error response, so we never hand out a credential we cannot
// later track or reconcile (audit F6). Returns nil on success.
func (b *backend) trackActiveKey(ctx context.Context, req *logical.Request, a trackArgs) *logical.Response {
	activeEntry, _ := logical.StorageEntryJSON("active-tokens/"+a.keyID, map[string]interface{}{
		fieldRole: a.roleName,
		"minter":  a.minterID,
		"created": a.now.UTC().Format(time.RFC3339),
	})
	if activeEntry == nil {
		return nil
	}
	if err := req.Storage.Put(ctx, activeEntry); err != nil {
		_, _ = a.client.DeleteAPIKey(ctx, a.keyID)
		b.Logger().Error("failed to persist active-key record; revoked upstream credential",
			"key_id", a.keyID, "error", err)
		return credenvelope.ErrorResponse(credenvelope.ErrInternal,
			"failed to persist credential tracking record")
	}
	return nil
}

func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keyID, ok := req.Secret.InternalData["upstream_key_id"].(string)
	if !ok || keyID == "" {
		return nil, fmt.Errorf("missing upstream_key_id in internal_data")
	}

	minterSet, _ := req.Secret.InternalData[fieldMinterSet].(string)
	minterID, _ := req.Secret.InternalData["minter_id"].(string)
	client, err := b.getMinter(minterSet, minterID)
	if err != nil {
		client, err = b.anyHealthyMinterInSet(minterSet)
		if err != nil {
			// The upstream credential has no expiry of its own, so it does NOT
			// lapse when the lease does: the owner-tag reconciler is the only
			// backstop that will eventually delete it.
			b.Logger().Warn("revoke: issuing minter gone and no fallback in set; "+
				"credential left upstream for the owner-tag reconciler to delete "+
				"(it does not expire on its own)",
				"minter_set", minterSet, "minter_id", minterID)
			_ = req.Storage.Delete(ctx, "active-tokens/"+keyID)
			return nil, nil
		}
	}

	roleName, _ := req.Secret.InternalData[fieldRole].(string)

	now := time.Now()
	httpStatus, err := client.DeleteAPIKey(ctx, keyID)
	if err != nil && httpStatus != http.StatusNotFound {
		b.recordMinterError(minterSet, minterID, httpStatus, err, now)
		emitLeaseRevokeFailed(roleName)
		b.Logger().Warn("upstream credential revocation failed",
			"cloud", cloudName, "status", httpStatus, "error", err)
		return nil, fmt.Errorf("%s: upstream credential revocation failed",
			credenvelope.ErrLeaseRevokeFailed)
	}
	// 404 = already deleted upstream; treat as success.
	b.recordMinterSuccess(minterSet, minterID, now)

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

// selectedMinter bundles the result of selectMinter: the set and minter that
// were chosen plus a ready-to-use client for them.
type selectedMinter struct {
	setID    string
	minterID string
	client   *exoscaleClient
}

func (b *backend) selectMinter(setName string, now time.Time) (selectedMinter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return selectedMinter{}, fmt.Errorf("upstream_auth_failed: minter set %q not loaded", setName)
	}
	apiURL := b.exoscaleAPIURL()
	for id, ms := range states {
		if !ms.minter.Retired && ms.sm.Selectable(now) {
			return selectedMinter{setID: setName, minterID: id, client: newExoscaleClient(apiURL, ms.minter.Token)}, nil
		}
	}
	return selectedMinter{}, fmt.Errorf("upstream_auth_failed: all minters in set %q are failing", setName)
}

// anyHealthyMinter returns a client for any healthy minter across all sets.
// Used by the reconciler, which lists owner-tagged keys regardless of set.
func (b *backend) anyHealthyMinter() (*exoscaleClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	apiURL := b.exoscaleAPIURL()
	for _, states := range b.minterSets {
		for _, ms := range states {
			if !ms.minter.Retired && ms.sm.Selectable(now) {
				return newExoscaleClient(apiURL, ms.minter.Token), nil
			}
		}
	}
	return nil, fmt.Errorf("upstream_auth_failed: no healthy minter available")
}

// anyHealthyMinterInSet returns a client for any healthy minter in the given
// set. Used by revoke when the issuing minter was removed after issuance.
func (b *backend) anyHealthyMinterInSet(setName string) (*exoscaleClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	now := time.Now()
	apiURL := b.exoscaleAPIURL()
	if states, ok := b.minterSets[setName]; ok {
		for _, ms := range states {
			if !ms.minter.Retired && ms.sm.Selectable(now) {
				return newExoscaleClient(apiURL, ms.minter.Token), nil
			}
		}
	}
	return nil, fmt.Errorf("no healthy minter in set %q", setName)
}

func (b *backend) getMinter(setName, id string) (*exoscaleClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	apiURL := b.exoscaleAPIURL()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			return newExoscaleClient(apiURL, ms.minter.Token), nil
		}
	}
	return nil, fmt.Errorf("minter %q not found in set %q", id, setName)
}

// exoscaleAPIURL returns the configured API base URL. Callers MUST hold b.mu
// (read or write). It performs no locking of its own.
func (b *backend) exoscaleAPIURL() string {
	if b.apiURL != "" {
		return b.apiURL
	}
	return "https://api-ch-gva-2.exoscale.com"
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

func (b *backend) recordMinterError(setName, id string, httpStatus int, err error, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			ms.sm.RecordUpstream(httpStatus, err, at)
		}
	}
}

// issuanceError logs the raw upstream failure (operator-only) and returns a
// classified, body-free error response for the client (audit2 #4,#5).
func (b *backend) issuanceError(httpStatus int, err error) *logical.Response {
	b.Logger().Warn("upstream credential issuance failed",
		"cloud", cloudName, "status", httpStatus, "error", err)
	return credenvelope.ErrorResponse(credenvelope.Classify(httpStatus, err),
		"upstream credential issuance failed")
}
