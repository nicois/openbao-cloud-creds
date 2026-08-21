package credentialupcloud

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

func (b *backend) secretUpCloud() *framework.Secret {
	return &framework.Secret{
		Type:   "upcloud_token",
		Revoke: b.pathCredsRevoke,
		// No Renew callback, deliberately: framework.Secret.Renewable() is (Renew
		// != nil) and that is the flag the LEASE carries, so a callback that only
		// ever returns an error would still advertise renewable=true — and OpenBao
		// REVOKES a lease whose renewal fails, destroying the credential the
		// client was trying to keep. The token's expires_in is fixed at mint, so
		// the lease is non-renewable and core refuses renewal before the plugin is
		// reached (docs/ttl-semantics.md).
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get(fieldRole).(string)

	role, errResp, err := b.loadRole(ctx, req, roleName)
	if err != nil || errResp != nil {
		return errResp, err
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

	// Mint token via UpCloud API
	tokenName := fmt.Sprintf("cloud-creds-%s-%s", roleName, req.ID)
	expiresIn := fmt.Sprintf("%ds", int(role.DefaultTTL.Seconds()))
	tokenResp, httpStatus, err := client.CreateToken(ctx, tokenName, expiresIn)
	if err != nil {
		b.recordMinterError(setName, minterID, httpStatus, err, now)
		return b.issuanceError(httpStatus, err), nil
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
		Cloud: cloudName,
		Role:  roleName,
		Credential: map[string]interface{}{
			fieldUsername: client.username,
			"password":    tokenResp.Token,
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   int(role.DefaultTTL.Seconds()),
		Renewable:    false, // expires_in is fixed at mint — see pathCredsRenew
		CredentialID: tokenResp.ID,
		Scope:        role.Scopes,
		IssuedBy:     "cloud-creds-upcloud/v0.1",
		MinterSet:    setName,
		MinterID:     minterID,
	})

	// Track active token for reconciler
	activeEntry, _ := logical.StorageEntryJSON("active-tokens/"+tokenResp.ID, map[string]interface{}{
		fieldRole: roleName,
		"minter":  minterID,
		"created": now.UTC().Format(time.RFC3339),
	})
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			// Tracking write failed: revoke the just-minted upstream credential
			// so we never hand out a credential we cannot later track/reconcile
			// (audit F6). Best-effort delete.
			_, _ = client.DeleteToken(ctx, tokenResp.ID)
			b.Logger().Error("failed to persist active-token record; revoked upstream credential",
				"token_id", tokenResp.ID, "error", err)
			return credenvelope.ErrorResponse(credenvelope.ErrInternal,
				"failed to persist credential tracking record"), nil
		}
	}

	resp := b.Secret("upcloud_token").Response(env.ToMap(), map[string]interface{}{
		"upstream_token_id": tokenResp.ID,
		fieldRole:           roleName,
		fieldMinterSet:      setName,
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

	minterSet, _ := req.Secret.InternalData[fieldMinterSet].(string)
	minterID, _ := req.Secret.InternalData["minter_id"].(string)
	client, err := b.getMinter(minterSet, minterID)
	if err != nil {
		client, err = b.anyHealthyMinterInSet(minterSet)
		if err != nil {
			b.Logger().Warn("revoke: issuing minter gone and no fallback in set; "+
				"leaving credential to expire via TTL",
				"minter_set", minterSet, "minter_id", minterID)
			_ = req.Storage.Delete(ctx, "active-tokens/"+tokenID)
			return nil, nil
		}
	}

	roleName, _ := req.Secret.InternalData[fieldRole].(string)

	now := time.Now()
	httpStatus, err := client.DeleteToken(ctx, tokenID)
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
	if err := req.Storage.Delete(ctx, "active-tokens/"+tokenID); err != nil {
		b.Logger().Warn("failed to remove active token tracking", "token_id", tokenID, "error", err)
	}

	return nil, nil
}

// loadRole fetches and validates a role for issuance. It returns either the
// parsed role, or an *logical.Response describing why issuance can't proceed
// (role missing/disabled), or a hard error. Exactly one of role/errResp is
// non-nil when err is nil.
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*upcloudRole, *logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, nil, err
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName), nil
	}
	var role upcloudRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, nil, err
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName), nil
	}
	return &role, nil, nil
}

// selectedMinter bundles the result of selectMinter: the set and minter that
// were chosen plus a ready-to-use client for them.
type selectedMinter struct {
	setID    string
	minterID string
	client   *upcloudClient
}

func (b *backend) selectMinter(setName string, now time.Time) (selectedMinter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return selectedMinter{}, fmt.Errorf("upstream_auth_failed: minter set %q not loaded", setName)
	}
	apiURL := b.upcloudAPIURL()
	username := b.username
	for id, ms := range states {
		if !ms.minter.Retired && ms.sm.Selectable(now) {
			return selectedMinter{setID: setName, minterID: id, client: newUpCloudClient(apiURL, username, ms.minter.Token)}, nil
		}
	}
	return selectedMinter{}, fmt.Errorf("upstream_auth_failed: all minters in set %q are failing", setName)
}

// anyHealthyMinter returns a client for any healthy minter across all sets.
// Used by the reconciler, which lists owner-tagged tokens regardless of set.
func (b *backend) anyHealthyMinter() (*upcloudClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	apiURL := b.upcloudAPIURL()
	username := b.username
	for _, states := range b.minterSets {
		for _, ms := range states {
			if !ms.minter.Retired && ms.sm.Selectable(now) {
				return newUpCloudClient(apiURL, username, ms.minter.Token), nil
			}
		}
	}
	return nil, fmt.Errorf("upstream_auth_failed: no healthy minter available")
}

// anyHealthyMinterInSet returns a client for any healthy minter in the given
// set. Used by revoke when the issuing minter was removed after issuance.
func (b *backend) anyHealthyMinterInSet(setName string) (*upcloudClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	now := time.Now()
	apiURL := b.upcloudAPIURL()
	username := b.username
	if states, ok := b.minterSets[setName]; ok {
		for _, ms := range states {
			if !ms.minter.Retired && ms.sm.Selectable(now) {
				return newUpCloudClient(apiURL, username, ms.minter.Token), nil
			}
		}
	}
	return nil, fmt.Errorf("no healthy minter in set %q", setName)
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
