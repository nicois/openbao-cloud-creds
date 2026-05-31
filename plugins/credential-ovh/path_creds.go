package credentialovh

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
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

func (b *backend) secretOVH() *framework.Secret {
	return &framework.Secret{
		Type:   "ovh_access_token",
		Revoke: b.pathCredsRevoke,
		Renew:  b.pathCredsRenew,
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get(fieldRole).(string)

	role, errResp, err := b.loadRole(ctx, req, roleName)
	if err != nil || errResp != nil {
		return errResp, err
	}

	// Select a healthy minter from the role's bound set
	sel, err := b.selectMinter(role.MinterSet)
	if err != nil {
		// selectMinter fails when the set is unloaded or every minter in it is
		// failing — both surface to the client as an upstream auth failure. The
		// error string carries an "upstream_auth_failed: " prefix for internal
		// use; strip it so the envelope helper doesn't double-prefix.
		msg := strings.TrimPrefix(err.Error(), string(credenvelope.ErrUpstreamAuthFailed)+": ")
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "%s", msg), nil
	}
	setName, minterID, client := sel.setID, sel.minterID, sel.client

	now := time.Now()
	accessToken, expiresIn, err := client.MintToken(ctx)
	if err != nil {
		b.recordMinterError(setName, minterID, classifyOVHError(err), now)
		// We can't reliably classify the OAuth2 token-minting failure at this
		// layer, so ErrInternal is the honest, stable code to return.
		return credenvelope.ErrorResponse(credenvelope.ErrInternal, "upstream error: %v", err), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(setName+"/"+minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	expiresAt := now.Add(time.Duration(expiresIn) * time.Second)
	ttlSeconds := expiresIn

	// Generate a credential ID from a hash of the token prefix (for tracking without exposing the token)
	credentialID := hashTokenPrefix(accessToken)

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: cloudName,
		Role:  roleName,
		Credential: map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "Bearer",
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   ttlSeconds,
		Renewable:    false,
		CredentialID: credentialID,
		Scope:        "all",
		IssuedBy:     "cloud-creds-ovh/v0.1",
		MinterSet:    setName,
		MinterID:     minterID,
	})

	// Track active credential for metrics (no upstream entity to clean up)
	activeEntry, _ := logical.StorageEntryJSON("active-tokens/"+credentialID, map[string]interface{}{
		fieldRole:    roleName,
		"minter":     minterID,
		"created":    now.UTC().Format(time.RFC3339),
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			b.Logger().Warn("failed to track active credential", "credential_id", credentialID, "error", err)
		}
	}

	resp := b.Secret("ovh_access_token").Response(env.ToMap(), map[string]interface{}{
		"credential_id": credentialID,
		fieldRole:       roleName,
		fieldMinterSet:  setName,
		"minter_id":     minterID,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

// pathCredsRevoke is a no-op for OVH access tokens — they expire naturally.
// We just remove the tracking entry. Unlike the JIT clouds (e.g. DigitalOcean),
// there is no upstream entity to delete, so we do NOT resolve the minter that
// issued this credential; minter_set is read only for log context.
func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	credentialID, _ := req.Secret.InternalData["credential_id"].(string)
	minterSet, _ := req.Secret.InternalData["minter_set"].(string)
	if credentialID != "" {
		if err := req.Storage.Delete(ctx, "active-tokens/"+credentialID); err != nil {
			b.Logger().Warn("failed to remove active credential tracking",
				"credential_id", credentialID, "minter_set", minterSet, "error", err)
		}
	}
	// OVH access tokens cannot be revoked — they expire at the time OVH set.
	return nil, nil
}

// pathCredsRenew returns an error — OVH access tokens cannot be renewed.
func (b *backend) pathCredsRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return logical.ErrorResponse("ovh access tokens cannot be renewed; issue a new credential instead"), nil
}

// loadRole fetches and validates a role for issuance. It returns either the
// parsed role, or an *logical.Response describing why issuance can't proceed
// (role missing/disabled), or a hard error. Exactly one of role/errResp is
// non-nil when err is nil.
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*ovhRole, *logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, nil, err
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName), nil
	}
	var role ovhRole
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
	client   TokenClient
}

func (b *backend) selectMinter(setName string) (selectedMinter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return selectedMinter{}, fmt.Errorf("upstream_auth_failed: minter set %q not loaded", setName)
	}
	for id, ms := range states {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			return selectedMinter{setID: setName, minterID: id, client: b.buildTokenClient(ms.minter)}, nil
		}
	}
	return selectedMinter{}, fmt.Errorf("upstream_auth_failed: all minters in set %q are failing", setName)
}

// buildTokenClient creates a token client from a minter. The token field stores
// client_id:client_secret. Callers MUST hold b.mu (read or write); it performs
// no locking of its own (it reads b.tokenEndpoint and b.tokenClientFn).
func (b *backend) buildTokenClient(m cloudconfig.Minter) TokenClient {
	clientID, clientSecret, _ := parseMinterToken(m.Token)
	endpoint := b.tokenEndpoint

	if b.tokenClientFn != nil {
		return b.tokenClientFn(clientID, clientSecret, endpoint)
	}
	return newRealTokenClient(clientID, clientSecret, endpoint)
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

// classifyOVHError maps OVH OAuth2 errors to HTTP status codes for the state machine.
func classifyOVHError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "401") || strings.Contains(errMsg, "invalid_client") {
		return http.StatusUnauthorized
	}
	if strings.Contains(errMsg, "403") {
		return http.StatusForbidden
	}
	if strings.Contains(errMsg, "429") {
		return http.StatusTooManyRequests
	}
	return http.StatusInternalServerError
}

// tokenHashPrefixLen is how many leading characters of an access token feed the
// credential-ID hash — enough to make the identifier unique without hashing the
// full secret.
const tokenHashPrefixLen = 16

// hashTokenPrefix generates a short identifier from the first 16 chars of a token.
func hashTokenPrefix(token string) string {
	prefix := token
	if len(prefix) > tokenHashPrefixLen {
		prefix = prefix[:tokenHashPrefixLen]
	}
	h := sha256.Sum256([]byte(prefix))
	return fmt.Sprintf("%x", h[:8])
}
