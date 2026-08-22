package credentialazure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/nicois/openbao-cloud-creds/pkg/telemetry"
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

func (b *backend) secretAzure() *framework.Secret {
	return &framework.Secret{
		Type:   "azure_client_secret",
		Revoke: b.pathCredsRevoke,
		// No Renew callback, deliberately: framework.Secret.Renewable() is (Renew
		// != nil) and that is the flag the LEASE carries, so a callback that only
		// ever returns an error would still advertise renewable=true — and OpenBao
		// REVOKES a lease whose renewal fails, destroying the credential the
		// client was trying to keep. The client secret's endDateTime is fixed at
		// mint, so the lease is non-renewable and core refuses renewal before the
		// plugin is reached (docs/ttl-semantics.md).
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get(fieldRole).(string)

	role, errResp := b.loadRole(ctx, req, roleName)
	if errResp != nil {
		return errResp, nil
	}

	now := time.Now()

	// Select a healthy minter from the role's bound set
	sel, err := b.selectMinter(role.MinterSet, now)
	if err != nil {
		// The error carries its own code: an unloaded set is config_invalid, a
		// rate-limited set is upstream_quota_exceeded (with the remaining wait),
		// and only genuinely failing credentials are upstream_auth_failed.
		return credenvelope.ResponseFor(err), nil
	}
	setName, minterID, client := sel.setID, sel.minterID, sel.client

	// Create password credential via Graph API
	displayName := fmt.Sprintf("cloud-creds-%s-%s", roleName, req.ID)
	endDateTime := now.Add(role.DefaultTTL)
	pwResp, httpStatus, err := client.AddPassword(ctx, role.AppObjectID, displayName, endDateTime)
	if err != nil {
		b.recordMinterError(setName, minterID, httpStatus, err, now)
		return b.issuanceError(httpStatus, err, telemetry.IssuanceAttempt{
			Cloud: cloudName, Role: roleName, MinterSet: setName, MinterID: minterID,
			RequestID: req.ID,
		}), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(setName+"/"+minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	env := b.buildEnvelope(envelopeArgs{
		role:        role,
		roleName:    roleName,
		pwResp:      pwResp,
		endDateTime: endDateTime,
		setName:     setName,
		minterID:    minterID,
	})

	// Track active credential for reconciler
	activeEntry, _ := logical.StorageEntryJSON("active-tokens/"+pwResp.KeyID, map[string]interface{}{
		fieldRole:        roleName,
		"minter":         minterID,
		fieldAppObjectID: role.AppObjectID,
		"created":        now.UTC().Format(time.RFC3339),
	})
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			// Tracking write failed: revoke the just-minted upstream credential
			// so we never hand out a credential we cannot later track/reconcile
			// (audit F6). Best-effort delete.
			_, _ = client.RemovePassword(ctx, role.AppObjectID, pwResp.KeyID)
			b.Logger().Error("failed to persist active-credential record; revoked upstream credential",
				"key_id", pwResp.KeyID, "error", err)
			return credenvelope.ErrorResponse(credenvelope.ErrInternal,
				"failed to persist credential tracking record"), nil
		}
	}

	resp := b.Secret("azure_client_secret").Response(env.ToMap(), map[string]interface{}{
		"upstream_key_id": pwResp.KeyID,
		fieldRole:         roleName,
		fieldMinterSet:    setName,
		"minter_id":       minterID,
		fieldAppObjectID:  role.AppObjectID,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

// envelopeArgs carries everything buildEnvelope needs to assemble a response
// envelope for a freshly minted Azure client secret.
type envelopeArgs struct {
	role        *azureRole
	roleName    string
	pwResp      *addPasswordResponse
	endDateTime time.Time
	setName     string
	minterID    string
}

// buildEnvelope assembles the response envelope for a freshly minted Azure
// client secret, including the cloud-specific credential map and the actual
// expiry parsed back from the Graph addPassword response.
func (b *backend) buildEnvelope(a envelopeArgs) *credenvelope.Envelope {
	// Parse the actual endDateTime from response
	expiresAt := a.endDateTime
	if a.pwResp.EndDateTime != "" {
		if parsed, parseErr := time.Parse(time.RFC3339, a.pwResp.EndDateTime); parseErr == nil {
			expiresAt = parsed
		}
	}

	// NOTE: a freshly-added client_secret may fail auth (AADSTS7000215) for a
	// few seconds due to Entra directory replication lag — see
	// docs/known-issues.md (KI-003). Self-heals; clients should retry a
	// transient 401 immediately after issuance.
	credential := map[string]interface{}{
		fieldClientID:   a.role.ClientID,
		"client_secret": a.pwResp.SecretText,
		fieldTenantID:   b.getTenantID(),
	}
	if a.role.SubscriptionID != "" {
		credential["subscription_id"] = a.role.SubscriptionID
	}

	return credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud:        cloudName,
		Role:         a.roleName,
		Credential:   credential,
		ExpiresAt:    expiresAt,
		TTLSeconds:   int(a.role.DefaultTTL.Seconds()),
		Renewable:    false, // endDateTime is fixed at mint — see pathCredsRenew
		CredentialID: a.pwResp.KeyID,
		Scope:        a.role.AppObjectID,
		IssuedBy:     "cloud-creds-azure/v0.1",
		MinterSet:    a.setName,
		MinterID:     a.minterID,
	})
}

// loadRole fetches and validates a role for issuance. It returns either the
// parsed role, or an *logical.Response describing why issuance can't proceed
// (role missing/disabled), or a hard error. Exactly one of role/errResp is
// non-nil when err is nil.
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*azureRole, *logical.Response) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "loading the role", err)
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName)
	}
	var role azureRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "parsing the stored role", err)
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName)
	}
	return &role, nil
}

func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keyID, ok := req.Secret.InternalData["upstream_key_id"].(string)
	if !ok || keyID == "" {
		return nil, fmt.Errorf("missing upstream_key_id in internal_data")
	}

	appObjectID, _ := req.Secret.InternalData[fieldAppObjectID].(string)
	if appObjectID == "" {
		return nil, fmt.Errorf("missing app_object_id in internal_data")
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
			_ = req.Storage.Delete(ctx, "active-tokens/"+keyID)
			return nil, nil
		}
	}

	roleName, _ := req.Secret.InternalData[fieldRole].(string)

	now := time.Now()
	httpStatus, err := client.RemovePassword(ctx, appObjectID, keyID)
	if err != nil && httpStatus != http.StatusNotFound {
		b.recordMinterError(minterSet, minterID, httpStatus, err, now)
		emitLeaseRevokeFailed(roleName)
		b.Logger().Warn("upstream credential revocation failed",
			"cloud", cloudName, "status", httpStatus, "error", err)
		return nil, fmt.Errorf("%s: upstream credential revocation failed",
			credenvelope.ErrLeaseRevokeFailed)
	}
	// 404 = already removed upstream; treat as success.
	b.recordMinterSuccess(minterSet, minterID, now)

	// Remove from active tokens
	if err := req.Storage.Delete(ctx, "active-tokens/"+keyID); err != nil {
		b.Logger().Warn("failed to remove active credential tracking", "key_id", keyID, "error", err)
	}

	return nil, nil
}

// selectedMinter bundles the result of selectMinter: the set and minter that
// were chosen plus a ready-to-use client for them.
type selectedMinter struct {
	setID    string
	minterID string
	client   *azureClient
}

func (b *backend) selectMinter(setName string, now time.Time) (selectedMinter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return selectedMinter{}, credenvelope.NewError(credenvelope.ErrConfigInvalid,
			http.StatusBadRequest, fmt.Sprintf("minter set %q is not loaded", setName))
	}
	for id, ms := range states {
		if !ms.minter.Retired && ms.sm.TryAcquire(now) {
			return selectedMinter{setID: setName, minterID: id, client: b.newClientForMinter(ms.minter)}, nil
		}
	}
	return selectedMinter{}, recovery.UnavailableError(setName, machinesOf(states), now)
}

// anyHealthyMinter returns a client for any healthy minter across all sets.
// Used by the reconciler, which lists owner-tagged credentials regardless of set.
func (b *backend) anyHealthyMinter() (*azureClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	for _, states := range b.minterSets {
		for _, ms := range states {
			if !ms.minter.Retired && ms.sm.Selectable(now) {
				return b.newClientForMinter(ms.minter), nil
			}
		}
	}
	return nil, credenvelope.NewError(credenvelope.ErrUpstreamAuthFailed, http.StatusBadGateway,
		"no healthy minter available")
}

// anyHealthyMinterInSet returns a client for any healthy minter in the given
// set. Used by revoke when the issuing minter was removed after issuance.
func (b *backend) anyHealthyMinterInSet(setName string) (*azureClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	now := time.Now()
	if states, ok := b.minterSets[setName]; ok {
		for _, ms := range states {
			if !ms.minter.Retired && ms.sm.Selectable(now) {
				return b.newClientForMinter(ms.minter), nil
			}
		}
	}
	return nil, fmt.Errorf("no healthy minter in set %q", setName)
}

func (b *backend) getMinter(setName, id string) (*azureClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			return b.newClientForMinter(ms.minter), nil
		}
	}
	return nil, fmt.Errorf("minter %q not found in set %q", id, setName)
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
func (b *backend) issuanceError(httpStatus int, err error, attempt telemetry.IssuanceAttempt) *logical.Response {
	b.Logger().Warn("upstream credential issuance failed", attempt.LogFields(httpStatus, err)...)
	return credenvelope.ErrorResponse(credenvelope.Classify(httpStatus, err),
		"upstream credential issuance failed")
}
