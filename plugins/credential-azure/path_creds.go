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
	"github.com/nicois/openbao-cloud-creds/pkg/minteraffinity"
	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
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
				fieldCredentialKind: {
					Type: framework.TypeString,
					Description: "Optional: the credential shape the caller can parse. " +
						"A mismatch is refused with credential_kind_unsupported instead of " +
						"returning a payload the caller cannot read",
				},
				minteraffinity.FieldShardKey: minteraffinity.ShardKeyField(),
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

	// Checked first, and before any mint — see RequireCredentialKind for why.
	if errResp := credenvelope.RequireCredentialKind(
		d.Get(fieldCredentialKind).(string), servedCredentialKind); errResp != nil {
		return errResp, nil
	}

	role, errResp := b.loadRole(ctx, req, roleName)
	if errResp != nil {
		return errResp, nil
	}

	now := time.Now()

	// Select a healthy minter from the role's bound set
	// Counted before selection so a minter with no room is passed over rather than failed on.
	// Costs nothing when no limit is configured, which is every cloud whose cap is unknown.
	capacity, err := mintercapacity.Snapshot(ctx, req.Storage, activeTrackingPrefix,
		b.credentialLimitPerMinter())
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "counting outstanding credentials", err), nil
	}
	b.warnOnNearingCapacity(capacity)

	sel, err := b.selectMinter(role.MinterSet, minteraffinity.KeyFromRequest(req, d), capacity, now)
	if err != nil {
		// The error carries its own code: an unloaded set is config_invalid, a
		// rate-limited set is upstream_quota_exceeded (with the remaining wait),
		// and only genuinely failing credentials are upstream_auth_failed.
		return credenvelope.ResponseFor(err), nil
	}
	setName, minterID, client := sel.setID, sel.minterID, sel.client

	// Create password credential via Graph API
	displayName, errResp := b.credentialName(ctx, req, roleName, req.ID)
	if errResp != nil {
		return errResp, nil
	}
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
		// The secret belongs to this app registration.
		Scope:          a.role.AppObjectID,
		ScopeKind:      credenvelope.ScopeKindIdentity,
		CredentialKind: servedCredentialKind,
		IssuedBy:       "cloud-creds-azure/v0.1",
		MinterSet:      a.setName,
		MinterID:       a.minterID,
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
		// Nothing here is retryable: an internal_data key that is absent will be absent
		// on every retry, and OpenBao retries a failed revoke indefinitely — so
		// returning an error wedged the lease forever while the password credential it names stayed
		// alive upstream. That is KI-002's wedge with a different cause (A30 in
		// docs/audit-2026-08-22.md).
		//
		// Releasing the lease is the lesser harm, and it is logged at ERROR because it
		// needs a human: we cannot name the upstream credential, so the owner-tag
		// reconciler will only reclaim it once its own tracking entry is gone.
		b.Logger().Error("revoke: lease internal_data is missing a required field; releasing the "+
			"lease and leaving the upstream credential to be reclaimed by hand",
			fieldCloud, cloudName, "missing_field", "upstream_key_id", "lease_id", req.Secret.LeaseID)
		return nil, nil
	}

	appObjectID, _ := req.Secret.InternalData[fieldAppObjectID].(string)
	if appObjectID == "" {
		// Nothing here is retryable: an internal_data key that is absent will be absent
		// on every retry, and OpenBao retries a failed revoke indefinitely — so
		// returning an error wedged the lease forever while the password credential it names stayed
		// alive upstream. That is KI-002's wedge with a different cause (A30 in
		// docs/audit-2026-08-22.md).
		//
		// Releasing the lease is the lesser harm, and it is logged at ERROR because it
		// needs a human: we cannot name the upstream credential, so the owner-tag
		// reconciler will only reclaim it once its own tracking entry is gone.
		b.Logger().Error("revoke: lease internal_data is missing a required field; releasing the "+
			"lease and leaving the upstream credential to be reclaimed by hand",
			fieldCloud, cloudName, "missing_field", "app_object_id", "lease_id", req.Secret.LeaseID)
		return nil, nil
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

func (b *backend) selectMinter(setName, affinityKey string, capacity mintercapacity.State, now time.Time) (selectedMinter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return selectedMinter{}, credenvelope.NewError(credenvelope.ErrConfigInvalid,
			http.StatusBadRequest, fmt.Sprintf("minter set %q is not loaded", setName))
	}
	// Affinity order, not map order. Map iteration is randomised, which spread each client's
	// requests across every minter — and so across every upstream rate-limit budget, since each
	// minter is its own credential and is metered as one (measured on DigitalOcean: per token,
	// 5000/hour each, from ONE account). Ordering by a stable key pins a client to one budget (so
	// a heavy client exhausts its own shard rather than everybody's) while leaving the rest of the
	// list as its fallback, so redundancy is unchanged. See pkg/minteraffinity.
	atCapacity := false
	for _, id := range minteraffinity.OrderKeys(affinityKey, states) {
		ms := states[id]
		if !capacity.HasRoom(id) {
			// Passed over rather than failed on: this minter holds as many credentials as its
			// account allows, and the next in preference order may not. That is what makes a set
			// scale the ceiling to (limit x minters).
			atCapacity = true
			continue
		}
		if !ms.minter.Retired && ms.sm.TryAcquire(now) {
			return selectedMinter{setID: setName, minterID: id, client: b.newClientForMinter(ms.minter)}, nil
		}
	}
	if atCapacity {
		// A different fault from an unhealthy set, and a different fix: nothing is wrong with the
		// credentials, there is simply no room. An operator adds a minter (or waits for leases to
		// expire); rotating a credential would not help and the message must not imply it.
		return selectedMinter{}, credenvelope.NewError(credenvelope.ErrPoolExhausted,
			http.StatusServiceUnavailable,
			fmt.Sprintf("every minter in set %q holds as many credentials as its account allows "+
				"(%s); add a minter to the set to raise the ceiling, or wait for leases to expire",
				setName, capacity.Describe()))
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

// credentialName resolves this mount's owner instance and builds the upstream name for
// one issued credential. The name IS the owner tag: it is what the reconciler matches on
// and what distinguishes this mount's credentials from another mount's (A19).
func (b *backend) credentialName(ctx context.Context, req *logical.Request, roleName, suffix string,
) (string, *logical.Response) {
	instanceID, err := b.ownerInstanceID(ctx, req.Storage)
	if err != nil {
		return "", credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err)
	}
	return ownertag.CredentialName(instanceID, roleName, suffix), nil
}

// activeTrackingPrefix is the storage prefix this plugin records issued credentials under. Named
// here because pkg/mintercapacity counts them, and the prefix is NOT uniform across clouds.
const activeTrackingPrefix = "active-tokens/"

// warnOnNearingCapacity tells an operator before the ceiling rather than with it. The remedy for a
// full set is adding a minter, which takes human time, so a signal that coincides with the failure
// is too late to be useful.
//
// A log line rather than a metric, deliberately: plugin metrics do not reach an operator in this
// deployment (they go to a blackhole across the plugin RPC boundary), so anything that must be seen
// is logged.
func (b *backend) warnOnNearingCapacity(capacity mintercapacity.State) {
	if !capacity.Enforced() {
		return
	}
	for id := range capacity.Used {
		if id != "" && capacity.Nearing(id) {
			b.Logger().Warn("a minter is close to the credential limit its account allows",
				fieldCloud, cloudName, "minter_id", id, "usage", capacity.Describe(),
				"note", "add a minter to this set to raise the ceiling; issuance fails once every "+
					"minter is full")
		}
	}
}

// credentialLimitPerMinter reads the configured cap under the lock, since b.config is replaced
// wholesale by a config write and a reload.
func (b *backend) credentialLimitPerMinter() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.config.CredentialLimitPerMinter()
}
