package credentialexoscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/minteraffinity"
	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
	"github.com/nicois/openbao-cloud-creds/pkg/mintledger"
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

func (b *backend) secretExoscale() *framework.Secret {
	return &framework.Secret{
		Type:   "exoscale_api_key",
		Revoke: b.pathCredsRevoke,
		Renew:  b.pathCredsRenew,
	}
}

// loadIssuableRole fetches a role and reports why issuance cannot proceed. Split
// out so pathCredsRead stays within the function-length limit after the issuance
// log line gained the fields an operator needs (A26); credential-do has had the
// same helper for the same reason.
//
// Exactly one of role/errResp is non-nil when err is nil.
func (b *backend) loadIssuableRole(ctx context.Context, req *logical.Request, roleName string,
) (*exoscaleRole, *logical.Response) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "loading the role", err)
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound,
			"role %q does not exist", roleName)
	}
	var role exoscaleRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "parsing the stored role", err)
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled,
			"role %q is disabled", roleName)
	}
	return &role, nil
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get(fieldRole).(string)

	role, capacity, errResp := b.preflight(ctx, req, d, roleName)
	if errResp != nil {
		return errResp, nil
	}

	now := time.Now()

	sel, err := b.selectMinter(role.MinterSet, minteraffinity.KeyFromRequest(req, d), capacity, now)
	if err != nil {
		// The error carries its own code: an unloaded set is config_invalid, a
		// rate-limited set is upstream_quota_exceeded (with the remaining wait),
		// and only genuinely failing credentials are upstream_auth_failed.
		return credenvelope.ResponseFor(err), nil
	}
	setName, minterID, client := sel.setID, sel.minterID, sel.client

	// Mint API key via Exoscale API
	keyName, errResp := b.credentialName(ctx, req, roleName, req.ID)
	if errResp != nil {
		return errResp, nil
	}

	keyResp, httpStatus, err := client.CreateAPIKey(ctx, keyName, role.RoleID)
	if err != nil {
		b.recordMinterError(setName, minterID, httpStatus, err, now)
		return b.issuanceError(httpStatus, err, telemetry.IssuanceAttempt{
			Cloud: cloudName, Role: roleName, MinterSet: setName, MinterID: minterID,
			RequestID: req.ID,
		}), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	emitLeaseIssued(roleName)

	// Exoscale keys don't have native TTL, so we compute expiry from default_ttl
	expiresAt := now.Add(role.DefaultTTL)

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: cloudName,
		Role:  roleName,
		Credential: map[string]interface{}{
			"key":    keyResp.Key,
			"secret": keyResp.Secret,
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   int(role.DefaultTTL.Seconds()),
		Renewable:    true,
		CredentialID: keyResp.KeyID,
		// The API key is bound to this Exoscale IAM role.
		Scope:          role.RoleID,
		ScopeKind:      credenvelope.ScopeKindRole,
		CredentialKind: servedCredentialKind,
		IssuedBy:       "cloud-creds-exoscale/v0.1",
		MinterSet:      setName,
		MinterID:       minterID,
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
	// Record the mint in the ledger BEFORE the tracking entry. The ledger is what
	// makes this credential reclaimable later: this cloud's list API reports no
	// creation time, and the reconciler will not delete an entity whose age it
	// cannot confirm (A5). Unlike the tracking entry, the ledger entry is not
	// deleted on revoke — the leak worth cleaning up is precisely the one where the
	// upstream delete failed and the tracking entry went away.
	if err := mintledger.Record(ctx, req.Storage, a.keyID, a.now); err != nil {
		b.Logger().Warn("could not record the mint in the ledger; this credential will not be "+
			"automatically reclaimable if it leaks", "cloud", cloudName, "id", a.keyID, "error", err)
	}
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
		// Nothing here is retryable: an internal_data key that is absent will be absent
		// on every retry, and OpenBao retries a failed revoke indefinitely — so
		// returning an error wedged the lease forever while the API key it names stayed
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

func (b *backend) selectMinter(setName, affinityKey string, capacity mintercapacity.State, now time.Time) (selectedMinter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return selectedMinter{}, credenvelope.NewError(credenvelope.ErrConfigInvalid,
			http.StatusBadRequest, fmt.Sprintf("minter set %q is not loaded", setName))
	}
	apiURL := b.exoscaleAPIURL()
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
			return selectedMinter{setID: setName, minterID: id, client: newExoscaleClient(apiURL, ms.minter.Token)}, nil
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
	return nil, credenvelope.NewError(credenvelope.ErrUpstreamAuthFailed, http.StatusBadGateway,
		"no healthy minter available")
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

// preflight runs the checks that must pass before anything is minted: the caller can parse what
// this role serves, the role exists and may issue, and there is room for another credential
// somewhere in its set. Grouped because they share one property — every one of them must happen
// before a mint, and none of them costs an upstream call.
func (b *backend) preflight(ctx context.Context, req *logical.Request, d *framework.FieldData,
	roleName string,
) (*exoscaleRole, mintercapacity.State, *logical.Response) {
	// Checked first, and before any mint — see RequireCredentialKind for why.
	if errResp := credenvelope.RequireCredentialKind(
		d.Get(fieldCredentialKind).(string), servedCredentialKind); errResp != nil {
		return nil, mintercapacity.State{}, errResp
	}
	role, errResp := b.loadIssuableRole(ctx, req, roleName)
	if errResp != nil {
		return nil, mintercapacity.State{}, errResp
	}
	capacity, errResp := b.capacitySnapshot(ctx, req)
	if errResp != nil {
		return nil, capacity, errResp
	}
	return role, capacity, nil
}

// capacitySnapshot counts outstanding credentials before selection, so a minter with no room is
// passed over rather than failed on. It costs nothing when no limit is configured, which is every
// cloud whose cap is undocumented.
func (b *backend) capacitySnapshot(ctx context.Context, req *logical.Request) (mintercapacity.State, *logical.Response) {
	capacity, err := mintercapacity.Snapshot(ctx, req.Storage, activeTrackingPrefix,
		b.credentialLimitPerMinter())
	if err != nil {
		return capacity, credenvelope.InternalResponse(b.Logger().Warn,
			"counting outstanding credentials", err)
	}
	b.warnOnNearingCapacity(capacity)
	return capacity, nil
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
