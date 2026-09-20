package credentialakamai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/minteraffinity"
	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/nicois/openbao-cloud-creds/pkg/requester"
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

func (b *backend) secretAkamai() *framework.Secret {
	return &framework.Secret{
		Type:   "akamai_client",
		Revoke: b.pathCredsRevoke,
		Renew:  b.pathCredsRenew,
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

	// Before a minter is picked and before anything is minted: a role that demands an
	// identifiable caller must cost the upstream nothing when it refuses one.
	if resp := requester.Enforce(req, role.RequireCallerIdentity); resp != nil {
		return resp, nil
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
		return credenvelope.ResponseFor(err), nil
	}

	clientName, errResp := b.credentialName(ctx, req, roleName, leaseShortID(req.ID))
	if errResp != nil {
		return errResp, nil
	}
	apiAccess, groupAccess := roleAccess(role)

	clientResp, httpStatus, err := sel.client.CreateClient(ctx, clientName, apiAccess, groupAccess)
	if err != nil {
		b.recordMinterError(sel.setID, sel.minterID, httpStatus, err, now)
		return b.issuanceError(httpStatus, err, telemetry.IssuanceAttempt{
			Cloud: cloudName, Role: roleName, MinterSet: sel.setID, MinterID: sel.minterID,
			RequestID: req.ID,
		}), nil
	}
	b.recordMinterSuccess(sel.setID, sel.minterID, now)

	if len(clientResp.Credentials) == 0 {
		return credenvelope.ErrorResponse(credenvelope.ErrInternal, "no credentials returned from Akamai"), nil
	}

	emitLeaseIssued(roleName)

	return b.buildCredsResponse(ctx, req, credsResponseArgs{
		role:       role,
		roleName:   roleName,
		setName:    sel.setID,
		minterID:   sel.minterID,
		client:     sel.client,
		clientResp: clientResp,
		now:        now,
	}), nil
}

// credsResponseArgs bundles the inputs needed to build the issuance response so
// the helper stays under the argument-count limit.
type credsResponseArgs struct {
	role       *akamaiRole
	roleName   string
	setName    string
	minterID   string
	client     *akamaiClient
	clientResp *createClientResponse
	now        time.Time
}

// buildCredsResponse assembles the response envelope, records the active client
// for the reconciler, and wraps it in a secret with the role's TTLs.
func (b *backend) buildCredsResponse(ctx context.Context, req *logical.Request, a credsResponseArgs) *logical.Response {
	cred := a.clientResp.Credentials[0]
	b.mu.RLock()
	host := b.host
	b.mu.RUnlock()

	expiresAt := a.now.Add(a.role.DefaultTTL)
	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: cloudName,
		Role:  a.roleName,
		Credential: map[string]interface{}{
			"client_token":  cred.ClientToken,
			"access_token":  cred.AccessToken,
			"client_secret": cred.ClientSecret,
			fieldHost:       host,
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   int(a.role.DefaultTTL.Seconds()),
		Renewable:    true,
		CredentialID: a.clientResp.ClientID,
		// Akamai apiAccess is the list of APIs the client may call.
		Scope:          a.role.APIAccess,
		ScopeKind:      credenvelope.ScopeKindScopes,
		CredentialKind: servedCredentialKind,
		IssuedBy:       "cloud-creds-akamai/v0.1",
		MinterSet:      a.setName,
		MinterID:       a.minterID,
	})

	// Track active client for reconciler
	activeEntry, _ := logical.StorageEntryJSON("active-clients/"+a.clientResp.ClientID,
		requester.Stamp(map[string]interface{}{
			fieldRole:      a.roleName,
			fieldMinterSet: a.setName,
			"minter":       a.minterID,
			"created":      a.now.UTC().Format(time.RFC3339),
		}, req))
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			// Tracking write failed: revoke the just-minted upstream credential
			// so we never hand out a credential we cannot later track/reconcile
			// (audit F6). Best-effort delete.
			_, _ = a.client.DeleteClient(ctx, a.clientResp.ClientID)
			b.Logger().Error("failed to persist active-client record; revoked upstream credential",
				"client_id", a.clientResp.ClientID, "error", err)
			return credenvelope.ErrorResponse(credenvelope.ErrInternal,
				"failed to persist credential tracking record")
		}
	}

	resp := b.Secret("akamai_client").Response(env.ToMap(), map[string]interface{}{
		"upstream_client_id": a.clientResp.ClientID,
		fieldRole:            a.roleName,
		fieldMinterSet:       a.setName,
		"minter_id":          a.minterID,
	})
	resp.Secret.TTL = a.role.DefaultTTL
	resp.Secret.MaxTTL = a.role.MaxTTL

	return resp
}

// leaseShortID truncates the lease/request ID to a short, human-readable prefix
// used when naming the upstream API client.
func leaseShortID(id string) string {
	if len(id) > leaseShortIDLen {
		return id[:leaseShortIDLen]
	}
	return id
}

// roleAccess derives the Akamai apiAccess and groupAccess request bodies from a
// role's config, falling back to empty access when unset or unparseable.
func roleAccess(role *akamaiRole) (apiAccess, groupAccess interface{}) {
	if role.APIAccess != "" {
		if err := json.Unmarshal([]byte(role.APIAccess), &apiAccess); err != nil {
			apiAccess = map[string]interface{}{jsonKeyAPIs: []interface{}{}}
		}
	} else {
		apiAccess = map[string]interface{}{jsonKeyAPIs: []interface{}{}}
	}

	if role.GroupID > 0 {
		groupAccess = map[string]interface{}{
			jsonKeyGroups: []interface{}{
				map[string]interface{}{jsonKeyGroupID: role.GroupID},
			},
		}
	} else {
		groupAccess = map[string]interface{}{jsonKeyGroups: []interface{}{}}
	}
	return apiAccess, groupAccess
}

// loadRole fetches and validates a role for issuance. It returns either the
// parsed role, or an *logical.Response describing why issuance can't proceed
// (role missing/disabled), or a hard error. Exactly one of role/errResp is
// non-nil when err is nil.
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*akamaiRole, *logical.Response) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "loading the role", err)
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName)
	}
	var role akamaiRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "parsing the stored role", err)
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName)
	}
	return &role, nil
}

func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	clientID, ok := req.Secret.InternalData["upstream_client_id"].(string)
	if !ok || clientID == "" {
		// Nothing here is retryable: an internal_data key that is absent will be absent
		// on every retry, and OpenBao retries a failed revoke indefinitely — so
		// returning an error wedged the lease forever while the API client it names stayed
		// alive upstream. That is KI-002's wedge with a different cause (A30 in
		// docs/audit-2026-08-22.md).
		//
		// Releasing the lease is the lesser harm, and it is logged at ERROR because it
		// needs a human: we cannot name the upstream credential, so the owner-tag
		// reconciler will only reclaim it once its own tracking entry is gone.
		b.Logger().Error("revoke: lease internal_data is missing a required field; releasing the "+
			"lease and leaving the upstream credential to be reclaimed by hand",
			fieldCloud, cloudName, "missing_field", "upstream_client_id", "lease_id", req.Secret.LeaseID)
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
			_ = req.Storage.Delete(ctx, "active-clients/"+clientID)
			return nil, nil
		}
	}

	roleName, _ := req.Secret.InternalData[fieldRole].(string)

	now := time.Now()
	httpStatus, err := client.DeleteClient(ctx, clientID)
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

// selectedMinter bundles the result of selectMinter: the set and minter that
// were chosen plus a ready-to-use client for them.
type selectedMinter struct {
	setID    string
	minterID string
	client   *akamaiClient
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
			c, err := b.clientFor(ms)
			if err != nil {
				continue
			}
			return selectedMinter{setID: setName, minterID: id, client: c}, nil
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
// Used by the reconciler, which lists owner-tagged clients regardless of set.
func (b *backend) anyHealthyMinter() (*akamaiClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	for _, states := range b.minterSets {
		for _, ms := range states {
			if !ms.minter.Retired && ms.sm.Selectable(now) {
				c, err := b.clientFor(ms)
				if err != nil {
					continue
				}
				return c, nil
			}
		}
	}
	return nil, credenvelope.NewError(credenvelope.ErrUpstreamAuthFailed, http.StatusBadGateway,
		"no healthy minter available")
}

// anyHealthyMinterInSet returns a client for any healthy minter in the given
// set. Used by revoke when the issuing minter was removed after issuance.
func (b *backend) anyHealthyMinterInSet(setName string) (*akamaiClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	now := time.Now()
	if states, ok := b.minterSets[setName]; ok {
		for _, ms := range states {
			if !ms.minter.Retired && ms.sm.Selectable(now) {
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
const activeTrackingPrefix = "active-clients/"

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
