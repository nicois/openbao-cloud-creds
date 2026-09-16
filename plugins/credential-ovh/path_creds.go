package credentialovh

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/minteraffinity"
	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
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

func (b *backend) secretOVH() *framework.Secret {
	return &framework.Secret{
		Type:   "ovh_access_token",
		Revoke: b.pathCredsRevoke,
		// No Renew callback, deliberately: framework.Secret.Renewable() is (Renew
		// != nil) and that is the flag the LEASE carries, so a callback that only
		// ever returns an error would still advertise renewable=true — and OpenBao
		// REVOKES a lease whose renewal fails, destroying the credential the
		// client was trying to keep. An OVH token is a fixed 1h with no extend and
		// no revoke call, so the lease is non-renewable and core refuses renewal
		// before the plugin is reached (docs/ttl-semantics.md).
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
		// selectMinter fails when the set is unloaded or every minter in it is
		// failing — both surface to the client as an upstream auth failure. The
		// error string carries an "upstream_auth_failed: " prefix for internal
		// use; strip it so the envelope helper doesn't double-prefix.
		msg := strings.TrimPrefix(err.Error(), string(credenvelope.ErrUpstreamAuthFailed)+": ")
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "%s", msg), nil
	}
	setName, minterID, client := sel.setID, sel.minterID, sel.client

	accessToken, expiresIn, err := client.MintToken(ctx)
	if err != nil {
		status := classifyOVHError(err)
		b.recordMinterError(setName, minterID, status, err, now)
		return b.issuanceError(status, err, telemetry.IssuanceAttempt{
			Cloud: cloudName, Role: roleName, MinterSet: setName, MinterID: minterID,
			RequestID: req.ID,
		}), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	return b.buildCredsResponse(ctx, req, credsResponseArgs{
		role: role, roleName: roleName, sel: sel, accessToken: accessToken,
		expiresIn: expiresIn, now: now,
	}), nil
}

// credsResponseArgs bundles the inputs to buildCredsResponse, so splitting the handler
// does not mean threading seven parameters through it.
type credsResponseArgs struct {
	role        *ovhRole
	roleName    string
	sel         selectedMinter
	accessToken string
	expiresIn   int
	now         time.Time
}

// buildCredsResponse assembles the envelope, records the tracking entry and returns the
// lease. Split from the mint so the handler reads as decide-then-mint and this reads as
// report-what-was-minted.
func (b *backend) buildCredsResponse(ctx context.Context, req *logical.Request, args credsResponseArgs) *logical.Response {
	role, roleName, now := args.role, args.roleName, args.now
	setName, minterID := args.sel.setID, args.sel.minterID
	accessToken, expiresIn := args.accessToken, args.expiresIn

	emitLeaseIssued(roleName)

	expiresAt := now.Add(time.Duration(expiresIn) * time.Second)
	ttlSeconds := expiresIn

	// This cloud's token carries no upstream id, so the request id stands in — see
	// OpaqueCredentialID for why, and for what it does and does not claim to identify.
	credentialID := credenvelope.OpaqueCredentialID(req.ID)

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
		// OVH tokens carry the whole account's privilege: there is no per-token scoping.
		// `scope` was the literal string "all", which read like a value rather than the
		// absence of one.
		Scope:          "",
		ScopeKind:      credenvelope.ScopeKindAccount,
		CredentialKind: servedCredentialKind,
		IssuedBy:       "cloud-creds-ovh/v0.1",
		MinterSet:      setName,
		MinterID:       minterID,
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
			// Tracking is metrics-only here: OAuth2 tokens auto-expire and the
			// reconciler never deletes an upstream entity, so an untracked
			// credential is harmless (it self-expires). We keep the issued
			// credential and only lose a metrics datapoint (audit F6: N/A for
			// no-revoke plugins).
			b.Logger().Warn("failed to track active credential (metrics-only; OAuth2 token self-expires)",
				"credential_id", credentialID, "error", err)
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

	return resp
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

// loadRole fetches and validates a role for issuance. It returns either the
// parsed role, or an *logical.Response describing why issuance can't proceed
// (role missing/disabled), or a hard error. Exactly one of role/errResp is
// non-nil when err is nil.
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*ovhRole, *logical.Response) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "loading the role", err)
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName)
	}
	var role ovhRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "parsing the stored role", err)
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName)
	}
	return &role, nil
}

// selectedMinter bundles the result of selectMinter: the set and minter that
// were chosen plus a ready-to-use client for them.
type selectedMinter struct {
	setID    string
	minterID string
	client   TokenClient
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
			return selectedMinter{setID: setName, minterID: id, client: b.buildTokenClient(ms.minter)}, nil
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

// OVHErrorCodes maps the cloud's own textual error codes to a status. Bare
// digit substrings are deliberately absent: matching "403" against a whole error
// string found it inside request ids and account numbers, so a 500 was classified
// as an authorization failure and indicted a healthy minter (A16 in
// docs/audit-2026-08-22.md).
var ovhErrorCodes = map[string]int{
	"invalid_client":  http.StatusUnauthorized,
	"invalid_request": http.StatusBadRequest,
	"invalid_scope":   http.StatusBadRequest,
}

// httpStatusInError extracts the status this plugin's own client formats into its
// errors as "(HTTP nnn)" — a delimited marker we write ourselves, so it cannot be
// confused with a digit that happens to appear in an identifier.
var httpStatusInError = regexp.MustCompile(`\(HTTP (\d{3})\)`)

// classifyOVHError maps a OVH error to the HTTP status it represents, or
// credenvelope.StatusNone when nothing recognises it, in which case
// credenvelope.Classify inspects the error itself.
func classifyOVHError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	errMsg := err.Error()

	if m := httpStatusInError.FindStringSubmatch(errMsg); m != nil {
		if status, convErr := strconv.Atoi(m[1]); convErr == nil && status > 0 {
			return status
		}
	}
	for code, status := range ovhErrorCodes {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(code) + `\b`).MatchString(errMsg) {
			return status
		}
	}
	return credenvelope.StatusNone
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
