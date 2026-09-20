package credentialgcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/minteraffinity"
	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
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

func (b *backend) secretGCP() *framework.Secret {
	return &framework.Secret{
		Type:   "gcp_access_token",
		Revoke: b.pathCredsRevoke,
		// No Renew callback, deliberately: framework.Secret.Renewable() is (Renew
		// != nil) and that is the flag the LEASE carries, so a callback that only
		// ever returns an error would still advertise renewable=true — and OpenBao
		// REVOKES a lease whose renewal fails, destroying the credential the
		// client was trying to keep. An impersonation token's lifetime is fixed at
		// mint and cannot be extended, so the lease is non-renewable and core
		// refuses renewal before the plugin is reached (docs/ttl-semantics.md).
	}
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

	accessToken, expiresAt, err := client.GenerateAccessToken(ctx, role.ServiceAccountEmail, role.Scopes, role.DefaultTTL)
	if err != nil {
		status := classifyGCPError(err)
		b.recordMinterError(setName, minterID, status, err, now)
		return b.issuanceError(status, err, telemetry.IssuanceAttempt{
			Cloud: cloudName, Role: roleName, MinterSet: setName, MinterID: minterID,
			RequestID: req.ID,
		}), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	emitLeaseIssued(roleName)

	ttlSeconds := int(time.Until(expiresAt).Seconds())

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
		// The token impersonates this service account; role scopes narrow it further.
		Scope:          role.ServiceAccountEmail,
		ScopeKind:      credenvelope.ScopeKindIdentity,
		CredentialKind: servedCredentialKind,
		IssuedBy:       "cloud-creds-gcp/v0.1",
		MinterSet:      setName,
		MinterID:       minterID,
	})

	// Track active credential for metrics (no upstream entity to clean up)
	activeEntry, _ := logical.StorageEntryJSON(activeTrackingPrefix+credentialID,
		requester.Stamp(map[string]interface{}{
			fieldRole:    roleName,
			"minter":     minterID,
			"created":    now.UTC().Format(time.RFC3339),
			"expires_at": expiresAt.UTC().Format(time.RFC3339),
		}, req))
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			// Tracking is metrics-only here: access tokens auto-expire and the
			// reconciler never deletes an upstream entity, so an untracked
			// credential is harmless (it self-expires). We keep the issued
			// credential and only lose a metrics datapoint (audit F6: N/A for
			// no-revoke plugins).
			b.Logger().Warn("failed to track active credential (metrics-only; access token self-expires)",
				"credential_id", credentialID, "error", err)
		}
	}

	resp := b.Secret("gcp_access_token").Response(env.ToMap(), map[string]interface{}{
		"credential_id": credentialID,
		fieldRole:       roleName,
		fieldMinterSet:  setName,
		"minter_id":     minterID,
	})
	// The lease is derived from the expiry Google actually returned — the same one
	// the envelope publishes — not from the role's TTL: generateAccessToken may
	// cap the lifetime, and the round trip itself consumes wall-clock, so a lease
	// built from the role TTL can outlive the token it names (techrfc OBC-002).
	resp.Secret.TTL = leaseTTL(ttlSeconds)
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

// pathCredsRevoke is a no-op for GCP access tokens — they expire naturally.
// We just remove the tracking entry. Unlike the JIT clouds (e.g. DigitalOcean),
// there is no upstream entity to delete, so we do NOT resolve the minter that
// issued this credential; minter_set is read only for log context.
func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	credentialID, _ := req.Secret.InternalData["credential_id"].(string)
	minterSet, _ := req.Secret.InternalData[fieldMinterSet].(string)
	if credentialID != "" {
		if err := req.Storage.Delete(ctx, activeTrackingPrefix+credentialID); err != nil {
			b.Logger().Warn("failed to remove active credential tracking",
				"credential_id", credentialID, "minter_set", minterSet, "error", err)
		}
	}
	// GCP access tokens cannot be revoked — they expire at the time GCP set.
	return nil, nil
}

// selectedMinter bundles the result of selectMinter: the set and minter that
// were chosen plus a ready-to-use client for them. The client is an
// IAMCredentialsClient because GCP injects its client (see buildIAMClient).
type selectedMinter struct {
	setID    string
	minterID string
	client   IAMCredentialsClient
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
			return selectedMinter{setID: setName, minterID: id, client: b.buildIAMClient(ms.minter)}, nil
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

// minLeaseTTL is the floor for a lease derived from an upstream expiry: a zero
// TTL means "use the mount default" to core, which is never what a near-expiry
// credential wants.
const minLeaseTTL = time.Second

// leaseTTL converts the credential's remaining lifetime in seconds into the
// lease duration. A non-positive value would make core fall back to the mount's
// default lease, which could far outlive an already-expiring credential, so it
// is floored at minLeaseTTL instead.
func leaseTTL(remainingSeconds int) time.Duration {
	if remainingSeconds < 1 {
		return minLeaseTTL
	}
	return time.Duration(remainingSeconds) * time.Second
}

// loadRole fetches and validates a role for issuance. It returns either the
// parsed role, or an *logical.Response describing why issuance can't proceed
// (role missing/disabled), or a hard error. Exactly one of role/errResp is
// non-nil when err is nil.
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*gcpRole, *logical.Response) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "loading the role", err)
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName)
	}
	var role gcpRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "parsing the stored role", err)
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName)
	}
	return &role, nil
}

// buildIAMClient creates an IAM Credentials client from a minter. The token
// field stores the full service account JSON key. Callers MUST hold b.mu
// (read or write); it performs no locking of its own.
func (b *backend) buildIAMClient(m cloudconfig.Minter) IAMCredentialsClient {
	if b.iamClientFn != nil {
		return b.iamClientFn(m.Token)
	}
	return newRealIAMClient(m.Token)
}

// buildSAKeyClient creates a service-account key-management client from a
// minter's SA JSON (its Token), honoring the injected saKeyClientFn factory when
// set (tests inject a fake). Callers MUST hold b.mu (read or write); it performs
// no locking of its own. This is the KEY-MANAGEMENT client used by rotation, NOT
// the impersonation issuance client.
func (b *backend) buildSAKeyClient(m cloudconfig.Minter) SAKeyClient {
	if b.saKeyClientFn != nil {
		return b.saKeyClientFn(m.Token)
	}
	return newRealSAKeyClient(m.Token)
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

// GCPErrorCodes maps the cloud's own textual error codes to a status. Bare
// digit substrings are deliberately absent: matching "403" against a whole error
// string found it inside request ids and account numbers, so a 500 was classified
// as an authorization failure and indicted a healthy minter (A16 in
// docs/audit-2026-08-22.md).
var gcpErrorCodes = map[string]int{
	"PERMISSION_DENIED":   http.StatusForbidden,
	"UNAUTHENTICATED":     http.StatusUnauthorized,
	"invalid_grant":       http.StatusUnauthorized,
	"RESOURCE_EXHAUSTED":  http.StatusTooManyRequests,
	"INVALID_ARGUMENT":    http.StatusBadRequest,
	"FAILED_PRECONDITION": http.StatusBadRequest,
}

// httpStatusInError extracts the status this plugin's own client formats into its
// errors as "(HTTP nnn)" — a delimited marker we write ourselves, so it cannot be
// confused with a digit that happens to appear in an identifier.
var httpStatusInError = regexp.MustCompile(`\(HTTP (\d{3})\)`)

// classifyGCPError maps a GCP error to the HTTP status it represents, or
// credenvelope.StatusNone when nothing recognises it, in which case
// credenvelope.Classify inspects the error itself.
func classifyGCPError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	errMsg := err.Error()

	if m := httpStatusInError.FindStringSubmatch(errMsg); m != nil {
		if status, convErr := strconv.Atoi(m[1]); convErr == nil && status > 0 {
			return status
		}
	}
	for code, status := range gcpErrorCodes {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(code) + `\b`).MatchString(errMsg) {
			return status
		}
	}
	return credenvelope.StatusNone
}

// preflight runs the checks that must pass before anything is minted: that the caller can parse what
// this role serves, that the role exists and may issue, and that there is room for another credential
// somewhere in its set. Grouped because every one of them must happen before a mint and none costs an
// upstream call.
func (b *backend) preflight(ctx context.Context, req *logical.Request, d *framework.FieldData,
	roleName string,
) (*gcpRole, mintercapacity.State, *logical.Response) {
	// Checked first, and before any mint — see RequireCredentialKind for why.
	if errResp := credenvelope.RequireCredentialKind(
		d.Get(fieldCredentialKind).(string), servedCredentialKind); errResp != nil {
		return nil, mintercapacity.State{}, errResp
	}
	role, errResp := b.loadRole(ctx, req, roleName)
	if errResp != nil {
		return nil, mintercapacity.State{}, errResp
	}
	// Before capacity is counted and before a minter is selected: a role that demands a caller
	// it can name must cost the upstream nothing when it refuses one it cannot.
	if resp := requester.Enforce(req, role.RequireCallerIdentity); resp != nil {
		return nil, mintercapacity.State{}, resp
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
