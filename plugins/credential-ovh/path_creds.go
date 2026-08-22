package credentialovh

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
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

	role, errResp, err := b.loadRole(ctx, req, roleName)
	if err != nil || errResp != nil {
		return errResp, err
	}

	now := time.Now()

	// Select a healthy minter from the role's bound set
	sel, err := b.selectMinter(role.MinterSet, now)
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
			return selectedMinter{setID: setName, minterID: id, client: b.buildTokenClient(ms.minter)}, nil
		}
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
