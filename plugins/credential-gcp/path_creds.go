package credentialgcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
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

	role, errResp, err := b.loadRole(ctx, req, roleName)
	if err != nil || errResp != nil {
		return errResp, err
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

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(setName+"/"+minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	ttlSeconds := int(time.Until(expiresAt).Seconds())

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
		Scope:        role.ServiceAccountEmail,
		IssuedBy:     "cloud-creds-gcp/v0.1",
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
		if err := req.Storage.Delete(ctx, "active-tokens/"+credentialID); err != nil {
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
			return selectedMinter{setID: setName, minterID: id, client: b.buildIAMClient(ms.minter)}, nil
		}
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
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*gcpRole, *logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, nil, err
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName), nil
	}
	var role gcpRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, nil, err
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName), nil
	}
	return &role, nil, nil
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

// hashTokenPrefix generates a short opaque identifier from the leading
// characters of a token. Only the first credentialIDPrefixLen characters are
// hashed so the full secret token is never fed through the digest.
func hashTokenPrefix(token string) string {
	prefix := token
	if len(prefix) > credentialIDPrefixLen {
		prefix = prefix[:credentialIDPrefixLen]
	}
	h := sha256.Sum256([]byte(prefix))
	return fmt.Sprintf("%x", h[:8])
}
