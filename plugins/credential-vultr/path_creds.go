package credentialvultr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/mintledger"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/nicois/openbao-cloud-creds/pkg/telemetry"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// leaseShortIDLen is how many leading characters of the lease ID are folded
// into generated sub-user names/emails to keep them short but unique-enough.
const leaseShortIDLen = 8

// defaultEmailDomain is the non-routable domain generated sub-user addresses use
// when a role sets no email_domain.
const defaultEmailDomain = "managed.local"

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

func (b *backend) secretVultr() *framework.Secret {
	return &framework.Secret{
		Type:   "vultr_user",
		Revoke: b.pathCredsRevoke,
		Renew:  b.pathCredsRenew,
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

	ownerPrefix, errResp := b.ownerPrefix(ctx, req)
	if errResp != nil {
		return errResp, nil
	}
	userName, userEmail, acls := buildUserIdentity(ownerPrefix, roleName, req.ID, role)

	// Create sub-user via Vultr API
	userResp, httpStatus, err := client.CreateUser(ctx, userName, userEmail, acls)
	if err != nil {
		b.recordMinterError(setName, minterID, httpStatus, err, now)
		return b.issuanceError(httpStatus, err, telemetry.IssuanceAttempt{
			Cloud: cloudName, Role: roleName, MinterSet: setName, MinterID: minterID,
			RequestID: req.ID,
		}), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	emitLeaseIssued(roleName)

	expiresAt := now.Add(role.DefaultTTL)
	env := b.buildEnvelope(envelopeArgs{
		role: role, roleName: roleName, resp: userResp,
		setName: setName, minterID: minterID, expiresAt: expiresAt,
	})

	// Track active user for reconciler
	// Record the mint in the ledger BEFORE the tracking entry. The ledger is what
	// makes this credential reclaimable later: this cloud's list API reports no
	// creation time, and the reconciler will not delete an entity whose age it
	// cannot confirm (A5). Unlike the tracking entry, the ledger entry is not
	// deleted on revoke — the leak worth cleaning up is precisely the one where the
	// upstream delete failed and the tracking entry went away.
	if err := mintledger.Record(ctx, req.Storage, userResp.User.ID, now); err != nil {
		b.Logger().Warn("could not record the mint in the ledger; this credential will not be "+
			"automatically reclaimable if it leaks", "cloud", cloudName, "id", userResp.User.ID, "error", err)
	}
	activeEntry, _ := logical.StorageEntryJSON("active-users/"+userResp.User.ID, map[string]interface{}{
		fieldRole: roleName,
		"minter":  minterID,
		"created": now.UTC().Format(time.RFC3339),
	})
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			// Tracking write failed: revoke the just-minted upstream credential
			// so we never hand out a credential we cannot later track/reconcile
			// (audit F6). Best-effort delete.
			_, _ = client.DeleteUser(ctx, userResp.User.ID)
			b.Logger().Error("failed to persist active-user record; revoked upstream credential",
				"user_id", userResp.User.ID, "error", err)
			return credenvelope.ErrorResponse(credenvelope.ErrInternal,
				"failed to persist credential tracking record"), nil
		}
	}

	resp := b.Secret("vultr_user").Response(env.ToMap(), map[string]interface{}{
		"upstream_user_id": userResp.User.ID,
		fieldRole:          roleName,
		fieldMinterSet:     setName,
		"minter_id":        minterID,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	userID, ok := req.Secret.InternalData["upstream_user_id"].(string)
	if !ok || userID == "" {
		// Nothing here is retryable: an internal_data key that is absent will be absent
		// on every retry, and OpenBao retries a failed revoke indefinitely — so
		// returning an error wedged the lease forever while the sub-user it names stayed
		// alive upstream. That is KI-002's wedge with a different cause (A30 in
		// docs/audit-2026-08-22.md).
		//
		// Releasing the lease is the lesser harm, and it is logged at ERROR because it
		// needs a human: we cannot name the upstream credential, so the owner-tag
		// reconciler will only reclaim it once its own tracking entry is gone.
		b.Logger().Error("revoke: lease internal_data is missing a required field; releasing the "+
			"lease and leaving the upstream credential to be reclaimed by hand",
			fieldCloud, cloudName, "missing_field", "upstream_user_id", "lease_id", req.Secret.LeaseID)
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
			_ = req.Storage.Delete(ctx, "active-users/"+userID)
			return nil, nil
		}
	}

	roleName, _ := req.Secret.InternalData[fieldRole].(string)

	now := time.Now()
	httpStatus, err := client.DeleteUser(ctx, userID)
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

	// Remove from active users
	if err := req.Storage.Delete(ctx, "active-users/"+userID); err != nil {
		b.Logger().Warn("failed to remove active user tracking", "user_id", userID, "error", err)
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
	client   *vultrClient
}

func (b *backend) selectMinter(setName string, now time.Time) (selectedMinter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return selectedMinter{}, credenvelope.NewError(credenvelope.ErrConfigInvalid,
			http.StatusBadRequest, fmt.Sprintf("minter set %q is not loaded", setName))
	}
	apiURL := b.vultrAPIURL()
	for id, ms := range states {
		if !ms.minter.Retired && ms.sm.TryAcquire(now) {
			return selectedMinter{setID: setName, minterID: id, client: newVultrClient(apiURL, ms.minter.Token)}, nil
		}
	}
	return selectedMinter{}, recovery.UnavailableError(setName, machinesOf(states), now)
}

// loadRole fetches and validates a role for issuance. It returns either the
// parsed role, or an *logical.Response describing why issuance can't proceed
// (role missing/disabled), or a hard error. Exactly one of role/errResp is
// non-nil when err is nil.
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*vultrRole, *logical.Response) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "loading the role", err)
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName)
	}
	var role vultrRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "parsing the stored role", err)
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName)
	}
	return &role, nil
}

// buildUserIdentity derives the generated sub-user name, email, and trimmed ACL
// list for a given role and lease ID. The lease ID is truncated to keep the
// generated identifiers short while remaining unique-enough per lease.
func buildUserIdentity(ownerPrefix, roleName, leaseID string, role *vultrRole,
) (userName, userEmail string, acls []string) {
	leaseShortID := leaseID
	if len(leaseShortID) > leaseShortIDLen {
		leaseShortID = leaseShortID[:leaseShortIDLen]
	}
	// The generated name and email are this cloud's owner tag; both must carry the
	// mount's instance so another mount's reconciler leaves them alone (A19).
	userName = ownerPrefix + roleName + "-" + leaseShortID
	userEmail = userName + "@" + emailDomainFor(role)

	return userName, userEmail, role.ACLs
}

// emailDomainFor returns the domain generated sub-user addresses are formed in:
// the role's email_domain, or a non-routable default when it sets none.
func emailDomainFor(role *vultrRole) string {
	if role.EmailDomain == "" {
		return defaultEmailDomain
	}
	return role.EmailDomain
}

// anyHealthyMinter returns a client for any healthy minter across all sets.
// Used by the reconciler, which lists owner-tagged sub-users regardless of set.
func (b *backend) anyHealthyMinter() (*vultrClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	apiURL := b.vultrAPIURL()
	for _, states := range b.minterSets {
		for _, ms := range states {
			if !ms.minter.Retired && ms.sm.Selectable(now) {
				return newVultrClient(apiURL, ms.minter.Token), nil
			}
		}
	}
	return nil, credenvelope.NewError(credenvelope.ErrUpstreamAuthFailed, http.StatusBadGateway,
		"no healthy minter available")
}

// anyHealthyMinterInSet returns a client for any healthy minter in the given
// set. Used by revoke when the issuing minter was removed after issuance.
func (b *backend) anyHealthyMinterInSet(setName string) (*vultrClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	now := time.Now()
	apiURL := b.vultrAPIURL()
	if states, ok := b.minterSets[setName]; ok {
		for _, ms := range states {
			if !ms.minter.Retired && ms.sm.Selectable(now) {
				return newVultrClient(apiURL, ms.minter.Token), nil
			}
		}
	}
	return nil, fmt.Errorf("no healthy minter in set %q", setName)
}

func (b *backend) getMinter(setName, id string) (*vultrClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	apiURL := b.vultrAPIURL()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			return newVultrClient(apiURL, ms.minter.Token), nil
		}
	}
	return nil, fmt.Errorf("minter %q not found in set %q", id, setName)
}

// vultrAPIURL returns the configured API base URL. Callers MUST hold b.mu
// (read or write). It performs no locking of its own.
func (b *backend) vultrAPIURL() string {
	if b.apiURL != "" {
		return b.apiURL
	}
	return "https://api.vultr.com"
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

// ownerPrefix resolves this mount's owner prefix. The generated sub-user name and email
// ARE the owner tag here, so both must carry it (A19).
func (b *backend) ownerPrefix(ctx context.Context, req *logical.Request) (string, *logical.Response) {
	instanceID, err := b.ownerInstanceID(ctx, req.Storage)
	if err != nil {
		return "", credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err)
	}
	return ownertag.Prefix(instanceID), nil
}

// buildEnvelope assembles the response envelope. Extracted so pathCredsRead stays within
// the function-length limit; it is pure assembly with no upstream calls.
// envelopeArgs collects the envelope inputs, so the helper stays within the
// argument limit and the call site reads as named fields.
type envelopeArgs struct {
	role      *vultrRole
	roleName  string
	resp      *userResponse
	setName   string
	minterID  string
	expiresAt time.Time
}

func (b *backend) buildEnvelope(a envelopeArgs) *credenvelope.Envelope {
	return credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: cloudName,
		Role:  a.roleName,
		Credential: map[string]interface{}{
			"api_key": a.resp.User.APIKey,
		},
		ExpiresAt:    a.expiresAt,
		TTLSeconds:   int(a.role.DefaultTTL.Seconds()),
		Renewable:    true,
		CredentialID: a.resp.User.ID,
		// Vultr ACLs are eight coarse access-control categories.
		Scope:     strings.Join(a.role.ACLs, ","),
		ScopeKind: credenvelope.ScopeKindACL,
		IssuedBy:  "cloud-creds-vultr/v0.1",
		MinterSet: a.setName,
		MinterID:  a.minterID,
	})
}
