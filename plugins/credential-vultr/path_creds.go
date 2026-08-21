package credentialvultr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
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

	role, errResp, err := b.loadRole(ctx, req, roleName)
	if err != nil || errResp != nil {
		return errResp, err
	}

	now := time.Now()

	// Select a healthy minter from the role's bound set
	sel, err := b.selectMinter(role.MinterSet, now)
	if err != nil {
		// selectMinter fails when the set is unloaded or every minter in it is
		// failing — both surface to the client as an upstream auth failure.
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "%s", err.Error()), nil
	}
	setName, minterID, client := sel.setID, sel.minterID, sel.client

	userName, userEmail, acls := buildUserIdentity(roleName, req.ID, role)

	// Create sub-user via Vultr API
	userResp, httpStatus, err := client.CreateUser(ctx, userName, userEmail, acls)
	if err != nil {
		b.recordMinterError(setName, minterID, httpStatus, now)
		return b.issuanceError(httpStatus, err), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(setName+"/"+minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	expiresAt := now.Add(role.DefaultTTL)
	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: cloudName,
		Role:  roleName,
		Credential: map[string]interface{}{
			"api_key": userResp.User.APIKey,
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   int(role.DefaultTTL.Seconds()),
		Renewable:    true,
		CredentialID: userResp.User.ID,
		Scope:        role.ACLs,
		IssuedBy:     "cloud-creds-vultr/v0.1",
		MinterSet:    setName,
		MinterID:     minterID,
	})

	// Track active user for reconciler
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
		return nil, fmt.Errorf("missing upstream_user_id in internal_data")
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
		b.recordMinterError(minterSet, minterID, httpStatus, now)
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
		return selectedMinter{}, fmt.Errorf("upstream_auth_failed: minter set %q not loaded", setName)
	}
	apiURL := b.vultrAPIURL()
	for id, ms := range states {
		if !ms.minter.Retired && ms.sm.Selectable(now) {
			return selectedMinter{setID: setName, minterID: id, client: newVultrClient(apiURL, ms.minter.Token)}, nil
		}
	}
	return selectedMinter{}, fmt.Errorf("upstream_auth_failed: all minters in set %q are failing", setName)
}

// loadRole fetches and validates a role for issuance. It returns either the
// parsed role, or an *logical.Response describing why issuance can't proceed
// (role missing/disabled), or a hard error. Exactly one of role/errResp is
// non-nil when err is nil.
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*vultrRole, *logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, nil, err
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName), nil
	}
	var role vultrRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, nil, err
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName), nil
	}
	return &role, nil, nil
}

// buildUserIdentity derives the generated sub-user name, email, and trimmed ACL
// list for a given role and lease ID. The lease ID is truncated to keep the
// generated identifiers short while remaining unique-enough per lease.
func buildUserIdentity(roleName, leaseID string, role *vultrRole) (userName, userEmail string, acls []string) {
	leaseShortID := leaseID
	if len(leaseShortID) > leaseShortIDLen {
		leaseShortID = leaseShortID[:leaseShortIDLen]
	}
	userName = fmt.Sprintf("cloud-creds-%s-%s", roleName, leaseShortID)
	userEmail = fmt.Sprintf("cloud-creds-%s-%s@%s", roleName, leaseShortID, emailDomainFor(role))

	return userName, userEmail, parseACLs(role.ACLs)
}

// emailDomainFor returns the domain generated sub-user addresses are formed in:
// the role's email_domain, or a non-routable default when it sets none.
func emailDomainFor(role *vultrRole) string {
	if role.EmailDomain == "" {
		return defaultEmailDomain
	}
	return role.EmailDomain
}

// parseACLs splits a role's comma-separated ACL field into the list the Vultr
// create-user call takes. Shared with the capability probe so a probe requests
// exactly the ACLs a real issuance would.
func parseACLs(raw string) []string {
	acls := strings.Split(raw, ",")
	for i := range acls {
		acls[i] = strings.TrimSpace(acls[i])
	}
	return acls
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
	return nil, fmt.Errorf("upstream_auth_failed: no healthy minter available")
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

func (b *backend) recordMinterError(setName, id string, httpStatus int, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			ms.sm.RecordError(httpStatus, at)
		}
	}
}

// issuanceError logs the raw upstream failure (operator-only) and returns a
// classified, body-free error response for the client (audit2 #4,#5).
func (b *backend) issuanceError(httpStatus int, err error) *logical.Response {
	b.Logger().Warn("upstream credential issuance failed",
		"cloud", cloudName, "status", httpStatus, "error", err)
	return credenvelope.ErrorResponse(credenvelope.ClassifyUpstream(httpStatus),
		"upstream credential issuance failed")
}
