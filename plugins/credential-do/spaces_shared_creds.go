package credentialdo

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// secretDOSpacesKeyRotated is the lease type for the ONE Spaces key a rotated role serves.
//
// No Renew callback, and that is the whole reason it is a third secret type rather than the
// second one with a flag: framework.Secret.Renewable() is (Renew != nil), so a type that
// registered one would advertise renewable=true — and OpenBao REVOKES a lease whose renewal
// fails, which here would destroy a credential every other reader is using. Renewal has
// nothing to defer in any case: the credential's life is the role's rotation schedule, not
// this lease's.
//
// Revoke is registered but deliberately does nothing upstream, exactly as OCI's rotation
// slots do: the credential is the role's, not the lease's.
func (b *backend) secretDOSpacesKeyRotated() *framework.Secret {
	return &framework.Secret{
		Type:   secretTypeSpacesKeyRotated,
		Revoke: b.pathSharedSpacesKeyRevoke,
	}
}

// serveSharedSpacesKey answers a credential read on a rotated role: re-serve the key the role
// already has, or replace it first if it is due.
//
// Two paths, and the split is the point. A re-serve reads the record, mutates nothing and calls
// no API — and rotationReason is pure — so it takes NO lock at all. That is the path every client
// takes on almost every read.
//
// Only a rotation is exclusive, and only for its own role. Requests all land on the active node
// (standbys forward), so an in-process lock is the whole guard; a failover mid-rotation can at
// worst leave one extra tracked key, which the sweep and the reconciler both cover.
func (b *backend) serveSharedSpacesKey(ctx context.Context, req *logical.Request,
	role *doRole, roleName string,
) (*logical.Response, error) {
	now := time.Now()
	state, err := loadSharedSpacesState(ctx, req.Storage, roleName)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "loading the role's shared credential", err), nil
	}
	if rotationReason(state, role, now) == "" {
		return b.buildSharedSpacesResponse(role, roleName, state.Current, now), nil
	}

	release := b.lockSharedRole(roleName)
	defer release()

	// Decide AGAIN, from a fresh read. Another reader — or the sweeper — may have rotated
	// between the check above and this lock, and minting a second time would leave one key
	// recorded nowhere while it still exists upstream, where nothing expires it.
	now = time.Now()
	state, err = loadSharedSpacesState(ctx, req.Storage, roleName)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "loading the role's shared credential", err), nil
	}
	if reason := rotationReason(state, role, now); reason != causeNone {
		// One value describes the rotation to both the attempt and the fallback, so they cannot
		// disagree about which key was being replaced or why.
		attempt := rotationRequest{
			role: role, roleName: roleName, state: state, now: now, reason: reason,
		}
		rotated, errResp := b.rotateSharedSpacesKey(ctx, req.Storage, attempt)
		if errResp != nil {
			if fallback := b.serveOverdueKey(attempt, errResp); fallback != nil {
				return fallback, nil
			}
			return errResp, nil
		}
		state = rotated
	}

	return b.buildSharedSpacesResponse(role, roleName, state.Current, now), nil
}

// serveOverdueKey hands back the key the role already has when the rotation that should have
// replaced it FAILED, or nil when it must not be served.
//
// The defect this closes: a read that found the key due either rotated or returned an error, and
// on error it returned NO credential — while a valid, non-expiring Spaces key sat in the record
// unreturned. A transient upstream fault at the moment a key came due therefore denied a client
// the credential it had a moment earlier, and every subsequent read denied it again, for as long
// as DigitalOcean was unreachable. Nothing about the credential had changed.
//
// Three conditions, each of them a refusal in its own right:
//
//   - the cause must be causeAge. A key whose GRANTS no longer match the role carries privilege
//     the operator has revoked, and serving that because the replacement failed would hand out
//     exactly what they narrowed; an unminted role has nothing to serve at all.
//   - there must be a key. causeAge implies one, but the read is cheap and the alternative is a
//     nil dereference at the least convenient moment.
//   - now must be before servableUntil: inside the promise `rotation_period` makes, and inside
//     the window where a lease can still be issued that cannot outlive the credential.
//
// Past that the refusal is the rotation's OWN error response, unchanged, because its code says
// what is actually wrong upstream — which is what a client needs in order to decide whether to
// retry, and more useful than a code invented here to say "too late".
func (b *backend) serveOverdueKey(attempt rotationRequest,
	rotationErr *logical.Response,
) *logical.Response {
	role, roleName, state, now := attempt.role, attempt.roleName, attempt.state, attempt.now
	if attempt.reason != causeAge || state == nil || state.Current == nil {
		return nil
	}
	until := state.Current.servableUntil(role)
	if !now.Before(until) {
		b.Logger().Error("the shared Spaces key is past the age its role promises and cannot be "+
			"replaced; refusing to serve it",
			"role", roleName, "access_key", state.Current.AccessKey,
			"minted_at", state.Current.MintedAt.UTC().Format(time.RFC3339),
			"servable_until", until.UTC().Format(time.RFC3339),
			"rotation_error", rotationErr.Error())
		return nil
	}

	// Warn rather than Info: the rotation is failing, and the only thing keeping this role
	// serving is a window that is closing. An operator who sees this has until servable_until to
	// fix the upstream, and after that the role stops issuing.
	b.Logger().Warn("serving the shared Spaces key that is overdue for rotation, because the "+
		"rotation failed and the key still works",
		"role", roleName, "access_key", state.Current.AccessKey,
		"servable_until", until.UTC().Format(time.RFC3339),
		"rotation_error", rotationErr.Error())

	resp := b.buildSharedSpacesResponse(role, roleName, state.Current, now)
	resp.Warnings = append(resp.Warnings, fmt.Sprintf(
		"this credential is overdue for rotation and the rotation is failing (%s); it will be "+
			"served until %s and refused after that", rotationErr.Error(),
		until.UTC().Format(time.RFC3339)))
	return resp
}

func (b *backend) buildSharedSpacesResponse(role *doRole, roleName string,
	key *sharedSpacesKey, now time.Time,
) *logical.Response {
	emitLeaseIssued(roleName)

	// The clamp is a backstop, not the normal path: role write refuses a max_ttl above
	// overlap_ttl, and the key's remaining life is at least overlap_ttl at any moment — so a
	// reader gets its role's full TTL right up to the rotation. It stays because the numbers
	// it depends on are stored, and a role rewritten between two reads must not be able to
	// hand out a lease that outlives the credential it names (techrfc OBC-002).
	ttl := role.DefaultTTL
	if remaining := key.deadline(role).Sub(now); remaining < ttl {
		ttl = remaining
	}

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: cloudName,
		Role:  roleName,
		Credential: map[string]any{
			credKeyAccessKeyID:     key.AccessKey,
			credKeySecretAccessKey: key.SecretKey,
			credKeyEndpoint:        role.Endpoint,
			credKeyRegion:          role.Region,
		},
		ExpiresAt:  now.Add(ttl),
		TTLSeconds: int(ttl.Seconds()),
		// Not renewable: see secretDOSpacesKeyRotated. The client's contract is to re-read
		// before the lease expires, which is what makes rotation invisible to it.
		Renewable:      false,
		CredentialID:   key.AccessKey,
		Scope:          strings.Join(renderGrants(role.Grants), ","),
		ScopeKind:      credenvelope.ScopeKindGrants,
		CredentialKind: credenvelope.KindS3Credentials,
		IssuedBy:       issuedBy,
		MinterSet:      key.MinterSet,
		MinterID:       key.MinterID,
	})

	// The minter recorded is the one that MINTED this key, not one selected for this read:
	// that is what an auditor correlating the credential with an account needs, and on a
	// re-served key no selection happened at all.
	resp := b.Secret(secretTypeSpacesKeyRotated).Response(env.ToMap(), map[string]any{
		internalKeyAccessKey: key.AccessKey,
		fieldRole:            roleName,
		fieldMinterSet:       key.MinterSet,
		fieldMinterID:        key.MinterID,
	})
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = role.MaxTTL
	return resp
}

// pathSharedSpacesKeyRevoke releases the lease and leaves the credential alone.
//
// A soft revoke, like OCI's rotation slots and for the same reason: the credential belongs to
// the ROLE and is held by every other reader, so deleting it because one lease ended would
// break all of them. What bounds this credential is the rotation schedule and the sweeper,
// and an operator who wants it gone now has roles/<name>/revoke-upstream.
func (b *backend) pathSharedSpacesKeyRevoke(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	accessKey, _ := req.Secret.InternalData[internalKeyAccessKey].(string)
	roleName, _ := req.Secret.InternalData[fieldRole].(string)
	b.Logger().Debug("released a lease on a shared Spaces key; the credential is unchanged",
		fieldCloud, cloudName, fieldRole, roleName, "access_key", accessKey,
		"note", "a shared key is bounded by the role's rotation schedule, not by one lease")
	return nil, nil
}
