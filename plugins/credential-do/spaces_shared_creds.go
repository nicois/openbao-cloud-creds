package credentialdo

import (
	"context"
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
// One lock for the whole decide-and-mint, per backend rather than per role, because a
// rotation is rare and a shared key's entire point is that concurrent readers converge on one
// credential. Requests all land on the active node (standbys forward), so an in-process mutex
// is the whole guard; a failover mid-rotation can at worst leave one extra tracked key, which
// the sweep and the reconciler both cover.
func (b *backend) serveSharedSpacesKey(ctx context.Context, req *logical.Request,
	role *doRole, roleName string,
) (*logical.Response, error) {
	b.sharedSpacesMu.Lock()
	defer b.sharedSpacesMu.Unlock()

	now := time.Now()
	state, err := loadSharedSpacesState(ctx, req.Storage, roleName)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "loading the role's shared credential", err), nil
	}

	if reason := rotationReason(state, role, now); reason != "" {
		rotated, errResp := b.rotateSharedSpacesKey(ctx, req.Storage, rotationRequest{
			role: role, roleName: roleName, state: state, now: now, reason: reason,
		})
		if errResp != nil {
			return errResp, nil
		}
		state = rotated
	}

	return b.buildSharedSpacesResponse(role, roleName, state.Current, now), nil
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
		Credential: map[string]interface{}{
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
	resp := b.Secret(secretTypeSpacesKeyRotated).Response(env.ToMap(), map[string]interface{}{
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
