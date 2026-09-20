package credentialdo

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/minteraffinity"
	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
	"github.com/nicois/openbao-cloud-creds/pkg/telemetry"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// spacesTrackingPrefix is the storage prefix issued Spaces keys are recorded under.
//
// SEPARATE from activeTrackingPrefix, and deliberately so: the two credential types draw
// on separate upstream quotas (DigitalOcean caps Spaces keys at 200 per account, while the
// PAT cap is undocumented), and pkg/mintercapacity counts one prefix at a time. A shared
// prefix would count a token against the Spaces ceiling and refuse issuance the cloud
// would have allowed — and the reconciler would try to delete a key by token id.
const spacesTrackingPrefix = "active-spaces-keys/"

// secretDOSpacesKey is the lease type for an S3-compatible Spaces access key.
//
// Renewable, like DO's tokens and for the same reason: the credential has NO upstream
// expiry at all, so the lease TTL is enforced by the revoke below and by nothing else, and
// renewal simply defers it. (Contrast the clouds whose credential expires on its own,
// where a renewal that could not extend it must register no Renew callback.)
func (b *backend) secretDOSpacesKey() *framework.Secret {
	return &framework.Secret{
		Type:   secretTypeSpacesKey,
		Revoke: b.pathSpacesKeyRevoke,
		Renew:  b.pathCredsRenew,
	}
}

// issueSpacesKey mints one Spaces access key for a spaces_key role. It mirrors
// pathCredsRead's decide-then-mint shape rather than sharing it, because almost nothing
// downstream of the mint is common: a different upstream call, a different identifier, a
// different credential block, a different tracking prefix and a different lease type.
func (b *backend) issueSpacesKey(ctx context.Context, req *logical.Request, d *framework.FieldData,
	role *doRole, roleName string,
) (*logical.Response, error) {
	now := time.Now()

	// Counted under the SPACES prefix, so a minter's room for Spaces keys is independent
	// of how many tokens it holds. One configured limit applies to each class separately;
	// on this cloud that is the honest reading, since the two caps are different numbers
	// (200 for Spaces keys, unknown for tokens) and only one of them is documented.
	capacity, err := mintercapacity.Snapshot(ctx, req.Storage, spacesTrackingPrefix,
		b.credentialLimitPerMinter())
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "counting outstanding credentials", err), nil
	}
	b.warnOnNearingCapacity(capacity)

	sel, err := b.selectMinter(role.MinterSet, minteraffinity.KeyFromRequest(req, d), capacity, now)
	if err != nil {
		return credenvelope.ResponseFor(err), nil
	}
	setName, minterID, client := sel.setID, sel.minterID, sel.client

	keyName, errResp := b.credentialName(ctx, req.Storage, roleName, req.ID)
	if errResp != nil {
		return errResp, nil
	}
	created, httpStatus, err := client.CreateSpacesKey(ctx, keyName, role.Grants)
	if err != nil {
		b.recordMinterError(setName, minterID, httpStatus, err, now)
		return b.issuanceError(httpStatus, err, telemetry.IssuanceAttempt{
			Cloud: cloudName, Role: roleName, MinterSet: setName, MinterID: minterID,
			RequestID: req.ID,
		}), nil
	}
	b.recordMinterSuccess(setName, minterID, now)

	return b.buildSpacesResponse(ctx, req, spacesResponseArgs{
		role: role, roleName: roleName, sel: sel, key: &created.Key, now: now,
	}), nil
}

type spacesResponseArgs struct {
	role     *doRole
	roleName string
	sel      selectedMinter
	key      *spacesKeyInfo
	now      time.Time
}

func (b *backend) buildSpacesResponse(ctx context.Context, req *logical.Request, args spacesResponseArgs) *logical.Response {
	role, roleName, now := args.role, args.roleName, args.now
	setName, minterID, client := args.sel.setID, args.sel.minterID, args.sel.client
	key := args.key

	emitLeaseIssued(roleName)

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: cloudName,
		Role:  roleName,
		Credential: map[string]any{
			// The S3 shape, and only it. endpoint and region are here rather than in
			// metadata because an S3 client cannot be constructed without them and they
			// are not derivable from the key material — see credenvelope.KindS3Credentials.
			// No session_token: a Spaces key is a long-lived key, not an STS session.
			credKeyAccessKeyID:     key.AccessKey,
			credKeySecretAccessKey: key.SecretKey,
			credKeyEndpoint:        role.Endpoint,
			credKeyRegion:          role.Region,
		},
		ExpiresAt:  now.Add(role.DefaultTTL),
		TTLSeconds: int(role.DefaultTTL.Seconds()),
		Renewable:  true,
		// DigitalOcean gives a Spaces key no id of its own; the access key IS the
		// identifier, and it is what a delete takes.
		CredentialID: key.AccessKey,
		// Per-bucket grants, rendered as the role wrote them (`*` for account-wide) —
		// which is what ScopeKindGrants tells a client to expect.
		Scope:          strings.Join(renderGrants(role.Grants), ","),
		ScopeKind:      credenvelope.ScopeKindGrants,
		CredentialKind: credenvelope.KindS3Credentials,
		IssuedBy:       issuedBy,
		MinterSet:      setName,
		MinterID:       minterID,
	})

	// The request that read this lease is the caller that obtained the key, so its identity is
	// recorded with it: a leaked Spaces key otherwise traces to this mount and role, no further.
	if err := b.trackSpacesKey(ctx, req.Storage, req, spacesKeyRecord{
		roleName: roleName, minterID: minterID, accessKey: key.AccessKey, createdAt: now,
	}); err != nil {
		// Same bargain as the token path (audit F6): never hand out a credential we
		// cannot later track or reconcile. It matters more here — a Spaces key has no
		// upstream expiry, so an untracked one is permanent.
		_, _ = client.DeleteSpacesKey(ctx, key.AccessKey)
		b.Logger().Error("failed to persist active Spaces key record; revoked upstream credential",
			"access_key", key.AccessKey, "error", err)
		return credenvelope.ErrorResponse(credenvelope.ErrInternal,
			"failed to persist credential tracking record")
	}

	resp := b.Secret(secretTypeSpacesKey).Response(env.ToMap(), map[string]any{
		internalKeyAccessKey: key.AccessKey,
		fieldRole:            roleName,
		fieldMinterSet:       setName,
		fieldMinterID:        minterID,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp
}

func (b *backend) pathSpacesKeyRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	accessKey, ok := req.Secret.InternalData[internalKeyAccessKey].(string)
	if !ok || accessKey == "" {
		// Not retryable, and OpenBao retries a failed revoke forever, so returning an
		// error would wedge the lease while the key stayed live (A30 / KI-002's shape).
		// Logged at ERROR because it needs a human: we cannot name the credential, so only
		// the owner-tag reconciler will reclaim it — and it never expires on its own.
		b.Logger().Error("revoke: lease internal_data is missing a required field; releasing the "+
			"lease and leaving the upstream Spaces key to be reclaimed by hand",
			fieldCloud, cloudName, "missing_field", internalKeyAccessKey, "lease_id", req.Secret.LeaseID)
		return nil, nil
	}

	minterSet, _ := req.Secret.InternalData[fieldMinterSet].(string)
	minterID, _ := req.Secret.InternalData[fieldMinterID].(string)
	client, err := b.getMinter(minterSet, minterID)
	if err != nil {
		client, err = b.anyHealthyMinterInSet(minterSet)
		if err != nil {
			b.Logger().Warn("revoke: issuing minter gone and no fallback in set; Spaces key left "+
				"upstream for the owner-tag reconciler to delete (it does not expire on its own)",
				fieldMinterSet, minterSet, fieldMinterID, minterID)
			_ = req.Storage.Delete(ctx, spacesTrackingPrefix+accessKey)
			return nil, nil
		}
	}

	roleName, _ := req.Secret.InternalData[fieldRole].(string)

	now := time.Now()
	httpStatus, err := client.DeleteSpacesKey(ctx, accessKey)
	if err != nil && httpStatus != http.StatusNotFound {
		b.recordMinterError(minterSet, minterID, httpStatus, err, now)
		emitLeaseRevokeFailed(roleName)
		b.Logger().Warn("upstream credential revocation failed",
			fieldCloud, cloudName, "status", httpStatus, "error", err)
		return nil, fmt.Errorf("%s: upstream credential revocation failed",
			credenvelope.ErrLeaseRevokeFailed)
	}
	// 404 = already deleted upstream; treat as success, or the lease never releases.
	b.recordMinterSuccess(minterSet, minterID, now)

	if err := req.Storage.Delete(ctx, spacesTrackingPrefix+accessKey); err != nil {
		b.Logger().Warn("failed to remove active Spaces key tracking",
			"access_key", accessKey, "error", err)
	}

	return nil, nil
}
