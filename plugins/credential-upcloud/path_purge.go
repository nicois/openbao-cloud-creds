package credentialupcloud

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/upstreampurge"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// purgePaths is roles/<name>/revoke-upstream: delete what a role has already issued.
//
// The schema, the modes, the pacing and the report all live in pkg/upstreampurge, so this
// plugin supplies only what is cloud-specific — where the tracking records are, and how one
// credential is deleted. An operator's runbook is then the same on every cloud that can do it.
func (b *backend) purgePaths() []*framework.Path {
	return []*framework.Path{upstreampurge.Path(b.purgeEndpoint)}
}

// purgeEndpoint is rebuilt per request so the log lines go to a live logger.
//
// It takes the shared default pass bound rather than this mount's max_deletes_per_pass: that
// setting bounds the RECONCILER, whose risk is deleting something it inferred was an orphan,
// while a purge deletes exactly what an operator named. An operator who tightened the
// reconciler for safety must not find they slowed their own incident response.
func (b *backend) purgeEndpoint() upstreampurge.Endpoint {
	return upstreampurge.Endpoint{
		Cloud:   cloudName,
		Logger:  b.Logger(),
		Resolve: b.resolvePurgeTarget,
	}
}

// resolvePurgeTarget finds a role's tracking records and a way to delete its credentials.
//
// It deliberately does NOT use loadRole: that refuses a disabled role, and disable-then-purge
// is the sequence this whole pair of levers is for. A role disabled to stop the bleeding must
// still be purgeable, or an operator would have to re-enable it — briefly reopening issuance —
// to destroy what leaked.
func (b *backend) resolvePurgeTarget(ctx context.Context, storage logical.Storage, roleName string) (*upstreampurge.Target, *logical.Response) {
	entry, err := storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "loading the role", err)
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName)
	}
	var role upcloudRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "parsing the stored role", err)
	}
	return &upstreampurge.Target{Prefix: activeTrackingPrefix, Delete: b.purgeDeleter(&role)}, nil
}

// purgeDeleter deletes one of a role's issued credentials upstream.
//
// The minter is chosen the way a lease revoke chooses one: the issuing minter if it is still
// in the set, else any healthy minter in it. Either can delete the credential — it belongs to
// the account, not to the key that created it — and the issuing minter may well be the one
// that has just been rotated out because it leaked.
func (b *backend) purgeDeleter(role *upcloudRole) upstreampurge.Deleter {
	return func(ctx context.Context, rec upstreampurge.Record) error {
		client, err := b.getMinter(role.MinterSet, rec.Minter)
		if err != nil {
			client, err = b.anyHealthyMinterInSet(role.MinterSet)
			if err != nil {
				return err
			}
		}

		now := time.Now()
		status, err := client.DeleteToken(ctx, rec.ID)
		if outcome := upstreampurge.Outcome(status, err); outcome != nil {
			// Recorded against the minter for the same reason a probe's 429 is: the callers
			// issuing from this quota are sharing it with the purge, and a credential that has
			// stopped authenticating is a fact about the minter however we found out.
			b.recordMinterError(role.MinterSet, rec.Minter, status, err, now)
			return outcome
		}
		b.recordMinterSuccess(role.MinterSet, rec.Minter, now)
		return nil
	}
}
