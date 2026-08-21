package credentialakamai

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// withRotatedSuccessor returns a fresh slice equal to minters but with the
// minter at oldIdx marked retired (RetiredAt=retiredAt) and the given successor
// appended active. Index iteration avoids copying Minter by value in a range
// loop. Used for both the synthetic-successor pre-mint validation and the
// real-successor commit, so the two views are constructed identically.
func withRotatedSuccessor(minters []cloudconfig.Minter, oldIdx int, retiredAt time.Time, successor cloudconfig.Minter) []cloudconfig.Minter {
	out := make([]cloudconfig.Minter, 0, len(minters)+1)
	for i := range minters {
		m := minters[i]
		if i == oldIdx {
			m.Retired = true
			m.RetiredAt = retiredAt
		}
		out = append(out, m)
	}
	return append(out, successor)
}

// rotationTarget bundles a loaded set with the index of the minter to rotate.
type rotationTarget struct {
	set    *cloudconfig.MinterSet
	oldIdx int
}

// locateRotatable loads the set and finds the (non-retired) minter to rotate.
// It returns the target (set + minter index), or an error response describing
// why the rotation can't proceed (set/minter missing, already retired).
func (b *backend) locateRotatable(ctx context.Context, storage logical.Storage, name, minterID string) (*rotationTarget, *logical.Response, error) {
	set, err := b.readSet(ctx, storage, name)
	if err != nil {
		return nil, nil, err
	}
	if set == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter set %q does not exist", name), nil
	}
	oldIdx := -1
	for i := range set.Minters {
		if set.Minters[i].ID == minterID {
			oldIdx = i
			break
		}
	}
	if oldIdx == -1 {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter %q not found in set %q", minterID, name), nil
	}
	if set.Minters[oldIdx].Retired {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter %q is already retired", minterID), nil
	}
	return &rotationTarget{set: set, oldIdx: oldIdx}, nil, nil
}

// validateRotation checks the prospective post-rotation set against a SYNTHETIC
// successor (no cloud call). ValidateMinterSet only inspects
// NeverExpires/ExpiresAt/Retired, so a synthetic stand-in with the same expiry
// the real successor will have (minterSecretLifetime out, matching RotateMinter
// for a non-never-expires minter) is exact. Returns an error response when the
// rotation would invalidate the set, else nil.
func validateRotation(minters []cloudconfig.Minter, oldIdx int, retiredAt time.Time, old cloudconfig.Minter) *logical.Response {
	synthetic := cloudconfig.Minter{
		ID:           old.ID + "-rot-pending",
		NeverExpires: old.NeverExpires,
	}
	if !old.NeverExpires {
		synthetic.ExpiresAt = time.Now().Add(minterSecretLifetime)
	}
	if verr := cloudconfig.ValidateMinterSet(withRotatedSuccessor(minters, oldIdx, retiredAt, synthetic)); verr != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "rotation would invalidate the minter set: %v", verr)
	}
	return nil
}

// mintAndCheckSuccessor mints the real successor using a healthy active client
// (prefer the minter being rotated if itself selectable, else any other active
// minter in the set), then health-checks it via a client built from ITS token.
// On any failure it cleans up the just-created successor client and returns an
// error response; on success it returns the minting client and the successor.
func (b *backend) mintAndCheckSuccessor(ctx context.Context, name, minterID string, old cloudconfig.Minter) (*akamaiClient, cloudconfig.Minter, *logical.Response) {
	client, err := b.rotationClient(name, minterID, time.Now())
	if err != nil {
		return nil, cloudconfig.Minter{}, credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "no healthy minter to perform rotation: %v", err)
	}
	successor, err := client.RotateMinter(ctx, old)
	if err != nil {
		return nil, cloudconfig.Minter{}, credenvelope.ErrorResponse(credenvelope.Classify(credenvelope.StatusNone, err), "rotation failed: %v", err)
	}

	successorClient, err := b.clientForMinter(successor)
	if err != nil {
		b.cleanupSuccessor(ctx, client, successor)
		return nil, cloudconfig.Minter{}, credenvelope.ErrorResponse(credenvelope.ErrInternal, "could not build successor client: %v", err)
	}
	if status, herr := successorClient.CheckHealth(ctx); herr != nil || status != http.StatusOK {
		b.cleanupSuccessor(ctx, client, successor)
		return nil, cloudconfig.Minter{}, credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "successor minter failed health check (status %d): %v", status, herr)
	}
	return client, successor, nil
}

// pathMinterSetRotate rotates one minter in a set: it first validates the
// prospective post-rotation set against a synthetic successor (no cloud call),
// and only if that passes mints the real successor — a new Akamai API client
// granted READ-WRITE on the per-account Identity-Management API so it can itself
// be rotated later — health-checks it AS the successor, then (atomically, under
// rotateSweepMu) appends the successor active and marks the original retired.
// The original's upstream API client stays alive until the retired-sweep
// deletes it after minter_retire_grace — so no other raft node, whose in-memory
// snapshot may still hold the original as selectable, ever loses its minter
// mid-flight.
func (b *backend) pathMinterSetRotate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	minterID := d.Get(fieldMinterID).(string)
	if minterID == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_id is required"), nil
	}

	b.rotateSweepMu.Lock()
	defer b.rotateSweepMu.Unlock()

	tgt, errResp, err := b.locateRotatable(ctx, req.Storage, name, minterID)
	if err != nil || errResp != nil {
		return errResp, err
	}
	set, oldIdx := tgt.set, tgt.oldIdx
	old := set.Minters[oldIdx]

	// 1. Validate the prospective post-rotation set FIRST, using a SYNTHETIC
	//    successor — no cloud call yet. Validating before minting means a rotation
	//    that would break the set never creates an upstream API client (audit2 #9).
	retiredAt := time.Now()
	if errResp := validateRotation(set.Minters, oldIdx, retiredAt, old); errResp != nil {
		return errResp, nil
	}

	// 2 + 3. Mint the real successor with a healthy active client and health-check
	//    it AS the successor; on failure the successor's upstream client is
	//    cleaned up and the rotation rejected with no state change.
	client, successor, errResp := b.mintAndCheckSuccessor(ctx, name, minterID, old)
	if errResp != nil {
		return errResp, nil
	}

	// 3b. Health is not capability: GET /api-clients/self succeeds for any live
	//     EdgeGrid credential, including a successor whose copied grants came back
	//     narrower than the incumbent's and so cannot delegate a bound role's
	//     apiAccess. Prove the successor can mint before committing.
	if errResp := b.verifySuccessorCapability(ctx, req.Storage, name, successor); errResp != nil {
		b.cleanupSuccessor(ctx, client, successor)
		return errResp, nil
	}

	// 4. Commit: append the real successor active, mark the old retired, then
	//    persist the set and refresh the in-memory snapshot.
	set.Minters = withRotatedSuccessor(set.Minters, oldIdx, retiredAt, successor)
	if err := b.persistSet(ctx, req.Storage, set); err != nil {
		// Persist failed after minting the successor: best-effort clean up so we
		// don't leak an upstream API client no set references.
		b.cleanupSuccessor(ctx, client, successor)
		return nil, err
	}

	emitMinterRotated(name)
	b.Logger().Info("minter rotated",
		"cloud", cloudName, "minter_set", name,
		"retired_minter_id", minterID, "successor_id", successor.ID)

	return &logical.Response{Data: map[string]interface{}{
		"successor_id":      successor.ID,
		"retired_minter_id": minterID,
		"retired_at":        retiredAt,
	}}, nil
}

// clientForMinter builds an EdgeGrid-signing Akamai client from a minter's
// EdgeGrid triple plus the configured host. Unlike clientFor it takes the
// minter directly (the successor is not yet in the in-memory snapshot) and
// takes b.mu itself.
func (b *backend) clientForMinter(m cloudconfig.Minter) (*akamaiClient, error) {
	cred, err := parseEdgeGridToken(m.Token)
	if err != nil {
		return nil, err
	}
	b.mu.RLock()
	cred.Host = b.host
	url := b.akamaiAPIURL()
	b.mu.RUnlock()
	return newAkamaiClient(url, cred), nil
}

// rotationClient returns a client to mint the successor: the minter being
// rotated if it is itself selectable, otherwise any other healthy active minter
// in the set (so a wedged minter can still be rotated out by a sibling).
func (b *backend) rotationClient(setName, minterID string, now time.Time) (*akamaiClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	states, ok := b.minterSets[setName]
	if !ok {
		return nil, fmt.Errorf("minter set %q not loaded", setName)
	}
	if ms, ok := states[minterID]; ok && !ms.minter.Retired && ms.sm.Selectable(now) {
		return b.clientFor(ms)
	}
	for id, ms := range states {
		if id == minterID {
			continue
		}
		if !ms.minter.Retired && ms.sm.Selectable(now) {
			return b.clientFor(ms)
		}
	}
	return nil, fmt.Errorf("no healthy active minter in set %q", setName)
}

// cleanupSuccessor best-effort deletes a just-created successor API client when
// the rotation is aborted (health-check or persist failure). Uses the minting
// client (which holds Identity-Management rights). Failures are logged, not
// returned — the rotation is already being rejected.
func (b *backend) cleanupSuccessor(ctx context.Context, client *akamaiClient, successor cloudconfig.Minter) {
	clientID := successor.RotationParams[fieldClientID]
	if clientID == "" {
		return
	}
	if status, err := client.DeleteClient(ctx, clientID); err != nil && status != http.StatusNotFound {
		b.Logger().Warn("failed to clean up aborted-rotation successor api client",
			"cloud", cloudName, "client_id", clientID, "status", status, "error", err)
	}
}
