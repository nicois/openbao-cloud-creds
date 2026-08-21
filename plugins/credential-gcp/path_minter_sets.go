package credentialgcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) minterSetPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "minter-sets/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				fieldName: {Type: framework.TypeString, Description: "Name of the minter set"},
				"minters": {Type: framework.TypeSlice, Description: "Minter credentials (service account JSON keys) in this set"},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathMinterSetWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathMinterSetRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathMinterSetDelete},
			},
		},
		{
			Pattern: "minter-sets/" + framework.GenericNameRegex("name") + "/rotate",
			Fields: map[string]*framework.FieldSchema{
				fieldName:     {Type: framework.TypeString, Description: "Name of the minter set"},
				fieldMinterID: {Type: framework.TypeString, Description: "ID of the minter in the set to rotate"},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathMinterSetRotate},
			},
		},
		{
			Pattern: "minter-sets/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathMinterSetList},
			},
		},
	}
}

// parseMinters converts the raw "minters" field into cloudconfig.Minters.
// For GCP, each minter carries the full service account JSON key, which we
// store in the Token field; the IAM client constructor consumes it directly.
func parseMinters(d *framework.FieldData) ([]cloudconfig.Minter, error) {
	raw := d.Get("minters")
	if raw == nil {
		return nil, fmt.Errorf("minters is required")
	}
	slice, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("minters must be an array")
	}
	var minters []cloudconfig.Minter
	for _, m := range slice {
		mMap, ok := m.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("each minter must be an object")
		}
		minter, err := parseMinter(mMap)
		if err != nil {
			return nil, err
		}
		minters = append(minters, minter)
	}
	return minters, nil
}

// parseMinter converts one raw minter object into a cloudconfig.Minter. The SA
// JSON key (credentials_json) is required and stored in Token; never_expires /
// expires_at / rotation_params are optional.
func parseMinter(mMap map[string]interface{}) (cloudconfig.Minter, error) {
	minter := cloudconfig.Minter{
		ID:        fmt.Sprintf("%v", mMap["id"]),
		CreatedAt: time.Now(),
	}
	credJSON, ok := mMap["credentials_json"].(string)
	if !ok || credJSON == "" {
		return cloudconfig.Minter{}, fmt.Errorf("minter %s: credentials_json is required", minter.ID)
	}
	minter.Token = credJSON
	if ne, ok := mMap["never_expires"].(bool); ok && ne {
		minter.NeverExpires = true
	}
	if exp, ok := mMap["expires_at"].(string); ok {
		t, err := time.Parse(time.RFC3339, exp)
		if err != nil {
			return cloudconfig.Minter{}, fmt.Errorf("invalid expires_at for minter %s: %v", minter.ID, err)
		}
		minter.ExpiresAt = t
	}
	if rp, ok := mMap[fieldRotationParams].(map[string]interface{}); ok {
		params := make(map[string]string, len(rp))
		for k, v := range rp {
			params[k] = fmt.Sprintf("%v", v)
		}
		minter.RotationParams = params
	}
	return minter, nil
}

func (b *backend) pathMinterSetWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	if err := cloudconfig.ValidateSetName(name); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
	minters, err := parseMinters(d)
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
	if err := cloudconfig.ValidateMinterSet(minters); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "invalid minter set: %v", err), nil
	}
	set := &cloudconfig.MinterSet{Name: name, Minters: minters}
	// Prove the candidate minters can mint for the roles already bound to this
	// set before persisting them (see capability.go). The validation above only
	// inspects expiry metadata; without this a replacement minter that
	// authenticates but cannot mint would be accepted silently.
	if errResp := b.verifySetCapability(ctx, req.Storage, set); errResp != nil {
		return errResp, nil
	}
	entry, err := logical.StorageEntryJSON("minter-sets/"+name, set)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	b.loadMinterSet(set)
	go b.startWorkers(b.baseCtx, req.Storage)
	return nil, nil
}

// readSet loads a persisted minter set from storage, or nil if absent.
func (b *backend) readSet(ctx context.Context, storage logical.Storage, name string) (*cloudconfig.MinterSet, error) {
	entry, err := storage.Get(ctx, "minter-sets/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var set cloudconfig.MinterSet
	if err := json.Unmarshal(entry.Value, &set); err != nil {
		return nil, err
	}
	return &set, nil
}

// persistSet writes the set to storage and refreshes the in-memory snapshot.
func (b *backend) persistSet(ctx context.Context, storage logical.Storage, set *cloudconfig.MinterSet) error {
	entry, err := logical.StorageEntryJSON("minter-sets/"+set.Name, set)
	if err != nil {
		return err
	}
	if err := storage.Put(ctx, entry); err != nil {
		return err
	}
	b.loadMinterSet(set)
	return nil
}

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

// pathMinterSetRotate rotates one minter in a set: it first validates the
// prospective post-rotation set against a synthetic successor (no cloud call),
// and only if that passes mints the real successor — a NEW JSON key on the SAME
// minter service account (make-before-break) — health-checks it (the SA key
// authenticates), then (atomically, under rotateSweepMu) appends the successor
// active and marks the original retired. The original's upstream SA key stays
// alive until the retired-sweep deletes it after minter_retire_grace — so no
// other raft node, whose in-memory snapshot may still hold the original as
// selectable, ever loses its minter mid-flight.
//
// If keys.create is blocked by the iam.disableServiceAccountKeyCreation org
// policy, the rotate is rejected with a clear operator-facing message (rotate
// out-of-band or request a policy exemption), distinct from a generic failure.
// findRotatableMinter locates the named minter in the set and returns its index
// and value, or an error response when it is absent or already retired (a
// retired minter's upstream key is already scheduled for the sweep, so rotating
// it again would create a successor nothing selects).
func findRotatableMinter(set *cloudconfig.MinterSet, minterID string) (int, cloudconfig.Minter, *logical.Response) {
	for i := range set.Minters {
		if set.Minters[i].ID != minterID {
			continue
		}
		if set.Minters[i].Retired {
			return -1, cloudconfig.Minter{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter %q is already retired", minterID)
		}
		return i, set.Minters[i], nil
	}
	return -1, cloudconfig.Minter{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter %q not found in set %q", minterID, set.Name)
}

func (b *backend) pathMinterSetRotate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	minterID := d.Get(fieldMinterID).(string)
	if minterID == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_id is required"), nil
	}

	b.rotateSweepMu.Lock()
	defer b.rotateSweepMu.Unlock()

	set, err := b.readSet(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter set %q does not exist", name), nil
	}

	oldIdx, old, errResp := findRotatableMinter(set, minterID)
	if errResp != nil {
		return errResp, nil
	}

	// 1. Validate the prospective post-rotation set FIRST, using a SYNTHETIC
	//    successor — no cloud call yet. ValidateMinterSet only inspects
	//    NeverExpires/ExpiresAt/Retired; SA keys never expire so the successor
	//    inherits old.NeverExpires (matching RotateMinter), making the synthetic
	//    stand-in exact. Validating before minting means a rotation that would
	//    break the set never creates an upstream SA key (audit2 #9): zero
	//    keys.create calls on a rejected rotation.
	retiredAt := time.Now()
	synthetic := cloudconfig.Minter{
		ID:           old.ID + "-rot-pending",
		NeverExpires: old.NeverExpires,
	}
	if !old.NeverExpires {
		synthetic.ExpiresAt = old.ExpiresAt
	}
	if verr := cloudconfig.ValidateMinterSet(withRotatedSuccessor(set.Minters, oldIdx, retiredAt, synthetic)); verr != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "rotation would invalidate the minter set: %v", verr), nil
	}

	// 2. Validation passed: NOW mint the real successor (a new SA key on the
	//    minter service account), using a healthy active minter as the rotator:
	//    prefer the minter being rotated if it is itself selectable, else any
	//    other active minter in the set.
	rotator, err := b.rotationRotator(name, minterID, time.Now())
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "no healthy minter to perform rotation: %v", err), nil
	}
	successor, err := rotator.RotateMinter(ctx, old)
	if err != nil {
		if errors.Is(err, errKeyCreationDisabled) {
			return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "minter rotation disabled by GCP org policy "+
				orgPolicyKeyCreationDisabled+"; rotate out-of-band or request a policy exemption"), nil
		}
		return credenvelope.ErrorResponse(credenvelope.Classify(credenvelope.StatusNone, err), "rotation failed: %v", err), nil
	}

	// 3. Health-check the successor by authenticating AS its new SA key (the same
	//    probe healthCheckWorker uses). If it fails, delete the just-created key
	//    and reject with no state change.
	if herr := b.checkSuccessorHealth(ctx, successor); herr != nil {
		b.cleanupSuccessor(ctx, successor)
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "successor minter failed health check: %v", herr), nil
	}

	// 3b. Health is not capability: TestConnection only proves the successor's new
	//     key authenticates as its own service account. It cannot see that a
	//     tokenCreator binding on a bound role's target SA is gone, which would
	//     leave the set with a healthy minter no role can use. Prove the successor
	//     can mint before committing.
	if errResp := b.verifySuccessorCapability(ctx, req.Storage, name, successor); errResp != nil {
		b.cleanupSuccessor(ctx, successor)
		return errResp, nil
	}

	// 4. Commit: append the real successor active, mark the old retired, then
	//    persist the set and refresh the in-memory snapshot.
	set.Minters = withRotatedSuccessor(set.Minters, oldIdx, retiredAt, successor)
	if err := b.persistSet(ctx, req.Storage, set); err != nil {
		// Persist failed after creating the successor key: best-effort clean up so
		// we don't leak an SA key no set references.
		b.cleanupSuccessor(ctx, successor)
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

// rotationRotator returns a minterRotator (wrapping an SA key-management client)
// to mint the successor: the minter being rotated if it is itself selectable,
// otherwise any other healthy active minter in the set (so a wedged minter can
// still be rotated out by a sibling).
func (b *backend) rotationRotator(setName, minterID string, now time.Time) (*minterRotator, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	states, ok := b.minterSets[setName]
	if !ok {
		return nil, fmt.Errorf("minter set %q not loaded", setName)
	}
	if ms, ok := states[minterID]; ok && !ms.minter.Retired && ms.sm.Selectable(now) {
		return &minterRotator{client: b.buildSAKeyClient(ms.minter)}, nil
	}
	for id, ms := range states {
		if id == minterID {
			continue
		}
		if !ms.minter.Retired && ms.sm.Selectable(now) {
			return &minterRotator{client: b.buildSAKeyClient(ms.minter)}, nil
		}
	}
	return nil, fmt.Errorf("no healthy active minter in set %q", setName)
}

// checkSuccessorHealth verifies the successor's SA key authenticates by building
// an impersonation client from its token and calling TestConnection (the same
// probe healthCheckWorker uses, which exchanges the SA's self-signed JWT for an
// access token). Returns nil when the successor is usable.
func (b *backend) checkSuccessorHealth(ctx context.Context, successor cloudconfig.Minter) error {
	b.mu.RLock()
	client := b.buildIAMClient(successor)
	b.mu.RUnlock()
	return client.TestConnection(ctx)
}

// cleanupSuccessor best-effort deletes a just-created successor SA key upstream
// when the rotation is aborted (health-check failure or persist failure). Uses a
// key-management client built from the SUCCESSOR's own token (it can delete its
// own key). Failures are logged, not returned — the rotation is already being
// rejected.
func (b *backend) cleanupSuccessor(ctx context.Context, successor cloudconfig.Minter) {
	keyName := successor.RotationParams[fieldKeyName]
	if keyName == "" {
		return
	}
	b.mu.RLock()
	client := b.buildSAKeyClient(successor)
	b.mu.RUnlock()
	if err := client.DeleteKey(ctx, keyName); err != nil && !isSAKeyNotFound(err) {
		b.Logger().Warn("failed to clean up aborted-rotation successor SA key",
			"cloud", cloudName, "key_name", keyName, "error", err)
	}
}

func (b *backend) pathMinterSetRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	entry, err := req.Storage.Get(ctx, "minter-sets/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var set cloudconfig.MinterSet
	if err := json.Unmarshal(entry.Value, &set); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(set.Minters))
	for i := range set.Minters {
		ids = append(ids, set.Minters[i].ID)
	}
	return &logical.Response{Data: map[string]interface{}{
		fieldName: set.Name, "minter_count": len(set.Minters), "minter_ids": ids,
	}}, nil
}

func (b *backend) pathMinterSetDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	if err := req.Storage.Delete(ctx, "minter-sets/"+name); err != nil {
		return nil, err
	}
	b.mu.Lock()
	delete(b.minterSets, name)
	b.mu.Unlock()
	return nil, nil
}

func (b *backend) pathMinterSetList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "minter-sets/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *backend) loadMinterSet(set *cloudconfig.MinterSet) {
	b.mu.Lock()
	defer b.mu.Unlock()
	states := make(map[string]*minterState, len(set.Minters))
	for i := range set.Minters {
		m := set.Minters[i]
		states[m.ID] = &minterState{
			set:    set.Name,
			minter: m,
			sm: recovery.NewStateMachine(recovery.Config{
				AuthFailThreshold:   authFailThreshold,
				HealthCheckInterval: healthCheckInterval,
			}),
		}
	}
	b.minterSets[set.Name] = states
}

func (b *backend) loadAllMinterSets(ctx context.Context, storage logical.Storage) error {
	names, err := storage.List(ctx, "minter-sets/")
	if err != nil {
		return err
	}
	for _, name := range names {
		entry, err := storage.Get(ctx, "minter-sets/"+name)
		if err != nil {
			b.Logger().Warn("skipping minter set: storage read failed", "name", name, "error", err)
			continue
		}
		if entry == nil {
			continue
		}
		var set cloudconfig.MinterSet
		if err := json.Unmarshal(entry.Value, &set); err != nil {
			b.Logger().Warn("skipping unparseable minter set", "name", name, "error", err)
			continue
		}
		b.loadMinterSet(&set)
	}
	return nil
}

func (b *backend) minterSetExists(ctx context.Context, storage logical.Storage, name string) (bool, error) {
	entry, err := storage.Get(ctx, "minter-sets/"+name)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}
