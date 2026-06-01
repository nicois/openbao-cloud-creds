package credentialupcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
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
				"minters": {Type: framework.TypeSlice, Description: "Minter credentials in this set"},
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
		minter := cloudconfig.Minter{
			ID:        fmt.Sprintf("%v", mMap["id"]),
			Token:     fmt.Sprintf("%v", mMap["token"]),
			CreatedAt: time.Now(),
		}
		if ne, ok := mMap["never_expires"].(bool); ok && ne {
			minter.NeverExpires = true
		}
		if exp, ok := mMap["expires_at"].(string); ok {
			t, err := time.Parse(time.RFC3339, exp)
			if err != nil {
				return nil, fmt.Errorf("invalid expires_at for minter %s: %v", minter.ID, err)
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
		minters = append(minters, minter)
	}
	return minters, nil
}

func (b *backend) pathMinterSetWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	if err := cloudconfig.ValidateSetName(name); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	minters, err := parseMinters(d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := cloudconfig.ValidateMinterSet(minters); err != nil {
		return logical.ErrorResponse("invalid minter set: %v", err), nil
	}
	set := &cloudconfig.MinterSet{Name: name, Minters: minters}
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
// and only if that passes mints the real successor (a mint-capable UpCloud
// token), health-checks it, then (atomically, under rotateSweepMu) appends the
// successor active and marks the original retired. The original's upstream
// token stays alive until the retired-sweep deletes it after minter_retire_grace
// — so no other raft node, whose in-memory snapshot may still hold the original
// as selectable, ever loses its minter mid-flight.
func (b *backend) pathMinterSetRotate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	minterID := d.Get(fieldMinterID).(string)
	if minterID == "" {
		return logical.ErrorResponse("minter_id is required"), nil
	}

	b.rotateSweepMu.Lock()
	defer b.rotateSweepMu.Unlock()

	set, err := b.readSet(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return logical.ErrorResponse("minter set %q does not exist", name), nil
	}

	oldIdx := -1
	for i := range set.Minters {
		if set.Minters[i].ID == minterID {
			oldIdx = i
			break
		}
	}
	if oldIdx == -1 {
		return logical.ErrorResponse("minter %q not found in set %q", minterID, name), nil
	}
	old := set.Minters[oldIdx]
	if old.Retired {
		return logical.ErrorResponse("minter %q is already retired", minterID), nil
	}

	// 1. Validate the prospective post-rotation set FIRST, using a SYNTHETIC
	//    successor — no cloud call yet. ValidateMinterSet only inspects
	//    NeverExpires/ExpiresAt/Retired, so a synthetic stand-in with the same
	//    expiry the real successor will have (defaultMinterSecretLifetime,
	//    matching RotateMinter) is exact. Validating before minting means a
	//    rotation that would break the set never consumes an upstream token slot
	//    — load-bearing where the cloud caps tokens per account (audit2 #9).
	retiredAt := time.Now()
	synthetic := cloudconfig.Minter{
		ID:           old.ID + "-rot-pending",
		NeverExpires: old.NeverExpires,
	}
	if !old.NeverExpires {
		synthetic.ExpiresAt = time.Now().Add(defaultMinterSecretLifetime)
	}
	if verr := cloudconfig.ValidateMinterSet(withRotatedSuccessor(set.Minters, oldIdx, retiredAt, synthetic)); verr != nil {
		return logical.ErrorResponse("rotation would invalidate the minter set: %v", verr), nil
	}

	// 2. Validation passed: NOW mint the real mint-capable successor, using a
	//    healthy active client (prefer the minter being rotated if it is itself
	//    selectable, else any other active minter in the set).
	client, err := b.rotationClient(name, minterID, time.Now())
	if err != nil {
		return logical.ErrorResponse("no healthy minter to perform rotation: %v", err), nil
	}
	successor, err := client.RotateMinter(ctx, old)
	if err != nil {
		return logical.ErrorResponse("rotation failed: %v", err), nil
	}

	// 3. Health-check the successor via a client built from ITS token. If it
	//    fails, clean up the just-minted token and reject with no state change.
	successorClient := b.newClientForMinter(successor)
	if status, herr := successorClient.CheckHealth(ctx); herr != nil || status != http.StatusOK {
		b.cleanupSuccessor(ctx, client, successor)
		return logical.ErrorResponse("successor minter failed health check (status %d): %v", status, herr), nil
	}

	// 4. Commit: append the real successor active, mark the old retired, then
	//    persist the set and refresh the in-memory snapshot.
	set.Minters = withRotatedSuccessor(set.Minters, oldIdx, retiredAt, successor)
	if err := b.persistSet(ctx, req.Storage, set); err != nil {
		// Persist failed after minting the successor: best-effort clean up so we
		// don't leak an upstream token no set references.
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

// rotationClient returns a client to mint the successor: the minter being
// rotated if it is itself selectable, otherwise any other healthy active minter
// in the set (so a wedged minter can still be rotated out by a sibling).
func (b *backend) rotationClient(setName, minterID string, now time.Time) (*upcloudClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	apiURL := b.upcloudAPIURL()
	username := b.username
	states, ok := b.minterSets[setName]
	if !ok {
		return nil, fmt.Errorf("minter set %q not loaded", setName)
	}
	if ms, ok := states[minterID]; ok && !ms.minter.Retired && ms.sm.Selectable(now) {
		return newUpCloudClient(apiURL, username, ms.minter.Token), nil
	}
	for id, ms := range states {
		if id == minterID {
			continue
		}
		if !ms.minter.Retired && ms.sm.Selectable(now) {
			return newUpCloudClient(apiURL, username, ms.minter.Token), nil
		}
	}
	return nil, fmt.Errorf("no healthy active minter in set %q", setName)
}

// newClientForMinter builds a client authenticating AS the given minter's token.
func (b *backend) newClientForMinter(m cloudconfig.Minter) *upcloudClient {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return newUpCloudClient(b.upcloudAPIURL(), b.username, m.Token)
}

// cleanupSuccessor best-effort deletes a just-minted successor token upstream
// when the rotation is aborted (health-check failure or persist failure). Uses
// the minting client. Failures are logged, not returned — the rotation is
// already being rejected.
func (b *backend) cleanupSuccessor(ctx context.Context, client *upcloudClient, successor cloudconfig.Minter) {
	tokenID := successor.RotationParams[fieldTokenID]
	if tokenID == "" {
		return
	}
	if status, err := client.DeleteToken(ctx, tokenID); err != nil && status != http.StatusNotFound {
		b.Logger().Warn("failed to clean up aborted-rotation successor token",
			"cloud", cloudName, "token_id", tokenID, "status", status, "error", err)
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
