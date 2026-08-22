package credentialexoscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
				fieldName:       {Type: framework.TypeString, Description: "Name of the minter set"},
				fieldMintersKey: {Type: framework.TypeSlice, Description: "Minter credentials in this set"},
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

// parseMinters converts the raw fieldMintersKey field into cloudconfig.Minters.
// Exoscale minters carry a single Bearer "key" credential.
// minterSetStoragePrefix is where minter sets are persisted.
const minterSetStoragePrefix = "minter-sets/"

func parseMinters(d *framework.FieldData) ([]cloudconfig.Minter, error) {
	raw := d.Get(fieldMintersKey)
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
			Token:     fmt.Sprintf("%v", mMap["key"]),
			CreatedAt: time.Now(),
		}
		if ne, ok := mMap[neverExpiresKey].(bool); ok && ne {
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
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
	minters, err := parseMinters(d)
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
	if err := cloudconfig.ValidateMinterIDs(minters); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
	// Carry retirement and creation state forward from the stored set. Without
	// this, editing a set during the retirement grace silently un-retires a
	// rotated-out minter and cancels the sweep that deletes its upstream
	// credential (A13 in docs/audit-2026-08-22.md).
	stored, err := b.loadStoredSet(ctx, req.Storage, name)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "a storage operation", err), nil
	}
	minters = cloudconfig.PreserveLifecycle(minters, stored, time.Now())

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
		return credenvelope.InternalResponse(b.Logger().Warn, "encoding an entry for storage", err), nil
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "writing to storage", err), nil
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

// locateRotatable finds the active, rotatable minter named minterID in set. It
// returns its index and a copy, or a non-nil error response (minter absent,
// already retired, or missing the role_id needed to mint a mint-capable
// successor) which the caller surfaces as a logical error.
func locateRotatable(set *cloudconfig.MinterSet, minterID, name string) (int, cloudconfig.Minter, *logical.Response) {
	oldIdx := -1
	for i := range set.Minters {
		if set.Minters[i].ID == minterID {
			oldIdx = i
			break
		}
	}
	if oldIdx == -1 {
		return -1, cloudconfig.Minter{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter %q not found in set %q", minterID, name)
	}
	old := set.Minters[oldIdx]
	if old.Retired {
		return -1, cloudconfig.Minter{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter %q is already retired", minterID)
	}
	// A mint-capable successor needs the minter's own key-management role-id.
	// Reject early (no cloud call) when it is absent.
	if old.RotationParams[fieldRoleID] == "" {
		return -1, cloudconfig.Minter{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter has no rotation_params.role_id; "+
			"cannot create a mint-capable successor — ensure the minter role permits key creation")
	}
	return oldIdx, old, nil
}

// validateProspectiveRotation checks the post-rotation set against a SYNTHETIC
// successor (no cloud call). ValidateMinterSet only inspects
// NeverExpires/ExpiresAt/Retired, so a synthetic stand-in with the same expiry
// the real successor will have (defaultMinterSecretLifetime, matching
// RotateMinter) is exact.
func validateProspectiveRotation(set *cloudconfig.MinterSet, oldIdx int, old cloudconfig.Minter, retiredAt time.Time) error {
	synthetic := cloudconfig.Minter{
		ID:           old.ID + "-rot-pending",
		NeverExpires: old.NeverExpires,
	}
	if !old.NeverExpires {
		synthetic.ExpiresAt = time.Now().Add(defaultMinterSecretLifetime)
	}
	return cloudconfig.ValidateMinterSet(withRotatedSuccessor(set.Minters, oldIdx, retiredAt, synthetic))
}

// pathMinterSetRotate rotates one minter in a set: it first validates the
// prospective post-rotation set against a synthetic successor (no cloud call),
// and only if that passes mints the real successor (an Exoscale IAM API key
// bound to the minter's OWN key-management role-id, so the successor is itself
// mint-capable), health-checks it AS the successor, then (atomically, under
// rotateSweepMu) appends the successor active and marks the original retired.
// The original's upstream key stays alive until the retired-sweep deletes it
// after minter_retire_grace — so no other raft node, whose in-memory snapshot
// may still hold the original as selectable, ever loses its minter mid-flight.
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
		return credenvelope.InternalResponse(b.Logger().Warn, "a storage operation", err), nil
	}
	if set == nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter set %q does not exist", name), nil
	}

	oldIdx, old, errResp := locateRotatable(set, minterID, name)
	if errResp != nil {
		return errResp, nil
	}

	// 1. Validate the prospective post-rotation set FIRST, using a synthetic
	//    successor — no cloud call yet. Validating before minting means a
	//    rotation that would break the set never consumes an upstream key slot.
	retiredAt := time.Now()
	if verr := validateProspectiveRotation(set, oldIdx, old, retiredAt); verr != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "rotation would invalidate the minter set: %v", verr), nil
	}

	// 2. Validation passed: NOW mint the real mint-capable successor, using a
	//    healthy active client (prefer the minter being rotated if it is itself
	//    selectable, else any other active minter in the set).
	client, err := b.rotationClient(name, minterID, time.Now())
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "no healthy minter to perform rotation: %v", err), nil
	}
	successor, err := client.RotateMinter(ctx, old)
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "successor could not be granted key-creation; "+
			"ensure the minter role permits it: %v", err), nil
	}

	// 3. Health-check the successor via a client built from ITS key. If it fails,
	//    clean up the just-minted key and reject with no state change.
	successorClient := b.newClientForMinter(successor)
	if status, herr := successorClient.CheckHealth(ctx); herr != nil || status != http.StatusOK {
		b.cleanupSuccessor(ctx, client, successor)
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "successor minter failed health check (status %d): %v", status, herr), nil
	}

	// 3b. Health is not capability: /v2/zone answers for any live key, including
	//     one whose IAM role cannot create keys or cannot grant a bound role's
	//     role-id. Prove the successor can mint before committing.
	if errResp := b.verifySuccessorCapability(ctx, req.Storage, name, successor); errResp != nil {
		b.cleanupSuccessor(ctx, client, successor)
		return errResp, nil
	}

	// 4. Commit: append the real successor active, mark the old retired, then
	//    persist the set and refresh the in-memory snapshot.
	set.Minters = withRotatedSuccessor(set.Minters, oldIdx, retiredAt, successor)
	if err := b.persistSet(ctx, req.Storage, set); err != nil {
		// Persist failed after minting the successor: best-effort clean up so we
		// don't leak an upstream key no set references.
		b.cleanupSuccessor(ctx, client, successor)
		return credenvelope.InternalResponse(b.Logger().Warn, "a storage operation", err), nil
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
func (b *backend) rotationClient(setName, minterID string, now time.Time) (*exoscaleClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	apiURL := b.exoscaleAPIURL()
	states, ok := b.minterSets[setName]
	if !ok {
		return nil, fmt.Errorf("minter set %q not loaded", setName)
	}
	if ms, ok := states[minterID]; ok && !ms.minter.Retired && ms.sm.Selectable(now) {
		return newExoscaleClient(apiURL, ms.minter.Token), nil
	}
	for id, ms := range states {
		if id == minterID {
			continue
		}
		if !ms.minter.Retired && ms.sm.Selectable(now) {
			return newExoscaleClient(apiURL, ms.minter.Token), nil
		}
	}
	return nil, fmt.Errorf("no healthy active minter in set %q", setName)
}

// newClientForMinter builds a client authenticating AS the given minter's key.
func (b *backend) newClientForMinter(m cloudconfig.Minter) *exoscaleClient {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return newExoscaleClient(b.exoscaleAPIURL(), m.Token)
}

// cleanupSuccessor best-effort deletes a just-minted successor key upstream when
// the rotation is aborted (health-check failure or persist failure). Uses the
// minting client. Failures are logged, not returned — the rotation is already
// being rejected.
func (b *backend) cleanupSuccessor(ctx context.Context, client *exoscaleClient, successor cloudconfig.Minter) {
	keyID := successor.RotationParams[fieldKeyID]
	if keyID == "" {
		return
	}
	if status, err := client.DeleteAPIKey(ctx, keyID); err != nil && status != http.StatusNotFound {
		b.Logger().Warn("failed to clean up aborted-rotation successor key",
			"cloud", cloudName, "key_id", keyID, "status", status, "error", err)
	}
}

func (b *backend) pathMinterSetRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	entry, err := req.Storage.Get(ctx, "minter-sets/"+name)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	if entry == nil {
		return nil, nil
	}
	var set cloudconfig.MinterSet
	if err := json.Unmarshal(entry.Value, &set); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "parsing a stored entry", err), nil
	}
	ids := make([]string, 0, len(set.Minters))
	for i := range set.Minters {
		ids = append(ids, set.Minters[i].ID)
	}
	return &logical.Response{Data: map[string]interface{}{
		"name": set.Name, "minter_count": len(set.Minters), "minter_ids": ids,
		// Per-minter lifecycle and health. All of this was in this process and none
		// of it was observable, so an operator could not see which minter was
		// retired, when the sweep would delete it, or that a minter was auth_failing
		// or rate-limited (A27). No credential material is included.
		fieldMintersKey: b.minterStatus(&set),
	}}, nil
}

func (b *backend) pathMinterSetDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	if err := req.Storage.Delete(ctx, "minter-sets/"+name); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "deleting from storage", err), nil
	}
	b.mu.Lock()
	delete(b.minterSets, name)
	b.mu.Unlock()
	return nil, nil
}

func (b *backend) pathMinterSetList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "minter-sets/")
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	return logical.ListResponse(entries), nil
}

func (b *backend) loadMinterSet(set *cloudconfig.MinterSet) {
	b.mu.Lock()
	defer b.mu.Unlock()
	previous := b.minterSets[set.Name]
	states := make(map[string]*minterState, len(set.Minters))
	for i := range set.Minters {
		m := set.Minters[i]
		// Carry the recovery state machine forward for a minter we already know.
		// Building a fresh one discarded everything it had learned: an AuthFailing
		// minter became Healthy and immediately selectable again, and an open
		// rate-limit cooldown was thrown away — on any unrelated minter-set write,
		// not merely on a reload (A25 in docs/audit-2026-08-22.md). That made
		// RSK-007's "the operator never sees a sustained signal" strictly worse than
		// documented, because a routine write reset the signal.
		sm := recovery.NewStateMachine(recovery.Config{
			AuthFailThreshold:   authFailThreshold,
			HealthCheckInterval: healthCheckInterval,
		})
		if existing, known := previous[m.ID]; known && existing.sm != nil {
			sm = existing.sm
		}
		states[m.ID] = &minterState{set: set.Name, minter: m, sm: sm}
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
		// OBC-005 requires an invalid minter set to fail at config LOAD, not only at
		// config write, and this path used to register whatever was persisted. A set
		// no write would accept today — one a version-skewed binary stripped fields
		// from, or storage was edited under — was therefore loaded fail-OPEN and
		// issued from, which is exactly the silent single-minter case RSK-005 exists
		// to prevent (A29 in docs/audit-2026-08-22.md).
		//
		// Not registering it is the fail-closed action available here: roles bound to
		// it then fail to issue with config_invalid naming the set, and the operator
		// can rewrite it. Refusing to load the MOUNT would crash-loop it, which is
		// the mistake A2 was about.
		if err := cloudconfig.ValidateMinterSet(set.Minters); err != nil {
			b.Logger().Error("refusing to load an invalid minter set; roles bound to it cannot issue "+
				"until it is rewritten", fieldCloud, cloudName, "name", name, "error", err)
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

// loadStoredSet reads the persisted minter set, or nil when it does not exist yet.
// A storage error is returned rather than treated as "absent": silently treating an
// unreadable set as new would discard the retirement state PreserveLifecycle exists
// to carry forward.
func (b *backend) loadStoredSet(ctx context.Context, storage logical.Storage, name string,
) (*cloudconfig.MinterSet, error) {
	entry, err := storage.Get(ctx, minterSetStoragePrefix+name)
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

// minterStatus renders each minter's lifecycle and health for the read endpoint.
// Secrets are structurally absent: only ids, timestamps, flags and the recovery
// snapshot are emitted, never Token or RotationParams.
func (b *backend) minterStatus(set *cloudconfig.MinterSet) []map[string]interface{} {
	now := time.Now()
	b.mu.RLock()
	states := b.minterSets[set.Name]
	b.mu.RUnlock()

	out := make([]map[string]interface{}, 0, len(set.Minters))
	for i := range set.Minters {
		m := set.Minters[i]
		entry := map[string]interface{}{
			"id":            m.ID,
			neverExpiresKey: m.NeverExpires,
			"retired":       m.Retired,
		}
		if !m.CreatedAt.IsZero() {
			entry["created_at"] = m.CreatedAt.UTC().Format(time.RFC3339)
		}
		if !m.ExpiresAt.IsZero() {
			entry["expires_at"] = m.ExpiresAt.UTC().Format(time.RFC3339)
		}
		if !m.RetiredAt.IsZero() {
			entry["retired_at"] = m.RetiredAt.UTC().Format(time.RFC3339)
		}
		if state, known := states[m.ID]; known && state.sm != nil {
			entry["health"] = state.sm.Snapshot(now)
		}
		out = append(out, entry)
	}
	return out
}
