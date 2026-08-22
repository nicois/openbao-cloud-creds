package credentialvultr

import (
	"context"
	"encoding/json"
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
				"name":    {Type: framework.TypeString, Description: "Name of the minter set"},
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

// pathMinterSetRotate is the uniform rotate endpoint. Vultr sub-user API keys
// cannot be self-rotated headlessly by the plugin, so this always rejects before
// any state change — the endpoint exists only so clients see one consistent
// surface across all clouds. Rotate Vultr minters out-of-band.
func (b *backend) pathMinterSetRotate(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return credenvelope.ErrorResponse(credenvelope.ErrUnsupported, "minter rotation is not supported for %s; rotate this minter out-of-band", cloudName), nil
}

// parseMinters converts the raw "minters" field into cloudconfig.Minters.
// minterSetStoragePrefix is where minter sets are persisted.
const minterSetStoragePrefix = "minter-sets/"

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
		minters = append(minters, minter)
	}
	return minters, nil
}

func (b *backend) pathMinterSetWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
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

func (b *backend) pathMinterSetRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
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
	}}, nil
}

func (b *backend) pathMinterSetDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
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
