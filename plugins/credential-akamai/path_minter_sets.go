package credentialakamai

import (
	"context"
	"encoding/json"
	"fmt"
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
			Pattern: "minter-sets/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathMinterSetList},
			},
		},
	}
}

// parseMinters converts the raw "minters" field into cloudconfig.Minters.
// Each Akamai minter token must be an EdgeGrid triple
// "client_token:access_token:client_secret".
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
		token := fmt.Sprintf("%v", mMap["token"])
		// Validate the EdgeGrid triple format up front.
		if _, err := parseEdgeGridToken(token); err != nil {
			return nil, fmt.Errorf("invalid minter token for %v: %v", mMap["id"], err)
		}
		minter := cloudconfig.Minter{
			ID:        fmt.Sprintf("%v", mMap["id"]),
			Token:     token,
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
	for _, m := range set.Minters {
		ids = append(ids, m.ID)
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
	for _, m := range set.Minters {
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
