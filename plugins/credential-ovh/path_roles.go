package credentialovh

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// OVH OAuth2 access tokens have a fixed 1-hour lifetime.
	maxOVHTTL = 3600 * time.Second
)

type ovhRole struct {
	Name       string        `json:"name"`
	DefaultTTL time.Duration `json:"default_ttl"`
	MaxTTL     time.Duration `json:"max_ttl"`
	MinterSet  string        `json:"minter_set"`
	Disabled   bool          `json:"disabled,omitempty"`
}

func (b *backend) rolePaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
				"default_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     3600,
					Description: "Default lease TTL in seconds (max 3600s — OVH tokens are fixed 1h)",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     3600,
					Description: "Maximum lease TTL in seconds (max 3600s)",
				},
				"minter_set": {
					Type:        framework.TypeString,
					Description: "Name of the minter set this role mints from (required)",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
			},
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRoleList},
			},
		},
	}
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	defaultTTL := time.Duration(d.Get("default_ttl").(int)) * time.Second
	maxTTL := time.Duration(d.Get("max_ttl").(int)) * time.Second

	// OVH tokens have a fixed 1h lifetime — TTLs must not exceed that
	if maxTTL > maxOVHTTL {
		return logical.ErrorResponse("max_ttl must not exceed 3600 seconds (OVH tokens have a fixed 1-hour lifetime)"), nil
	}
	if defaultTTL > maxOVHTTL {
		return logical.ErrorResponse("default_ttl must not exceed 3600 seconds (OVH tokens have a fixed 1-hour lifetime)"), nil
	}

	minterSet := d.Get("minter_set").(string)
	if minterSet == "" {
		return logical.ErrorResponse("minter_set is required"), nil
	}
	exists, err := b.minterSetExists(ctx, req.Storage, minterSet)
	if err != nil {
		return nil, err
	}
	if !exists {
		return logical.ErrorResponse("minter_set %q does not exist", minterSet), nil
	}

	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      "ovh",
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	ovhR := &ovhRole{
		Name:       name,
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		MinterSet:  minterSet,
	}

	entry, err := logical.StorageEntryJSON("roles/"+name, ovhR)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	entry, err := req.Storage.Get(ctx, "roles/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role ovhRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		"name":        role.Name,
		"default_ttl": int(role.DefaultTTL.Seconds()),
		"max_ttl":     int(role.MaxTTL.Seconds()),
		"minter_set":  role.MinterSet,
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := req.Storage.Delete(ctx, "roles/"+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}
