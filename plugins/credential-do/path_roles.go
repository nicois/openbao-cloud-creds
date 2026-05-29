package credentialdo

import (
	"context"
	"encoding/json"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

type doRole struct {
	Name       string        `json:"name"`
	DefaultTTL time.Duration `json:"default_ttl"`
	MaxTTL     time.Duration `json:"max_ttl"`
	Scopes     string        `json:"scopes"`
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
					Default:     900,
					Description: "Default lease TTL",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     3600,
					Description: "Maximum lease TTL",
				},
				"scopes": {
					Type:        framework.TypeString,
					Description: "Comma-separated DO token scopes",
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
	scopes := d.Get("scopes").(string)

	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      "do",
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]interface{}{
			"scopes": scopes,
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	doR := &doRole{
		Name:       name,
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		Scopes:     scopes,
	}

	entry, err := logical.StorageEntryJSON("roles/"+name, doR)
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

	var role doRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":        role.Name,
			"default_ttl": int(role.DefaultTTL.Seconds()),
			"max_ttl":     int(role.MaxTTL.Seconds()),
			"scopes":      role.Scopes,
		},
	}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := req.Storage.Delete(ctx, "roles/"+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}
