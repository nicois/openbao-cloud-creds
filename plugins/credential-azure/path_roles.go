package credentialazure

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type azureRole struct {
	Name           string        `json:"name"`
	DefaultTTL     time.Duration `json:"default_ttl"`
	MaxTTL         time.Duration `json:"max_ttl"`
	AppObjectID    string        `json:"app_object_id"`
	ClientID       string        `json:"client_id"`
	SubscriptionID string        `json:"subscription_id,omitempty"`
	MinterSet      string        `json:"minter_set"`
	Disabled       bool          `json:"disabled,omitempty"`
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
					Description: "Default lease TTL (password expiry)",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     86400,
					Description: "Maximum lease TTL",
				},
				"app_object_id": {
					Type:        framework.TypeString,
					Description: "Azure AD application object ID to add passwords to",
				},
				"client_id": {
					Type:        framework.TypeString,
					Description: "The app's client ID (returned in credential envelope)",
				},
				"subscription_id": {
					Type:        framework.TypeString,
					Description: "Optional Azure subscription ID (returned in envelope for convenience)",
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
	appObjectID := d.Get("app_object_id").(string)
	clientID := d.Get("client_id").(string)

	if appObjectID == "" {
		return logical.ErrorResponse("app_object_id is required"), nil
	}
	if clientID == "" {
		return logical.ErrorResponse("client_id is required"), nil
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
		Cloud:      "azure",
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]interface{}{
			"app_object_id": appObjectID,
			"client_id":     clientID,
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	subscriptionID := ""
	if sid, ok := d.GetOk("subscription_id"); ok {
		subscriptionID = sid.(string)
	}

	azRole := &azureRole{
		Name:           name,
		DefaultTTL:     defaultTTL,
		MaxTTL:         maxTTL,
		AppObjectID:    appObjectID,
		ClientID:       clientID,
		SubscriptionID: subscriptionID,
		MinterSet:      minterSet,
	}

	entry, err := logical.StorageEntryJSON("roles/"+name, azRole)
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

	var role azureRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":            role.Name,
			"default_ttl":     int(role.DefaultTTL.Seconds()),
			"max_ttl":         int(role.MaxTTL.Seconds()),
			"app_object_id":   role.AppObjectID,
			"client_id":       role.ClientID,
			"subscription_id": role.SubscriptionID,
			"minter_set":      role.MinterSet,
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
