package credentialazure

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// Role TTL schema defaults, in seconds (framework.TypeDurationSecond).
	defaultRoleTTLSeconds    = 3600  // 1h
	defaultRoleMaxTTLSeconds = 86400 // 24h
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
				fieldName: {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
				fieldDefaultTTL: {
					Type:        framework.TypeDurationSecond,
					Default:     defaultRoleTTLSeconds,
					Description: "Default lease TTL (password expiry)",
				},
				fieldMaxTTL: {
					Type:        framework.TypeDurationSecond,
					Default:     defaultRoleMaxTTLSeconds,
					Description: "Maximum lease TTL",
				},
				fieldAppObjectID: {
					Type:        framework.TypeString,
					Description: "Azure AD application object ID to add passwords to",
				},
				fieldClientID: {
					Type:        framework.TypeString,
					Description: "The app's client ID (returned in credential envelope)",
				},
				"subscription_id": {
					Type:        framework.TypeString,
					Description: "Optional Azure subscription ID (returned in envelope for convenience)",
				},
				fieldMinterSet: {
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
	name := d.Get(fieldName).(string)
	defaultTTL := time.Duration(d.Get(fieldDefaultTTL).(int)) * time.Second
	maxTTL := time.Duration(d.Get(fieldMaxTTL).(int)) * time.Second
	appObjectID := d.Get(fieldAppObjectID).(string)
	clientID := d.Get(fieldClientID).(string)

	if appObjectID == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "app_object_id is required"), nil
	}
	if clientID == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "client_id is required"), nil
	}

	minterSet := d.Get(fieldMinterSet).(string)
	if minterSet == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_set is required"), nil
	}
	exists, err := b.minterSetExists(ctx, req.Storage, minterSet)
	if err != nil {
		return nil, err
	}
	if !exists {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_set %q does not exist", minterSet), nil
	}

	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      cloudName,
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]interface{}{
			fieldAppObjectID: appObjectID,
			fieldClientID:    clientID,
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
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

	// Prove the bound set's minters can actually mint what this role asks for,
	// so an unsuitable minting key is reported to whoever wrote the role rather
	// than to the first caller that reads credentials from it.
	if errResp := b.verifyRoleCapability(ctx, req.Storage, azRole); errResp != nil {
		return errResp, nil
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
	name := d.Get(fieldName).(string)
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
			fieldName:         role.Name,
			fieldDefaultTTL:   int(role.DefaultTTL.Seconds()),
			fieldMaxTTL:       int(role.MaxTTL.Seconds()),
			fieldAppObjectID:  role.AppObjectID,
			fieldClientID:     role.ClientID,
			"subscription_id": role.SubscriptionID,
			fieldMinterSet:    role.MinterSet,
		},
	}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
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
