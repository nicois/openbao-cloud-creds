package credentialazure

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/requester"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// Role TTL schema defaults, in seconds (framework.TypeDurationSecond).
	// The role TTL defaults are deliberately the SAME on every cloud that can honour
	// them — 15m default, 1h maximum — because short-lived credentials are the product
	// and a default is what most roles will actually run with. They used to vary by up
	// to 400x across ten plugins with identical documentation (A28 in
	// docs/audit-2026-08-22.md). Only OVH (a fixed 1h token, so exactly 3600 either
	// way) and OCI (whose lease TTL is derived from the rotation period) differ, and
	// both are forced by the cloud rather than chosen.
	defaultRoleTTLSeconds    = 900  // 15m
	defaultRoleMaxTTLSeconds = 3600 // 1h
)

type azureRole struct {
	Name                  string        `json:"name"`
	DefaultTTL            time.Duration `json:"default_ttl"`
	MaxTTL                time.Duration `json:"max_ttl"`
	AppObjectID           string        `json:"app_object_id"`
	ClientID              string        `json:"client_id"`
	SubscriptionID        string        `json:"subscription_id,omitempty"`
	MinterSet             string        `json:"minter_set"`
	Disabled              bool          `json:"disabled,omitempty"`
	RequireCallerIdentity string        `json:"require_caller_identity,omitempty"`
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
				fieldDisabled: {
					Type: framework.TypeBool,
					Description: "When true the role issues nothing, answering role_disabled. This is " +
						"the lever for a suspected credential leak: deleting the role stops nothing, " +
						"because live leases stay renewable and issued credentials keep working. " +
						"Writing it alone is enough — a write to an existing role changes only the " +
						"fields it carries. Reversible; it destroys nothing already issued",
				},
				fieldRequireCallerIdentity: {
					Type:        framework.TypeString,
					Description: requester.RoleFieldDescription(),
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
	// A write to an existing role changes the fields it carries and leaves the rest as
	// they were, so `disabled=true` on its own is a complete request.
	if err := cloudconfig.PrefillRoleWrite(ctx, req.Storage, "roles/"+name, d, storedRoleData); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
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

	// Refused here rather than at issuance: an operator who mistypes the requirement finds
	// out on the write they made, not through a role that turns out to refuse every caller.
	requireCallerIdentity := d.Get(fieldRequireCallerIdentity).(string)
	if _, err := requester.ParseRequirement(requireCallerIdentity); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}

	minterSet := d.Get(fieldMinterSet).(string)
	if minterSet == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_set is required"), nil
	}
	exists, err := b.minterSetExists(ctx, req.Storage, minterSet)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "a storage operation", err), nil
	}
	if !exists {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_set %q does not exist", minterSet), nil
	}

	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      cloudName,
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]any{
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
		Name:                  name,
		DefaultTTL:            defaultTTL,
		MaxTTL:                maxTTL,
		AppObjectID:           appObjectID,
		ClientID:              clientID,
		SubscriptionID:        subscriptionID,
		MinterSet:             minterSet,
		Disabled:              d.Get(fieldDisabled).(bool),
		RequireCallerIdentity: requireCallerIdentity,
	}

	// Prove the bound set's minters can actually mint what this role asks for,
	// so an unsuitable minting key is reported to whoever wrote the role rather
	// than to the first caller that reads credentials from it.
	if errResp := b.verifyRoleCapability(ctx, req.Storage, azRole); errResp != nil {
		return errResp, nil
	}
	entry, err := logical.StorageEntryJSON("roles/"+name, azRole)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "encoding an entry for storage", err), nil
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "writing to storage", err), nil
	}

	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	entry, err := req.Storage.Get(ctx, "roles/"+name)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	if entry == nil {
		return nil, nil
	}

	var role azureRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "parsing a stored entry", err), nil
	}

	return &logical.Response{Data: roleData(&role)}, nil
}

// roleData renders a role for its read endpoint, in the same field names and units the
// write schema accepts. That is what lets a write to an existing role prefill from it
// (cloudconfig.PrefillRoleWrite), so a field cannot be readable and unpatchable.
func roleData(role *azureRole) map[string]any {
	return map[string]any{
		fieldName:                  role.Name,
		fieldDefaultTTL:            int(role.DefaultTTL.Seconds()),
		fieldMaxTTL:                int(role.MaxTTL.Seconds()),
		fieldAppObjectID:           role.AppObjectID,
		fieldClientID:              role.ClientID,
		"subscription_id":          role.SubscriptionID,
		fieldMinterSet:             role.MinterSet,
		fieldDisabled:              role.Disabled,
		fieldRequireCallerIdentity: role.RequireCallerIdentity,
	}
}

// storedRoleData renders a STORED role the same way, for a write that is patching one.
func storedRoleData(raw []byte) (map[string]any, error) {
	var role azureRole
	if err := json.Unmarshal(raw, &role); err != nil {
		return nil, err
	}
	return roleData(&role), nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	if err := req.Storage.Delete(ctx, "roles/"+name); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "deleting from storage", err), nil
	}
	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	return logical.ListResponse(entries), nil
}
