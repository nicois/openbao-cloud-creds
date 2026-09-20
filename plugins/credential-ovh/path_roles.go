package credentialovh

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
	// OVH OAuth2 access tokens have a fixed 1-hour lifetime; role TTLs may not
	// exceed it.
	maxOVHTTL = 3600 * time.Second

	// ...nor undercut it. OVH's token endpoint accepts no lifetime parameter and
	// OVH exposes no token-revoke API, so an issued token is valid for exactly
	// 1 hour regardless of the role's TTL. A shorter TTL would end the lease
	// while the credential stayed live upstream — a dishonest TTL we cannot
	// enforce — so short TTLs are rejected at role-write time rather than
	// silently misrepresented. Combined with maxOVHTTL this pins OVH roles to
	// exactly 3600s. See docs/decisions.md ("Why TTL bounds are enforced ...").
	minOVHTTL = maxOVHTTL

	// ovhShortTTLMsg is the rejection for a sub-1h TTL; %s is the field name.
	ovhShortTTLMsg = "%s must be at least 3600 seconds: OVH tokens have a fixed " +
		"1-hour lifetime that cannot be shortened at mint time, and OVH exposes no " +
		"token-revoke API, so a shorter TTL would end the lease while the credential " +
		"stayed valid upstream"

	// Role TTL schema defaults, in seconds (framework.TypeDurationSecond). Both
	// default to the OVH token lifetime (1h) since that is the hard ceiling.
	defaultRoleTTLSeconds    = 3600 // 1h
	defaultRoleMaxTTLSeconds = 3600 // 1h
)

type ovhRole struct {
	Name                  string        `json:"name"`
	DefaultTTL            time.Duration `json:"default_ttl"`
	MaxTTL                time.Duration `json:"max_ttl"`
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
				"default_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     defaultRoleTTLSeconds,
					Description: "Default lease TTL in seconds (must be exactly 3600s — OVH tokens have a fixed 1h lifetime and cannot be revoked)",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     defaultRoleMaxTTLSeconds,
					Description: "Maximum lease TTL in seconds (must be exactly 3600s — see default_ttl)",
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
	defaultTTL := time.Duration(d.Get("default_ttl").(int)) * time.Second
	maxTTL := time.Duration(d.Get("max_ttl").(int)) * time.Second

	// OVH tokens have a fixed 1h lifetime — TTLs must not exceed that
	if maxTTL > maxOVHTTL {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "max_ttl must not exceed 3600 seconds (OVH tokens have a fixed 1-hour lifetime)"), nil
	}
	if defaultTTL > maxOVHTTL {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "default_ttl must not exceed 3600 seconds (OVH tokens have a fixed 1-hour lifetime)"), nil
	}

	// ...nor be shorter than it: OVH cannot mint a shorter-lived token and cannot
	// revoke one, so a shorter TTL would be unenforceable.
	if maxTTL < minOVHTTL {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, ovhShortTTLMsg, "max_ttl"), nil
	}
	if defaultTTL < minOVHTTL {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, ovhShortTTLMsg, "default_ttl"), nil
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
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}

	// Refused HERE rather than at issuance: a requirement this binary cannot parse must
	// never reach storage, or the role reads back fine and fails closed on the first
	// caller instead of on the operator who mistyped it.
	requireCallerIdentity := d.Get(fieldRequireCallerIdentity).(string)
	if _, err := requester.ParseRequirement(requireCallerIdentity); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}

	ovhR := &ovhRole{
		Name:                  name,
		DefaultTTL:            defaultTTL,
		MaxTTL:                maxTTL,
		MinterSet:             minterSet,
		Disabled:              d.Get(fieldDisabled).(bool),
		RequireCallerIdentity: requireCallerIdentity,
	}

	// Prove the bound set's minters can actually mint what this role asks for,
	// so an unsuitable minting key is reported to whoever wrote the role rather
	// than to the first caller that reads credentials from it.
	if errResp := b.verifyRoleCapability(ctx, req.Storage, ovhR); errResp != nil {
		return errResp, nil
	}
	entry, err := logical.StorageEntryJSON("roles/"+name, ovhR)
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

	var role ovhRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "parsing a stored entry", err), nil
	}

	return &logical.Response{Data: roleData(&role)}, nil
}

// roleData renders a role for its read endpoint, in the same field names and units the
// write schema accepts. That is what lets a write to an existing role prefill from it
// (cloudconfig.PrefillRoleWrite), so a field cannot be readable and unpatchable.
func roleData(role *ovhRole) map[string]any {
	return map[string]any{
		"name":                     role.Name,
		"default_ttl":              int(role.DefaultTTL.Seconds()),
		"max_ttl":                  int(role.MaxTTL.Seconds()),
		"minter_set":               role.MinterSet,
		fieldDisabled:              role.Disabled,
		fieldRequireCallerIdentity: role.RequireCallerIdentity,
	}
}

// storedRoleData renders a STORED role the same way, for a write that is patching one.
func storedRoleData(raw []byte) (map[string]any, error) {
	var role ovhRole
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

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	return logical.ListResponse(entries), nil
}
