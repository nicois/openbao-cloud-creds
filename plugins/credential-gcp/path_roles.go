package credentialgcp

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// fullAccessScope is Google's catch-all OAuth2 scope: it grants everything the
	// impersonated service account can do. It used to be the DEFAULT for a role's
	// `scopes`, which made "no opinion about privilege" mean "all of it" on the one
	// axis this plugin can narrow — GCP access tokens carry no other restriction, so
	// the scope list IS the privilege boundary here (A29).
	//
	// It is still perfectly legal to ask for, and it is named rather than inlined so
	// the rejection message below can point at it. What is gone is getting it by
	// saying nothing.
	fullAccessScope = "https://www.googleapis.com/auth/cloud-platform"

	// maxGCPTTL is the absolute ceiling on generateAccessToken's `lifetime`
	// (12h, and only with the credential-lifetime-extension org policy; 1h
	// otherwise). GCP documents NO minimum lifetime — any shorter lifetime is
	// honoured verbatim and the token then expires on its own — so there is no
	// floor to enforce here.
	maxGCPTTL = 43200 * time.Second
)

type gcpRole struct {
	Name                string        `json:"name"`
	DefaultTTL          time.Duration `json:"default_ttl"`
	MaxTTL              time.Duration `json:"max_ttl"`
	ServiceAccountEmail string        `json:"service_account_email"`
	Scopes              []string      `json:"scopes"`
	MinterSet           string        `json:"minter_set"`
	Disabled            bool          `json:"disabled,omitempty"`
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
					Description: "Default token lifetime in seconds (max 3600s by default, up to 43200s with org policy)",
				},
				fieldMaxTTL: {
					Type:        framework.TypeDurationSecond,
					Default:     defaultRoleMaxTTLSeconds,
					Description: "Maximum token lifetime in seconds",
				},
				fieldServiceAccountEmail: {
					Type:        framework.TypeString,
					Description: "Target service account email to impersonate (e.g. my-sa@project.iam.gserviceaccount.com)",
				},
				fieldScopes: {
					Type: framework.TypeCommaStringSlice,
					Description: "OAuth2 scopes for the generated access token (required; " +
						"the scope list is this cloud's only privilege boundary, so there is " +
						"no default)",
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

// validateRoleShape rejects a target service account GCP could not parse and a
// lifetime generateAccessToken could not honour. The ceiling is 43200s (12h, and
// only with the credential-lifetime-extension org policy); GCP documents no
// minimum, so no floor is invented. Returns nil when the role is enforceable.
func validateRoleShape(serviceAccountEmail string, defaultTTL, maxTTL time.Duration) *logical.Response {
	if !strings.Contains(serviceAccountEmail, "@") || !strings.HasSuffix(serviceAccountEmail, ".iam.gserviceaccount.com") {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "service_account_email must be a valid GCP service account email (ending in .iam.gserviceaccount.com)")
	}
	if maxTTL > maxGCPTTL {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "max_ttl must not exceed 43200 seconds (12 hours) per GCP limits")
	}
	if defaultTTL > maxGCPTTL {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "default_ttl must not exceed 43200 seconds (12 hours) per GCP limits")
	}
	return nil
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
	serviceAccountEmail := d.Get(fieldServiceAccountEmail).(string)

	if serviceAccountEmail == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "service_account_email is required"), nil
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

	if errResp := validateRoleShape(serviceAccountEmail, defaultTTL, maxTTL); errResp != nil {
		return errResp, nil
	}

	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      cloudName,
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]interface{}{
			fieldServiceAccountEmail: serviceAccountEmail,
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}

	var scopes []string
	if scopesRaw, ok := d.GetOk(fieldScopes); ok && scopesRaw != nil {
		scopes = scopesRaw.([]string)
	}
	if len(scopes) == 0 {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"scopes is required: an impersonated access token's scope list is the only privilege "+
				"boundary this cloud offers, so a role must state it. Pass %q explicitly to grant "+
				"everything the target service account can do", fullAccessScope), nil
	}

	gcpR := &gcpRole{
		Name:                name,
		DefaultTTL:          defaultTTL,
		MaxTTL:              maxTTL,
		ServiceAccountEmail: serviceAccountEmail,
		Scopes:              scopes,
		MinterSet:           minterSet,
		Disabled:            d.Get(fieldDisabled).(bool),
	}

	// Prove the bound set's minters can actually mint what this role asks for,
	// so an unsuitable minting key is reported to whoever wrote the role rather
	// than to the first caller that reads credentials from it.
	if errResp := b.verifyRoleCapability(ctx, req.Storage, gcpR); errResp != nil {
		return errResp, nil
	}
	entry, err := logical.StorageEntryJSON("roles/"+name, gcpR)
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

	var role gcpRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "parsing a stored entry", err), nil
	}

	return &logical.Response{Data: roleData(&role)}, nil
}

// roleData renders a role for its read endpoint, in the same field names and units the
// write schema accepts. That is what lets a write to an existing role prefill from it
// (cloudconfig.PrefillRoleWrite), so a field cannot be readable and unpatchable.
func roleData(role *gcpRole) map[string]interface{} {
	return map[string]interface{}{
		fieldName:                role.Name,
		fieldDefaultTTL:          int(role.DefaultTTL.Seconds()),
		fieldMaxTTL:              int(role.MaxTTL.Seconds()),
		fieldServiceAccountEmail: role.ServiceAccountEmail,
		fieldScopes:              role.Scopes,
		fieldMinterSet:           role.MinterSet,
		fieldDisabled:            role.Disabled,
	}
}

// storedRoleData renders a STORED role the same way, for a write that is patching one.
func storedRoleData(raw []byte) (map[string]interface{}, error) {
	var role gcpRole
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
