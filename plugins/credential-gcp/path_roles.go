package credentialgcp

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	defaultScope = "https://www.googleapis.com/auth/cloud-platform"

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
					Default:     defaultRoleTTLSeconds,
					Description: "Maximum token lifetime in seconds",
				},
				fieldServiceAccountEmail: {
					Type:        framework.TypeString,
					Description: "Target service account email to impersonate (e.g. my-sa@project.iam.gserviceaccount.com)",
				},
				fieldScopes: {
					Type:        framework.TypeCommaStringSlice,
					Default:     []string{defaultScope},
					Description: "OAuth2 scopes for the generated access token",
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

// validateRoleShape rejects a target service account GCP could not parse and a
// lifetime generateAccessToken could not honour. The ceiling is 43200s (12h, and
// only with the credential-lifetime-extension org policy); GCP documents no
// minimum, so no floor is invented. Returns nil when the role is enforceable.
func validateRoleShape(serviceAccountEmail string, defaultTTL, maxTTL time.Duration) *logical.Response {
	if !strings.Contains(serviceAccountEmail, "@") || !strings.HasSuffix(serviceAccountEmail, ".iam.gserviceaccount.com") {
		return logical.ErrorResponse("service_account_email must be a valid GCP service account email (ending in .iam.gserviceaccount.com)")
	}
	if maxTTL > maxGCPTTL {
		return logical.ErrorResponse("max_ttl must not exceed 43200 seconds (12 hours) per GCP limits")
	}
	if defaultTTL > maxGCPTTL {
		return logical.ErrorResponse("default_ttl must not exceed 43200 seconds (12 hours) per GCP limits")
	}
	return nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	defaultTTL := time.Duration(d.Get(fieldDefaultTTL).(int)) * time.Second
	maxTTL := time.Duration(d.Get(fieldMaxTTL).(int)) * time.Second
	serviceAccountEmail := d.Get(fieldServiceAccountEmail).(string)

	if serviceAccountEmail == "" {
		return logical.ErrorResponse("service_account_email is required"), nil
	}

	minterSet := d.Get(fieldMinterSet).(string)
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
		return logical.ErrorResponse(err.Error()), nil
	}

	var scopes []string
	if scopesRaw, ok := d.GetOk(fieldScopes); ok && scopesRaw != nil {
		scopes = scopesRaw.([]string)
	}
	if len(scopes) == 0 {
		scopes = []string{defaultScope}
	}

	gcpR := &gcpRole{
		Name:                name,
		DefaultTTL:          defaultTTL,
		MaxTTL:              maxTTL,
		ServiceAccountEmail: serviceAccountEmail,
		Scopes:              scopes,
		MinterSet:           minterSet,
	}

	// Prove the bound set's minters can actually mint what this role asks for,
	// so an unsuitable minting key is reported to whoever wrote the role rather
	// than to the first caller that reads credentials from it.
	if errResp := b.verifyRoleCapability(ctx, req.Storage, gcpR); errResp != nil {
		return errResp, nil
	}
	entry, err := logical.StorageEntryJSON("roles/"+name, gcpR)
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

	var role gcpRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		fieldName:                role.Name,
		fieldDefaultTTL:          int(role.DefaultTTL.Seconds()),
		fieldMaxTTL:              int(role.MaxTTL.Seconds()),
		fieldServiceAccountEmail: role.ServiceAccountEmail,
		fieldScopes:              role.Scopes,
		fieldMinterSet:           role.MinterSet,
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
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
