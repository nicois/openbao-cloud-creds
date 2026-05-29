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
)

type gcpRole struct {
	Name                string   `json:"name"`
	DefaultTTL          time.Duration `json:"default_ttl"`
	MaxTTL              time.Duration `json:"max_ttl"`
	ServiceAccountEmail string   `json:"service_account_email"`
	Scopes              []string `json:"scopes"`
	Disabled            bool     `json:"disabled,omitempty"`
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
					Description: "Default token lifetime in seconds (max 3600s by default, up to 43200s with org policy)",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     3600,
					Description: "Maximum token lifetime in seconds",
				},
				"service_account_email": {
					Type:        framework.TypeString,
					Description: "Target service account email to impersonate (e.g. my-sa@project.iam.gserviceaccount.com)",
				},
				"scopes": {
					Type:        framework.TypeCommaStringSlice,
					Default:     []string{defaultScope},
					Description: "OAuth2 scopes for the generated access token",
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
	serviceAccountEmail := d.Get("service_account_email").(string)

	if serviceAccountEmail == "" {
		return logical.ErrorResponse("service_account_email is required"), nil
	}

	// Validate service account email format
	if !strings.Contains(serviceAccountEmail, "@") || !strings.HasSuffix(serviceAccountEmail, ".iam.gserviceaccount.com") {
		return logical.ErrorResponse("service_account_email must be a valid GCP service account email (ending in .iam.gserviceaccount.com)"), nil
	}

	// GCP access tokens have a maximum lifetime of 3600s by default,
	// or up to 43200s (12h) with the org policy constraint
	// constraints/iam.allowServiceAccountCredentialLifetimeExtension
	if maxTTL > 43200*time.Second {
		return logical.ErrorResponse("max_ttl must not exceed 43200 seconds (12 hours) per GCP limits"), nil
	}

	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      "gcp",
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]interface{}{
			"service_account_email": serviceAccountEmail,
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	var scopes []string
	if scopesRaw, ok := d.GetOk("scopes"); ok && scopesRaw != nil {
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
	name := d.Get("name").(string)
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
		"name":                  role.Name,
		"default_ttl":          int(role.DefaultTTL.Seconds()),
		"max_ttl":              int(role.MaxTTL.Seconds()),
		"service_account_email": role.ServiceAccountEmail,
		"scopes":               role.Scopes,
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
