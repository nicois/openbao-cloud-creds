package credentialdo

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
	defaultRoleTTLSeconds    = 900  // 15m
	defaultRoleMaxTTLSeconds = 3600 // 1h
)

type doRole struct {
	Name       string        `json:"name"`
	DefaultTTL time.Duration `json:"default_ttl"`
	MaxTTL     time.Duration `json:"max_ttl"`
	Scopes     []string      `json:"scopes"`
	MinterSet  string        `json:"minter_set"`
	Disabled   bool          `json:"disabled,omitempty"`

	// CredentialType selects which of this cloud's two credential shapes the role
	// issues. Empty means credentialTypeToken: roles written before this field existed
	// must keep issuing what they issued before, so the zero value has to be the old
	// behaviour rather than an error.
	CredentialType string `json:"credential_type,omitempty"`
	// Grants, Region and Endpoint belong to credentialTypeSpacesKey and are empty
	// otherwise. Grants are stored in DigitalOcean's WIRE form (an empty bucket means
	// account-wide); renderGrants converts back for anything a human or client reads.
	Grants   []spacesGrant `json:"grants,omitempty"`
	Region   string        `json:"region,omitempty"`
	Endpoint string        `json:"endpoint,omitempty"`
}

// credentialType returns the role's credential type, defaulting a role stored before the
// field existed to the token shape.
func (r *doRole) credentialType() string {
	if r.CredentialType == "" {
		return credentialTypeToken
	}
	return r.CredentialType
}

// issuesSpacesKey reports whether this role mints an S3-compatible Spaces access key
// rather than a personal access token.
func (r *doRole) issuesSpacesKey() bool {
	return r.credentialType() == credentialTypeSpacesKey
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
					Description: "Default lease TTL",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     defaultRoleMaxTTLSeconds,
					Description: "Maximum lease TTL",
				},
				fieldCredentialType: {
					Type:    framework.TypeString,
					Default: credentialTypeToken,
					Description: "Which credential shape this role issues: " +
						credentialTypeToken + " (a personal access token; see KI-009 — this " +
						"cannot be minted against real DigitalOcean) or " + credentialTypeSpacesKey +
						" (an S3-compatible Spaces access key). Defaults to " + credentialTypeToken,
				},
				fieldScopes: {
					Type: framework.TypeCommaStringSlice,
					Description: "DigitalOcean token scopes, e.g. droplet:create (required for a " +
						credentialTypeToken + " role; they are its privilege boundary, so there is " +
						"no default). Not accepted on a " + credentialTypeSpacesKey + " role",
				},
				fieldGrants: {
					Type: framework.TypeCommaStringSlice,
					Description: "Per-bucket Spaces grants as bucket:permission, e.g. " +
						"backups:read,archive:readwrite (required for a " + credentialTypeSpacesKey +
						" role). Permissions are " + permissionRead + ", " + permissionReadWrite +
						" and " + permissionFullAccess + "; " + permissionFullAccess + " is " +
						"account-wide and must be written as " + grantAllBuckets + grantSeparator +
						permissionFullAccess + " alone. Not accepted on a " + credentialTypeToken +
						" role",
				},
				fieldRegion: {
					Type: framework.TypeString,
					Description: "Spaces region, e.g. nyc3 (required for a " + credentialTypeSpacesKey +
						" role: it is what the endpoint is derived from, and an S3 client cannot be " +
						"constructed without it). Not accepted on a " + credentialTypeToken + " role",
				},
				fieldEndpoint: {
					Type: framework.TypeString,
					Description: "Optional: overrides the S3 endpoint otherwise derived from the " +
						"region. Not accepted on a " + credentialTypeToken + " role",
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
	defaultTTL := time.Duration(d.Get("default_ttl").(int)) * time.Second
	maxTTL := time.Duration(d.Get("max_ttl").(int)) * time.Second
	scopes := d.Get(fieldScopes).([]string)

	typed, errResp := parseCredentialTypeFields(d, scopes)
	if errResp != nil {
		return errResp, nil
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
		CloudConfig: map[string]interface{}{
			fieldScopes: scopes,
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}

	doR := &doRole{
		Name:           name,
		DefaultTTL:     defaultTTL,
		MaxTTL:         maxTTL,
		Scopes:         scopes,
		MinterSet:      minterSet,
		CredentialType: typed.credentialType,
		Grants:         typed.grants,
		Region:         typed.region,
		Endpoint:       typed.endpoint,
	}

	// Prove the bound set's minters can actually mint what this role asks for
	// before persisting it, so an unsuitable pairing is rejected here rather than
	// at the first credential read (see capability.go).
	if errResp := b.verifyRoleCapability(ctx, req.Storage, doR); errResp != nil {
		return errResp, nil
	}

	entry, err := logical.StorageEntryJSON("roles/"+name, doR)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "encoding an entry for storage", err), nil
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "writing to storage", err), nil
	}

	return nil, nil
}

// parseCredentialTypeFields validates the fields that depend on which credential type a
// role issues, and returns them normalised. Exactly one of the two field groups may be
// present.
//
// A field belonging to the OTHER credential type is refused rather than ignored. Silently
// dropping `scopes` from a Spaces role would let an operator believe they had narrowed a
// credential they had not — and the ignored-field failure mode is the one that survives
// review, because the role reads correctly.
func parseCredentialTypeFields(d *framework.FieldData, scopes []string) (credentialTypeFields, *logical.Response) {
	credentialType := d.Get(fieldCredentialType).(string)
	if credentialType == "" {
		credentialType = credentialTypeToken
	}
	grantSpecs := d.Get(fieldGrants).([]string)
	region := d.Get(fieldRegion).(string)
	endpoint := d.Get(fieldEndpoint).(string)

	switch credentialType {
	case credentialTypeToken:
		// DO scopes are the only privilege control this plugin has over a token, so a role
		// with none would issue a token that can do nothing — and "no opinion about
		// privilege" must not quietly mean that either (A28).
		if len(scopes) == 0 {
			return credentialTypeFields{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
				"%s is required for a %s role", fieldScopes, credentialTypeToken)
		}
		for field, set := range map[string]bool{
			fieldGrants:   len(grantSpecs) > 0,
			fieldRegion:   region != "",
			fieldEndpoint: endpoint != "",
		} {
			if set {
				return credentialTypeFields{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
					"%s belongs to a %s role, not a %s one; set %s=%s or drop %s",
					field, credentialTypeSpacesKey, credentialTypeToken,
					fieldCredentialType, credentialTypeSpacesKey, field)
			}
		}
		return credentialTypeFields{credentialType: credentialType}, nil

	case credentialTypeSpacesKey:
		if len(scopes) > 0 {
			return credentialTypeFields{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
				"%s belongs to a %s role, not a %s one; a Spaces key's privilege is its %s",
				fieldScopes, credentialTypeToken, credentialTypeSpacesKey, fieldGrants)
		}
		parsed, err := parseGrants(grantSpecs)
		if err != nil {
			return credentialTypeFields{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error())
		}
		// Without a region there is no endpoint, and without an endpoint the credential
		// cannot be used at all — so an unset region is a broken role, not a default. No
		// region is guessed, for the same reason no TTL floor is invented: a wrong one
		// yields a credential that authenticates and addresses the wrong datacentre.
		if region == "" {
			return credentialTypeFields{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
				"%s is required for a %s role: it is what the S3 endpoint is derived from "+
					"(e.g. nyc3), and a client cannot construct an S3 session without it",
				fieldRegion, credentialTypeSpacesKey)
		}
		if endpoint == "" {
			endpoint = spacesEndpointForRegion(region)
		}
		return credentialTypeFields{
			credentialType: credentialType,
			grants:         parsed,
			region:         region,
			endpoint:       endpoint,
		}, nil

	default:
		return credentialTypeFields{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s %q is not a credential shape this cloud issues; expected %s or %s",
			fieldCredentialType, credentialType, credentialTypeToken, credentialTypeSpacesKey)
	}
}

// credentialTypeFields is what a role write keeps from the type-dependent fields once they are
// validated and normalised: the type itself plus, for a Spaces role, the parsed grants and the
// region/endpoint a client needs. Returned as one value rather than four so that a caller cannot
// pair a credential type with another type's fields.
type credentialTypeFields struct {
	credentialType string
	grants         []spacesGrant
	region         string
	endpoint       string
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

	var role doRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "parsing a stored entry", err), nil
	}

	data := map[string]interface{}{
		fieldName:           role.Name,
		"default_ttl":       int(role.DefaultTTL.Seconds()),
		"max_ttl":           int(role.MaxTTL.Seconds()),
		fieldMinterSet:      role.MinterSet,
		fieldCredentialType: role.credentialType(),
	}
	// Only the fields belonging to this role's credential type are reported. Emitting the
	// other group as empty would suggest they could be set, which the write refuses.
	if role.issuesSpacesKey() {
		data[fieldGrants] = renderGrants(role.Grants)
		data[fieldRegion] = role.Region
		data[fieldEndpoint] = role.Endpoint
	} else {
		data[fieldScopes] = role.Scopes
	}

	return &logical.Response{Data: data}, nil
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
