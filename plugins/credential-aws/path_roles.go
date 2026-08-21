package credentialaws

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// Schema defaults are expressed in seconds (framework.TypeDurationSecond).
	defaultRoleTTLSeconds    = 900  // 15m
	defaultRoleMaxTTLSeconds = 3600 // 1h

	// STS DurationSeconds is documented as "Minimum value of 900. Maximum value
	// of 43200"; a role TTL outside that range would be rejected by AssumeRole at
	// mint time, so it is rejected at role-write time instead. STS sessions expire
	// on their own and cannot be revoked, so a TTL below the floor could not be
	// compensated for by early revocation either.
	minSTSTTL = 900 * time.Second
	maxSTSTTL = 43200 * time.Second
)

type awsRole struct {
	Name        string            `json:"name"`
	DefaultTTL  time.Duration     `json:"default_ttl"`
	MaxTTL      time.Duration     `json:"max_ttl"`
	IAMRoleARN  string            `json:"iam_role_arn"`
	SessionTags map[string]string `json:"session_tags,omitempty"`
	ExternalID  string            `json:"external_id,omitempty"`
	MinterSet   string            `json:"minter_set"`
	Disabled    bool              `json:"disabled,omitempty"`
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
					Description: "Default STS session duration (min 900s/15m, max 43200s/12h)",
				},
				fieldMaxTTL: {
					Type:        framework.TypeDurationSecond,
					Default:     defaultRoleMaxTTLSeconds,
					Description: "Maximum STS session duration",
				},
				fieldIAMRoleARN: {
					Type:        framework.TypeString,
					Description: "IAM role ARN to assume via STS",
				},
				"session_tags": {
					Type:        framework.TypeKVPairs,
					Description: "Session tags applied to every AssumeRole call",
				},
				"external_id": {
					Type:        framework.TypeString,
					Description: "External ID for cross-account assume role",
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

// validateSTSTTLs rejects role TTLs STS could not honour: AssumeRole documents
// DurationSeconds as 900–43200, and an STS session cannot be revoked early, so a
// TTL outside that range could not be made honest by any other means. Returns nil
// when both TTLs are enforceable.
func validateSTSTTLs(defaultTTL, maxTTL time.Duration) *logical.Response {
	if defaultTTL < minSTSTTL {
		return logical.ErrorResponse("default_ttl must be at least 900 seconds (15 minutes) per AWS STS limits")
	}
	if maxTTL < minSTSTTL {
		return logical.ErrorResponse("max_ttl must be at least 900 seconds (15 minutes) per AWS STS limits")
	}
	if maxTTL > maxSTSTTL {
		return logical.ErrorResponse("max_ttl must not exceed 43200 seconds (12 hours) per AWS STS limits")
	}
	if defaultTTL > maxSTSTTL {
		return logical.ErrorResponse("default_ttl must not exceed 43200 seconds (12 hours) per AWS STS limits")
	}
	return nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	defaultTTL := time.Duration(d.Get(fieldDefaultTTL).(int)) * time.Second
	maxTTL := time.Duration(d.Get(fieldMaxTTL).(int)) * time.Second
	iamRoleARN := d.Get(fieldIAMRoleARN).(string)

	if iamRoleARN == "" {
		return logical.ErrorResponse("iam_role_arn is required"), nil
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

	if errResp := validateSTSTTLs(defaultTTL, maxTTL); errResp != nil {
		return errResp, nil
	}

	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      cloudName,
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]interface{}{
			fieldIAMRoleARN: iamRoleARN,
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	var sessionTags map[string]string
	if tagsRaw, ok := d.GetOk("session_tags"); ok && tagsRaw != nil {
		sessionTags = tagsRaw.(map[string]string)
	}

	var externalID string
	if eid, ok := d.GetOk("external_id"); ok {
		externalID = eid.(string)
	}

	awsR := &awsRole{
		Name:        name,
		DefaultTTL:  defaultTTL,
		MaxTTL:      maxTTL,
		IAMRoleARN:  iamRoleARN,
		SessionTags: sessionTags,
		ExternalID:  externalID,
		MinterSet:   minterSet,
	}

	// Prove the bound set's minters can actually mint what this role asks for,
	// so an unsuitable minting key is reported to whoever wrote the role rather
	// than to the first caller that reads credentials from it.
	if errResp := b.verifyRoleCapability(ctx, req.Storage, awsR); errResp != nil {
		return errResp, nil
	}
	entry, err := logical.StorageEntryJSON("roles/"+name, awsR)
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

	var role awsRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		fieldName:       role.Name,
		fieldDefaultTTL: int(role.DefaultTTL.Seconds()),
		fieldMaxTTL:     int(role.MaxTTL.Seconds()),
		fieldIAMRoleARN: role.IAMRoleARN,
		fieldMinterSet:  role.MinterSet,
	}
	if role.SessionTags != nil {
		data["session_tags"] = role.SessionTags
	}
	if role.ExternalID != "" {
		data["external_id"] = role.ExternalID
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
