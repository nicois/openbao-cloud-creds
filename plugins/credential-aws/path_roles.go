package credentialaws

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/requester"
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
	// PolicyARNs and InlinePolicy narrow the session below the target role's own
	// permissions, using STS session policies. Both were specified in techrfc.md
	// and design.md and did not exist, so every issued credential carried the
	// target role's ENTIRE permission set and privilege separation could only be
	// done by creating one IAM role per level upstream (A22 in
	// docs/audit-2026-08-22.md).
	PolicyARNs   []string `json:"policy_arns,omitempty"`
	InlinePolicy string   `json:"inline_policy,omitempty"`
	MinterSet    string   `json:"minter_set"`
	Disabled     bool     `json:"disabled,omitempty"`
	// RequireCallerIdentity is how much of a caller's identity this role insists on
	// before it will issue. Empty means none, so a role written before the field
	// existed keeps issuing exactly as it did.
	RequireCallerIdentity string `json:"require_caller_identity,omitempty"`
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
				fieldPolicyARNs: {
					Type: framework.TypeCommaStringSlice,
					Description: "Managed policy ARNs used as STS session policies, narrowing the " +
						"session to the intersection of the target role's permissions and these",
				},
				fieldInlinePolicy: {
					Type: framework.TypeString,
					Description: "Inline JSON session policy, narrowing the session to the " +
						"intersection of the target role's permissions and this document",
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

// validateSTSTTLs rejects role TTLs STS could not honour: AssumeRole documents
// DurationSeconds as 900–43200, and an STS session cannot be revoked early, so a
// TTL outside that range could not be made honest by any other means. Returns nil
// when both TTLs are enforceable.
func validateSTSTTLs(defaultTTL, maxTTL time.Duration) *logical.Response {
	if defaultTTL < minSTSTTL {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "default_ttl must be at least 900 seconds (15 minutes) per AWS STS limits")
	}
	if maxTTL < minSTSTTL {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "max_ttl must be at least 900 seconds (15 minutes) per AWS STS limits")
	}
	if maxTTL > maxSTSTTL {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "max_ttl must not exceed 43200 seconds (12 hours) per AWS STS limits")
	}
	if defaultTTL > maxSTSTTL {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "default_ttl must not exceed 43200 seconds (12 hours) per AWS STS limits")
	}
	return nil
}

// optionalRoleFields reads the two role fields that are absent-or-set rather than
// empty-or-set: the session-tag map and the external id. GetOk distinguishes the two,
// which is what keeps a field the operator never mentioned out of the stored role — and
// out of the AssumeRole call, where an empty external id is not the same as none.
func optionalRoleFields(d *framework.FieldData) (sessionTags map[string]string, externalID string) {
	if tagsRaw, ok := d.GetOk("session_tags"); ok && tagsRaw != nil {
		sessionTags = tagsRaw.(map[string]string)
	}
	if eid, ok := d.GetOk("external_id"); ok {
		externalID = eid.(string)
	}
	return sessionTags, externalID
}

// requireExistingMinterSet resolves the set a role binds to, refusing an absent name and one that
// does not exist. Extracted from pathRoleWrite so that function stays inside the length limit; the
// check belongs at role write because a role naming a set that is not there can never issue.
func (b *backend) requireExistingMinterSet(ctx context.Context, storage logical.Storage,
	d *framework.FieldData,
) (string, *logical.Response) {
	minterSet := d.Get(fieldMinterSet).(string)
	if minterSet == "" {
		return "", credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_set is required")
	}
	exists, err := b.minterSetExists(ctx, storage, minterSet)
	if err != nil {
		return "", credenvelope.InternalResponse(b.Logger().Warn, "a storage operation", err)
	}
	if !exists {
		return "", credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"minter_set %q does not exist", minterSet)
	}
	return minterSet, nil
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
	iamRoleARN := d.Get(fieldIAMRoleARN).(string)

	if iamRoleARN == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "iam_role_arn is required"), nil
	}

	minterSet, errResp := b.requireExistingMinterSet(ctx, req.Storage, d)
	if errResp != nil {
		return errResp, nil
	}

	if errResp := validateSTSTTLs(defaultTTL, maxTTL); errResp != nil {
		return errResp, nil
	}

	policyARNs := d.Get(fieldPolicyARNs).([]string)
	inlinePolicy := d.Get(fieldInlinePolicy).(string)
	if errResp := validateSessionPolicies(policyARNs, inlinePolicy); errResp != nil {
		return errResp, nil
	}

	// Refused here rather than at issuance: an operator who mistypes the requirement finds
	// out when they write the role, not when the first caller is unexpectedly let through.
	requireCallerIdentity := d.Get(fieldRequireCallerIdentity).(string)
	if _, err := requester.ParseRequirement(requireCallerIdentity); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}

	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      cloudName,
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]any{
			fieldIAMRoleARN: iamRoleARN,
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}

	sessionTags, externalID := optionalRoleFields(d)

	awsR := &awsRole{
		Name:        name,
		DefaultTTL:  defaultTTL,
		MaxTTL:      maxTTL,
		IAMRoleARN:  iamRoleARN,
		SessionTags: sessionTags,
		ExternalID:  externalID,
		MinterSet:   minterSet,
		Disabled:    d.Get(fieldDisabled).(bool),

		PolicyARNs:   policyARNs,
		InlinePolicy: inlinePolicy,

		RequireCallerIdentity: requireCallerIdentity,
	}

	// Prove the bound set's minters can actually mint what this role asks for,
	// so an unsuitable minting key is reported to whoever wrote the role rather
	// than to the first caller that reads credentials from it.
	if errResp := b.verifyRoleCapability(ctx, req.Storage, awsR); errResp != nil {
		return errResp, nil
	}
	entry, err := logical.StorageEntryJSON("roles/"+name, awsR)
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

	var role awsRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "parsing a stored entry", err), nil
	}

	return &logical.Response{Data: roleData(&role)}, nil
}

// roleData renders a role for its read endpoint, in the same field names and units the
// write schema accepts. That is what lets a write to an existing role prefill from it
// (cloudconfig.PrefillRoleWrite), so a field cannot be readable and unpatchable.
func roleData(role *awsRole) map[string]any {
	data := map[string]any{
		fieldName:                  role.Name,
		fieldDefaultTTL:            int(role.DefaultTTL.Seconds()),
		fieldMaxTTL:                int(role.MaxTTL.Seconds()),
		fieldIAMRoleARN:            role.IAMRoleARN,
		fieldMinterSet:             role.MinterSet,
		fieldDisabled:              role.Disabled,
		fieldRequireCallerIdentity: role.RequireCallerIdentity,
	}
	// An unset optional field is omitted rather than reported empty, so a role that
	// never had one is not prefilled with one either.
	if role.SessionTags != nil {
		data["session_tags"] = role.SessionTags
	}
	if len(role.PolicyARNs) > 0 {
		data[fieldPolicyARNs] = role.PolicyARNs
	}
	if role.InlinePolicy != "" {
		data[fieldInlinePolicy] = role.InlinePolicy
	}
	if role.ExternalID != "" {
		data["external_id"] = role.ExternalID
	}
	return data
}

// storedRoleData renders a STORED role the same way, for a write that is patching one.
func storedRoleData(raw []byte) (map[string]any, error) {
	var role awsRole
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

// validateSessionPolicies checks the narrowing fields at role write, where the
// operator finds out, rather than at the first credential read.
//
// STS caps session policies at 10 managed ARNs, and an inline policy must be JSON —
// AWS rejects both cases at AssumeRole, which would otherwise surface as an
// upstream_request_invalid to an unrelated caller much later.
func validateSessionPolicies(policyARNs []string, inlinePolicy string) *logical.Response {
	if len(policyARNs) > maxSessionPolicyARNs {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s accepts at most %d managed policy ARNs (STS limit), got %d",
			fieldPolicyARNs, maxSessionPolicyARNs, len(policyARNs))
	}
	for _, arn := range policyARNs {
		if !strings.HasPrefix(arn, "arn:") {
			return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
				"%s entry %q is not an ARN", fieldPolicyARNs, arn)
		}
	}
	if inlinePolicy != "" && !json.Valid([]byte(inlinePolicy)) {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s must be a JSON policy document", fieldInlinePolicy)
	}
	return nil
}
