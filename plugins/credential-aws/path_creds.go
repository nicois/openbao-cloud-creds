package credentialaws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) credsPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("role"),
			Fields: map[string]*framework.FieldSchema{
				fieldRole: {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsRead},
			},
		},
	}
}

func (b *backend) secretAWS() *framework.Secret {
	return &framework.Secret{
		Type:   "aws_sts_credentials",
		Revoke: b.pathCredsRevoke,
		Renew:  b.pathCredsRenew,
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get(fieldRole).(string)

	role, errResp, err := b.loadRole(ctx, req, roleName)
	if err != nil || errResp != nil {
		return errResp, err
	}

	// Select a healthy minter from the role's bound set
	sel, err := b.selectMinter(role.MinterSet)
	if err != nil {
		// selectMinter fails when the set is unloaded or every minter in it is
		// failing — both surface to the client as an upstream auth failure.
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "%s", err.Error()), nil
	}

	now := time.Now()
	output, err := sel.client.AssumeRole(ctx, buildAssumeRoleInput(role, roleName, req.ID))
	if err != nil {
		b.recordMinterError(sel.setID, sel.minterID, classifyAWSError(err), now)
		// We can't reliably classify the upstream failure at this layer, so
		// ErrInternal is the honest, stable code to return.
		return credenvelope.ErrorResponse(credenvelope.ErrInternal, "upstream error: %v", err), nil
	}
	b.recordMinterSuccess(sel.setID, sel.minterID, now)

	if b.accessTracker != nil {
		b.accessTracker.RecordAccess(sel.setID+"/"+sel.minterID, roleName, now)
	}

	emitLeaseIssued(roleName)

	return b.buildCredsResponse(ctx, req, credsResponseArgs{
		role:     role,
		roleName: roleName,
		sel:      sel,
		output:   output,
		now:      now,
	}), nil
}

// credsResponseArgs bundles the inputs to buildCredsResponse so it stays under
// the argument-limit lint cap.
type credsResponseArgs struct {
	role     *awsRole
	roleName string
	sel      selectedMinter
	output   *sts.AssumeRoleOutput
	now      time.Time
}

// buildAssumeRoleInput assembles the STS AssumeRoleInput for a role, including
// the truncated session name, optional session tags, and optional external ID.
func buildAssumeRoleInput(role *awsRole, roleName, reqID string) *sts.AssumeRoleInput {
	sessionName := fmt.Sprintf("cloud-creds-%s-%s", roleName, reqID)
	// AWS session name max 64 chars, alphanumeric + =,.@-_
	if len(sessionName) > maxSessionNameLen {
		sessionName = sessionName[:maxSessionNameLen]
	}

	durationSeconds := int32(role.DefaultTTL.Seconds())
	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(role.IAMRoleARN),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: &durationSeconds,
	}

	// Add session tags for safety boundary
	if len(role.SessionTags) > 0 {
		tags := make([]ststypes.Tag, 0, len(role.SessionTags))
		for k, v := range role.SessionTags {
			tags = append(tags, ststypes.Tag{
				Key:   aws.String(k),
				Value: aws.String(v),
			})
		}
		input.Tags = tags
	}

	// Add external ID for cross-account assume
	if role.ExternalID != "" {
		input.ExternalId = aws.String(role.ExternalID)
	}

	return input
}

// buildCredsResponse builds the envelope, persists the active-credential
// tracking entry, and returns the lease response for a successful AssumeRole.
func (b *backend) buildCredsResponse(ctx context.Context, req *logical.Request, args credsResponseArgs) *logical.Response {
	output := args.output
	// STS credentials have a fixed expiration set by AWS
	expiresAt := *output.Credentials.Expiration
	ttlSeconds := int(time.Until(expiresAt).Seconds())

	accessKeyID := aws.ToString(output.Credentials.AccessKeyId)

	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: cloudName,
		Role:  args.roleName,
		Credential: map[string]interface{}{
			"access_key_id":     accessKeyID,
			"secret_access_key": aws.ToString(output.Credentials.SecretAccessKey),
			"session_token":     aws.ToString(output.Credentials.SessionToken),
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   ttlSeconds,
		Renewable:    false,
		CredentialID: accessKeyID,
		Scope:        args.role.IAMRoleARN,
		IssuedBy:     "cloud-creds-aws/v0.1",
		MinterSet:    args.sel.setID,
		MinterID:     args.sel.minterID,
	})

	// Track active credential for metrics (no upstream entity to clean up)
	activeEntry, _ := logical.StorageEntryJSON("active-tokens/"+accessKeyID, map[string]interface{}{
		fieldRole:    args.roleName,
		"minter":     args.sel.minterID,
		"created":    args.now.UTC().Format(time.RFC3339),
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
	if activeEntry != nil {
		if err := req.Storage.Put(ctx, activeEntry); err != nil {
			b.Logger().Warn("failed to track active credential", "access_key_id", accessKeyID, "error", err)
		}
	}

	resp := b.Secret("aws_sts_credentials").Response(env.ToMap(), map[string]interface{}{
		"access_key_id": accessKeyID,
		fieldRole:       args.roleName,
		fieldMinterSet:  args.sel.setID,
		"minter_id":     args.sel.minterID,
	})
	resp.Secret.TTL = args.role.DefaultTTL
	resp.Secret.MaxTTL = args.role.MaxTTL

	return resp
}

// loadRole fetches and validates a role for issuance. It returns either the
// parsed role, or an *logical.Response describing why issuance can't proceed
// (role missing/disabled), or a hard error. Exactly one of role/errResp is
// non-nil when err is nil.
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*awsRole, *logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, nil, err
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName), nil
	}
	var role awsRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, nil, err
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName), nil
	}
	return &role, nil, nil
}

// pathCredsRevoke is a no-op for AWS STS credentials — they expire naturally.
// We just remove the tracking entry. Unlike the JIT clouds (e.g. DigitalOcean),
// there is no upstream entity to delete, so we do NOT resolve the minter that
// issued this credential; minter_set is read only for log context.
func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	accessKeyID, _ := req.Secret.InternalData["access_key_id"].(string)
	minterSet, _ := req.Secret.InternalData[fieldMinterSet].(string)
	if accessKeyID != "" {
		if err := req.Storage.Delete(ctx, "active-tokens/"+accessKeyID); err != nil {
			b.Logger().Warn("failed to remove active credential tracking",
				"access_key_id", accessKeyID, "minter_set", minterSet, "error", err)
		}
	}
	// STS credentials cannot be revoked — they expire at the time AWS set.
	// This is strictly better from a security perspective (no revocation gap).
	return nil, nil
}

// pathCredsRenew returns an error — STS credentials cannot be renewed.
func (b *backend) pathCredsRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return logical.ErrorResponse("aws STS credentials cannot be renewed; issue a new credential instead"), nil
}

// selectedMinter bundles the result of selectMinter: the set and minter that
// were chosen plus a ready-to-use STS client for them. The client is built via
// b.buildSTSClient, which honors the injected stsClientFn factory when set.
type selectedMinter struct {
	setID    string
	minterID string
	client   STSClient
}

func (b *backend) selectMinter(setName string) (selectedMinter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return selectedMinter{}, fmt.Errorf("upstream_auth_failed: minter set %q not loaded", setName)
	}
	for id, ms := range states {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			return selectedMinter{setID: setName, minterID: id, client: b.buildSTSClient(ms.minter)}, nil
		}
	}
	return selectedMinter{}, fmt.Errorf("upstream_auth_failed: all minters in set %q are failing", setName)
}

// buildSTSClient creates an STS client from a minter. The token field stores
// "access_key_id:secret_access_key". Callers MUST hold b.mu (read or write);
// it reads b.region/b.stsEndpoint without locking of its own.
func (b *backend) buildSTSClient(m cloudconfig.Minter) STSClient {
	parts := strings.SplitN(m.Token, ":", 2)
	accessKeyID := parts[0]
	secretAccessKey := ""
	if len(parts) > 1 {
		secretAccessKey = parts[1]
	}

	region := b.region
	if region == "" {
		region = defaultRegion
	}

	if b.stsClientFn != nil {
		return b.stsClientFn(accessKeyID, secretAccessKey, region, b.stsEndpoint)
	}
	return newRealSTSClient(accessKeyID, secretAccessKey, region, b.stsEndpoint)
}

func (b *backend) recordMinterSuccess(setName, id string, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			ms.sm.RecordSuccess(at)
		}
	}
}

func (b *backend) recordMinterError(setName, id string, httpStatus int, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			ms.sm.RecordError(httpStatus, at)
		}
	}
}

// classifyAWSError maps AWS SDK errors to HTTP status codes for state machine.
func classifyAWSError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "AccessDenied") || strings.Contains(errMsg, "403") {
		return http.StatusForbidden
	}
	if strings.Contains(errMsg, "ExpiredToken") || strings.Contains(errMsg, "InvalidClientTokenId") || strings.Contains(errMsg, "401") {
		return http.StatusUnauthorized
	}
	if strings.Contains(errMsg, "Throttling") || strings.Contains(errMsg, "429") {
		return http.StatusTooManyRequests
	}
	return http.StatusInternalServerError
}
