package credentialaws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/nicois/openbao-cloud-creds/pkg/telemetry"
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
		// No Renew callback, deliberately: framework.Secret.Renewable() is (Renew
		// != nil) and that is the flag the LEASE carries, so a callback that only
		// ever returns an error would still advertise renewable=true — and OpenBao
		// REVOKES a lease whose renewal fails, destroying the credential the
		// client was trying to keep. An STS credential expires at the
		// DurationSeconds fixed at mint and there is no extend call, so the lease
		// is non-renewable and core refuses renewal before the plugin is reached
		// (docs/ttl-semantics.md).
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get(fieldRole).(string)

	role, errResp := b.loadRole(ctx, req, roleName)
	if errResp != nil {
		return errResp, nil
	}

	now := time.Now()

	// Select a healthy minter from the role's bound set
	sel, err := b.selectMinter(role.MinterSet, now)
	if err != nil {
		// The error carries its own code: an unloaded set is config_invalid, a
		// rate-limited set is upstream_quota_exceeded (with the remaining wait),
		// and only genuinely failing credentials are upstream_auth_failed.
		return credenvelope.ResponseFor(err), nil
	}

	instanceID, err := b.ownerInstanceID(ctx, req.Storage)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err), nil
	}

	output, err := sel.client.AssumeRole(ctx,
		buildAssumeRoleInput(ownertag.Prefix(instanceID), role, roleName, req.ID))
	if err != nil {
		status := classifyAWSError(err)
		b.recordMinterError(sel.setID, sel.minterID, status, err, now)
		return b.issuanceError(status, err, telemetry.IssuanceAttempt{
			Cloud: cloudName, Role: roleName, MinterSet: sel.setID, MinterID: sel.minterID,
			RequestID: req.ID,
		}), nil
	}
	b.recordMinterSuccess(sel.setID, sel.minterID, now)

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

// sessionNameFor builds the RoleSessionName for one issuance: this mount's owner
// prefix, the role, and enough of the request id to tell one lease's session from
// the next in CloudTrail.
//
// It used to be `prefix + role + "-" + reqID` truncated from the right at 64. With
// the instance id in the prefix (A19) that overflows for EVERY role name, so the
// request id was always partially cut and, from about 34 characters of role name,
// gone entirely — every lease of that role sharing one session name, which is the
// one thing a session name exists to prevent (A29).
func sessionNameFor(ownerPrefix, roleName, reqID string) string {
	role := sanitiseSessionName(roleName)
	id := sanitiseSessionName(reqID)
	// Shorten the request id BEFORE fitting. A whole UUID plus the owner prefix is
	// already over AWS's cap by itself, so leaving it at full length would make
	// FitName drop the role name from every session name we emit.
	if len(ownerPrefix)+len(role)+1+len(id) > maxSessionNameLen && len(id) > sessionRequestIDKeepLen {
		id = id[:sessionRequestIDKeepLen]
	}
	return ownertag.FitName(ownerPrefix, role, id, maxSessionNameLen)
}

// sanitiseSessionName maps anything outside AWS's session-name character class to
// a hyphen. AWS rejects the whole AssumeRole on an illegal character, so a role
// name a cloud-agnostic API accepted must not be able to fail issuance here.
func sanitiseSessionName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case strings.ContainsRune(sessionNameExtraChars, r):
			return r
		default:
			return '-'
		}
	}, s)
}

// buildAssumeRoleInput assembles the STS AssumeRoleInput for a role, including
// the fitted session name, optional session tags, and optional external ID.
func buildAssumeRoleInput(ownerPrefix string, role *awsRole, roleName, reqID string) *sts.AssumeRoleInput {
	// The session name is this cloud's owner tag: it is what CloudTrail shows and what
	// distinguishes this mount's sessions from another mount's (A19), and the request
	// id is what distinguishes one lease from the next.
	sessionName := sessionNameFor(ownerPrefix, roleName, reqID)

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

	// Session policies narrow the session to the INTERSECTION of the target role's
	// permissions and these — they can only ever reduce privilege, never grant it.
	// Without them every issued credential carried the target role's entire
	// permission set, so privilege separation required one IAM role per level
	// upstream while the published contract promised narrowing (A22).
	for _, policyARN := range role.PolicyARNs {
		input.PolicyArns = append(input.PolicyArns, ststypes.PolicyDescriptorType{
			Arn: aws.String(policyARN),
		})
	}
	if role.InlinePolicy != "" {
		input.Policy = aws.String(role.InlinePolicy)
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
			// Tracking is metrics-only here: STS credentials auto-expire and the
			// reconciler never deletes an upstream entity, so an untracked
			// credential is harmless (it self-expires). We keep the issued
			// credential and only lose a metrics datapoint (audit F6: N/A for
			// no-revoke plugins).
			b.Logger().Warn("failed to track active credential (metrics-only; STS cred self-expires)",
				"access_key_id", accessKeyID, "error", err)
		}
	}

	resp := b.Secret("aws_sts_credentials").Response(env.ToMap(), map[string]interface{}{
		"access_key_id": accessKeyID,
		fieldRole:       args.roleName,
		fieldMinterSet:  args.sel.setID,
		"minter_id":     args.sel.minterID,
	})
	// The lease is derived from the expiry AWS actually returned — the same one
	// the envelope publishes — not from the role's TTL. STS may grant slightly
	// less than DurationSeconds requested, and the round trip itself consumes
	// wall-clock, so a lease built from the role TTL can outlive the credential
	// it names (techrfc OBC-002).
	resp.Secret.TTL = leaseTTL(ttlSeconds)
	resp.Secret.MaxTTL = args.role.MaxTTL

	return resp
}

// minLeaseTTL is the floor for a lease derived from an upstream expiry: a zero
// TTL means "use the mount default" to core, which is never what a near-expiry
// credential wants.
const minLeaseTTL = time.Second

// leaseTTL converts the credential's remaining lifetime in seconds into the
// lease duration. A non-positive value would make core fall back to the mount's
// default lease, which could far outlive an already-expiring credential, so it
// is floored at minLeaseTTL instead.
func leaseTTL(remainingSeconds int) time.Duration {
	if remainingSeconds < 1 {
		return minLeaseTTL
	}
	return time.Duration(remainingSeconds) * time.Second
}

// loadRole fetches and validates a role for issuance. It returns either the
// parsed role, or an *logical.Response describing why issuance can't proceed
// (role missing/disabled), or a hard error. Exactly one of role/errResp is
// non-nil when err is nil.
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*awsRole, *logical.Response) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "loading the role", err)
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName)
	}
	var role awsRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "parsing the stored role", err)
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName)
	}
	return &role, nil
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

// selectedMinter bundles the result of selectMinter: the set and minter that
// were chosen plus a ready-to-use STS client for them. The client is built via
// b.buildSTSClient, which honors the injected stsClientFn factory when set.
type selectedMinter struct {
	setID    string
	minterID string
	client   STSClient
}

func (b *backend) selectMinter(setName string, now time.Time) (selectedMinter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	states, ok := b.minterSets[setName]
	if !ok {
		return selectedMinter{}, credenvelope.NewError(credenvelope.ErrConfigInvalid,
			http.StatusBadRequest, fmt.Sprintf("minter set %q is not loaded", setName))
	}
	for id, ms := range states {
		if !ms.minter.Retired && ms.sm.TryAcquire(now) {
			return selectedMinter{setID: setName, minterID: id, client: b.buildSTSClient(ms.minter)}, nil
		}
	}
	return selectedMinter{}, recovery.UnavailableError(setName, machinesOf(states), now)
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

// buildIAMMinterClient creates an IAM key-management client from a minter's
// access_key_id:secret_access_key token, honoring the injected
// iamMinterClientFn factory when set (tests inject a fake). Callers MUST hold
// b.mu (read or write); it reads b.region without locking of its own. This is
// the KEY-MANAGEMENT client used by rotation, NOT the STS issuance client.
func (b *backend) buildIAMMinterClient(m cloudconfig.Minter) IAMMinterClient {
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

	if b.iamMinterClientFn != nil {
		return b.iamMinterClientFn(accessKeyID, secretAccessKey, region)
	}
	return newRealIAMMinterClient(accessKeyID, secretAccessKey, region)
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

func (b *backend) recordMinterError(setName, id string, httpStatus int, err error, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			ms.sm.RecordUpstream(httpStatus, err, at)
		}
	}
}

// issuanceError logs the raw upstream failure (operator-only) and returns a
// classified, body-free error response for the client (audit2 #4,#5).
func (b *backend) issuanceError(httpStatus int, err error, attempt telemetry.IssuanceAttempt) *logical.Response {
	b.Logger().Warn("upstream credential issuance failed", attempt.LogFields(httpStatus, err)...)
	return credenvelope.ErrorResponse(credenvelope.Classify(httpStatus, err),
		"upstream credential issuance failed")
}

// awsErrorCodes maps AWS's own error codes to the HTTP status they represent.
// Keyed on the code the SDK reports, never on a substring of the message: the
// message carries request-ID hex, ARNs and 12-digit account numbers, so matching
// "403" inside it classified `StatusCode: 500, RequestID: 4038e1a2...` as an
// authorization failure and indicted a healthy minter during a cloud outage (A16
// in docs/audit-2026-08-22.md).
var awsErrorCodes = map[string]int{
	"AccessDenied":          http.StatusForbidden,
	"AccessDeniedException": http.StatusForbidden,
	"UnauthorizedOperation": http.StatusForbidden,
	"ExpiredToken":          http.StatusUnauthorized,
	"InvalidClientTokenId":  http.StatusUnauthorized,
	"Throttling":            http.StatusTooManyRequests,
	"ThrottlingException":   http.StatusTooManyRequests,
	// LimitExceeded is how IAM reports the 2-access-keys-per-user cap: a quota,
	// not a bug, and rotation depends on telling them apart.
	"LimitExceeded":          http.StatusTooManyRequests,
	"LimitExceededException": http.StatusTooManyRequests,
	// AWS labels these <Type>Sender</Type>: the request is wrong and an identical
	// retry cannot succeed. KI-010 — also how a target role's MaxSessionDuration
	// being below the role TTL surfaces.
	"ValidationError":       http.StatusBadRequest,
	"InvalidParameterValue": http.StatusBadRequest,
}

// classifyAWSError maps an AWS SDK error to the HTTP status it represents, or
// credenvelope.StatusNone when nothing recognises it — in which case
// credenvelope.Classify inspects the error itself, which is the only way a
// client-side timeout can be told apart from a defect in this plugin.
//
// The status is taken from the transport error where the SDK provides one, so a
// 500 is a 500 whatever its message happens to contain.
func classifyAWSError(err error) int {
	if err == nil {
		return http.StatusOK
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if status, ok := awsErrorCodes[apiErr.ErrorCode()]; ok {
			return status
		}
	}

	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() > 0 {
		return respErr.HTTPStatusCode()
	}

	// The SDK also renders the status into the message as "StatusCode: nnn" — its
	// own delimited marker, unlike a bare digit that could sit inside a request id.
	if m := statusCodeInError.FindStringSubmatch(err.Error()); m != nil {
		if status, convErr := strconv.Atoi(m[1]); convErr == nil && status > 0 {
			return status
		}
	}

	// The fakes and unit tests raise plain errors carrying AWS's code text; match
	// the code as a whole word rather than as a loose substring.
	for code, status := range awsErrorCodes {
		if awsCodeWord(code).MatchString(err.Error()) {
			return status
		}
	}
	return credenvelope.StatusNone
}

// statusCodeInError extracts the status from the AWS SDK's own rendering.
var statusCodeInError = regexp.MustCompile(`StatusCode: (\d{3})`)

// awsCodeWord builds a word-boundary matcher for an AWS error code, so a code
// cannot be found inside an unrelated identifier.
func awsCodeWord(code string) *regexp.Regexp {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(code) + `\b`)
}
