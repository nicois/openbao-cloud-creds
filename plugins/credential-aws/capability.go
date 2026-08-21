package credentialaws

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Capability verification for AWS.
//
// The health check is sts:GetCallerIdentity, which every valid signature answers
// — AWS does not even require a policy to permit it. It therefore says nothing
// about whether the minter IAM user may sts:AssumeRole a role's ARN, whether that
// role's trust policy names this principal, whether the external ID matches, or
// whether sts:TagSession is permitted for the role's session tags. Each of those
// is a per-role fact that a healthy minter can fail, and the failure only shows
// up as an AccessDenied on a caller's credential read.
//
// The probe is an AssumeRole with the role's own ARN, external ID and session
// tags, at the shortest duration AWS accepts. Nothing is deleted afterwards:
// STS credentials cannot be revoked, so the probe deliberately leaves a session
// that expires by itself. It is never returned to a caller and never recorded in
// a lease. probeDurationSeconds keeps that window at AWS's 900s floor.

// probeDurationSeconds is the DurationSeconds a probe AssumeRole asks for. AWS
// rejects anything below 900, so this is the shortest-lived session a probe can
// leave behind.
const probeDurationSeconds = 900

// capabilityChecks builds the probes proving each active minter in the set can
// assume the role one stored role names. The dedup key is the minter plus
// everything about the role that reaches STS — ARN, external ID and session tags
// are each independently able to turn an allowed AssumeRole into AccessDenied.
func (b *backend) capabilityChecks(set *cloudconfig.MinterSet, roleJSON []byte) []capability.Check {
	var role awsRole
	if err := json.Unmarshal(roleJSON, &role); err != nil {
		return nil
	}
	return capability.ChecksPerMinter(set, role.Name, assumeRoleShape(&role), func(minter cloudconfig.Minter) func(context.Context) error {
		return b.probeMint(minter, &role)
	})
}

// assumeRoleShape describes the mint request a role produces, for probe dedup.
// Session tags are sorted so two roles with the same tags in a different map
// order share one probe.
func assumeRoleShape(role *awsRole) string {
	keys := make([]string, 0, len(role.SessionTags))
	for k := range role.SessionTags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tags := make([]string, 0, len(keys))
	for _, k := range keys {
		tags = append(tags, k+"="+role.SessionTags[k])
	}
	return role.IAMRoleARN + "|" + role.ExternalID + "|" + strings.Join(tags, ",")
}

// probeMint returns a probe that assumes the role's ARN for the minimum duration.
// There is nothing to clean up: STS has no revoke, which is why the duration is
// pinned to the floor rather than the role's TTL.
func (b *backend) probeMint(minter cloudconfig.Minter, role *awsRole) func(context.Context) error {
	return func(ctx context.Context) error {
		b.mu.RLock()
		client := b.buildSTSClient(minter)
		b.mu.RUnlock()

		if _, err := client.AssumeRole(ctx, probeAssumeRoleInput(role)); err != nil {
			return fmt.Errorf("probe AssumeRole on %s failed: %w", role.IAMRoleARN, err)
		}
		return nil
	}
}

// probeAssumeRoleInput builds the probe's request from the same helper issuance
// uses — so the probe exercises the role's real external ID and session tags —
// then pins the session name to a probe name and the duration to the floor.
func probeAssumeRoleInput(role *awsRole) *sts.AssumeRoleInput {
	input := buildAssumeRoleInput(role, role.Name, "")
	sessionName := capability.ProbeName(role.Name)
	if len(sessionName) > maxSessionNameLen {
		sessionName = sessionName[:maxSessionNameLen]
	}
	input.RoleSessionName = aws.String(sessionName)
	duration := int32(probeDurationSeconds)
	input.DurationSeconds = &duration
	return input
}

// verifySetCapability gates a minter-set write on every active minter being able
// to mint for every role already bound to the set.
func (b *backend) verifySetCapability(ctx context.Context, storage logical.Storage, set *cloudconfig.MinterSet) *logical.Response {
	return b.gate().VerifySet(ctx, storage, set, b.capabilityChecks)
}

// verifyRoleCapability gates a role write on the minters of the set it binds to
// being able to assume what it names.
func (b *backend) verifyRoleCapability(ctx context.Context, storage logical.Storage, role *awsRole) *logical.Response {
	return b.gate().VerifyRole(ctx, storage, role.MinterSet, capability.RoleJSON(role), b.capabilityChecks)
}

// verifySuccessorCapability gates a rotation commit on the successor being able
// to mint for every role bound to the set. A rotated AWS access key belongs to
// the same IAM user, so it normally inherits the user's permissions — but not if
// the user's policy or a role's trust policy names the key, or a permissions
// boundary was changed between mint and rotate, and GetCallerIdentity cannot tell
// the difference.
func (b *backend) verifySuccessorCapability(ctx context.Context, storage logical.Storage, setName string, successor cloudconfig.Minter) *logical.Response {
	return b.gate().VerifySuccessor(ctx, storage, setName, successor, b.capabilityChecks)
}

// gate snapshots the operator's verification setting for this backend.
func (b *backend) gate() capability.Gate {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return capability.Gate{Cloud: cloudName, Logger: b.Logger(), Enabled: b.config.CapabilityVerificationEnabled()}
}
