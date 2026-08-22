package credentialaws

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// TestSessionPoliciesReachAssumeRole is the regression guard for A22. techrfc.md and
// design.md both specified policy_arns and inline_policy; neither existed, so every
// issued AWS credential carried the target IAM role's ENTIRE permission set and
// privilege separation could only be done by creating one IAM role per level
// upstream — while the published contract promised narrowing.
func TestSessionPoliciesReachAssumeRole(t *testing.T) {
	role := &awsRole{
		Name:         "narrowed",
		DefaultTTL:   minSTSTTL,
		IAMRoleARN:   "arn:aws:iam::123456789012:role/app",
		PolicyARNs:   []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		InlinePolicy: `{"Version":"2012-10-17","Statement":[]}`,
	}
	input := buildAssumeRoleInput(role, role.Name, "req1")

	if len(input.PolicyArns) != 1 {
		t.Fatalf("PolicyArns has %d entries, want 1: without them the session carries the target "+
			"role's full permissions", len(input.PolicyArns))
	}
	if got := aws.ToString(input.PolicyArns[0].Arn); got != role.PolicyARNs[0] {
		t.Errorf("PolicyArns[0] = %q, want %q", got, role.PolicyARNs[0])
	}
	if got := aws.ToString(input.Policy); got != role.InlinePolicy {
		t.Errorf("Policy = %q, want the role's inline policy", got)
	}
}

// The capability probe must exercise the same narrowing, and two roles differing only
// in it must not share one probe — a malformed inline policy makes AssumeRole fail,
// so it is part of the mint shape.
func TestNarrowingIsPartOfTheProbeShape(t *testing.T) {
	base := &awsRole{Name: "r", IAMRoleARN: "arn:aws:iam::1:role/a"}
	narrowed := &awsRole{Name: "r", IAMRoleARN: "arn:aws:iam::1:role/a",
		InlinePolicy: `{"Version":"2012-10-17"}`}

	if assumeRoleShape(base) == assumeRoleShape(narrowed) {
		t.Error("two roles differing only in inline_policy share one probe shape, so the narrowed " +
			"one is never actually probed (A22)")
	}

	probe := probeAssumeRoleInput(narrowed)
	if aws.ToString(probe.Policy) != narrowed.InlinePolicy {
		t.Error("the capability probe does not send the role's inline policy, so it proves a mint " +
			"shape the plugin will not use")
	}
	if !strings.HasPrefix(aws.ToString(probe.RoleSessionName), "cloud-creds-") {
		t.Error("probe session name lost the owner prefix")
	}
}
