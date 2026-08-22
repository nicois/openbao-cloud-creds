//go:build cloud_real

package credentialaws

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Real-cloud probe for credential-aws. Run by `make test-cloud-real-aws`; it
// calls the REAL AWS STS API with a real IAM user's access key.
//
// It exists because no fake can answer whether the plugin's mint shape is one AWS
// accepts. The DO probe made that concrete: every in-process layer agreed the DO
// mint path worked, and a real credential showed the endpoint is fenced (KI-009).
// The questions here are the AWS equivalents, and unlike DO's they are all
// answerable:
//
//	A1 does AssumeRole accept the shape buildAssumeRoleInput produces?
//	A2 is the credential AWS returns actually usable, and does the plugin read the
//	   right fields out of the response? (a wrong field name mints fine and hands
//	   back an empty credential — a fake written from the same docs cannot catch it)
//	A3 is the expiry AWS grants the one the role asked for? The whole TTL contract
//	   rests on it: a lease must never outlive its credential (techrfc OBC-002),
//	   and for AWS the credential's expiry is fixed at mint and cannot be revoked.
//	A4 does AWS enforce the 900s–43200s bound the plugin mirrors in role validation?
//
// It drives the plugin's OWN client, built by the plugin's own factory
// (newRealSTSClient) with the plugin's own request builders
// (buildAssumeRoleInput, probeAssumeRoleInput) — so signing, shaping and decoding
// are all under test, not merely reachable. The recorder is injected per call
// through the options the STSClient interface already exposes, so nothing in
// production code exists for the test's benefit.
//
// Every created session name carries the `cloud-creds-` owner prefix. Nothing
// needs cleaning up: STS sessions cannot be revoked, which is why every duration
// here is the shortest the assertion allows.
//
// Missing credentials FAIL rather than skip. The build tag is the opt-in; a run
// that passes without credentials would prove nothing while looking green.

const (
	envRealAWSKey        = "CLOUDREAL_AWS_KEY"
	envRealAWSRoleARN    = "CLOUDREAL_AWS_ROLE_ARN"
	envRealAWSRegion     = "CLOUDREAL_AWS_REGION"
	envRealAWSLowCapRole = "CLOUDREAL_AWS_LOWCAP_ROLE_ARN"

	// probeRoleName is the stored-role name the probe pretends to be issuing for.
	// It reaches AWS inside the session name, so it stays owner-prefixed.
	probeRoleName = "cloudreal"

	// probeReqID stands in for the core-assigned request id in a session name.
	probeReqID = "probe"

	// issuanceTTL is the role TTL the issuance-shape case asks for: above the 900s
	// floor so that "AWS granted what was asked" is distinguishable from "AWS
	// granted its minimum".
	issuanceTTL = 1800 * time.Second

	// expirySlack absorbs the round trip between asking and comparing. Anything
	// larger would stop the assertion being about AWS honouring the duration.
	expirySlack = 90 * time.Second

	// aboveSTSMaxSeconds is one second past the documented 43200s ceiling, used to
	// confirm the bound the plugin enforces at role write is AWS's, not folklore.
	aboveSTSMaxSeconds = 43201
)

// requireEnv fails (never skips) when a required input is absent.
func requireEnv(t *testing.T, name, what string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is not set, so this test cannot exercise real AWS. It FAILS rather than skips: "+
			"the cloud_real build tag is the opt-in, so a green run without credentials would be a "+
			"false negative. Set %s to %s (see .env.cloud-real).", name, name, what)
	}
	return value
}

// realAWSInputs returns the probe's configuration and the recorder that will see
// every response, with the minter's secret already registered as a secret.
func realAWSInputs(t *testing.T) (client STSClient, roleARN string, rec *recordingTransport) {
	t.Helper()
	key := requireEnv(t, envRealAWSKey, "access_key_id:secret_access_key for the minter IAM user")
	roleARN = requireEnv(t, envRealAWSRoleARN, "the ARN of a role the minter may assume")

	id, secret, found := strings.Cut(key, ":")
	if !found || id == "" || secret == "" {
		t.Fatalf("%s must be access_key_id:secret_access_key (a single colon-separated pair); got %d "+
			"characters with found=%v", envRealAWSKey, len(key), found)
	}
	if !strings.HasPrefix(roleARN, "arn:aws:iam::") || !strings.Contains(roleARN, ":role/") {
		t.Fatalf("%s must be a ROLE arn (arn:aws:iam::<account>:role/<name>); STS cannot assume a user, "+
			"so a user ARN here fails with an unhelpful AccessDenied. Got %q.", envRealAWSRoleARN, roleARN)
	}

	region := strings.TrimSpace(os.Getenv(envRealAWSRegion))
	if region == "" {
		region = defaultRegion
	}

	rec = newRecordingTransport(t, secret)
	// The plugin's own factory: static credentials, no session token, plugin
	// defaults for everything else.
	client = newRealSTSClient(id, secret, region, "")
	t.Logf("minter key id starts %q (%d chars), region %s, target role %s",
		id[:4], len(id), region, roleARN[strings.LastIndex(roleARN, ":")+1:])
	return client, roleARN, rec
}

// probeRole builds the stored role the probe issues against. SessionTags are set
// deliberately: they are the part of the mint shape that needs a SECOND action
// (sts:TagSession) in the target role's trust policy, so a trust policy that only
// allows sts:AssumeRole fails here and nowhere else.
func probeRole(roleARN string) *awsRole {
	return &awsRole{
		Name:        probeRoleName,
		DefaultTTL:  issuanceTTL,
		MaxTTL:      issuanceTTL,
		IAMRoleARN:  roleARN,
		MinterSet:   "cloudreal",
		SessionTags: map[string]string{"owner": "cloud-creds"},
	}
}

func TestRealAWSSTS(t *testing.T) {
	client, roleARN, rec := realAWSInputs(t)
	ctx := t.Context()

	// A control, and the answer to "is this credential even alive?". AWS requires
	// no policy to permit GetCallerIdentity, which is exactly why the capability
	// probe exists — a minter with no rights at all passes this.
	t.Run("MinterIdentity", func(t *testing.T) {
		out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, rec.recordOption())
		if err != nil {
			t.Fatalf("GetCallerIdentity failed, so the minter key is not usable at all: %v", err)
		}
		arn := aws.ToString(out.Arn)
		if !strings.Contains(arn, ":user/") {
			t.Errorf("the minter authenticates as %q, which is not an IAM user. Self-rotation calls "+
				"CreateAccessKey/ListAccessKeys with no UserName, so IAM must be able to infer a user "+
				"from the caller — an assumed-role credential can issue but can never rotate.",
				redactIdentifiers(arn))
		}
		t.Logf("minter identity %s (health check would pass)", redactIdentifiers(arn))
	})

	// A1 + A2 + A3 at the probe's own shape: exactly what capability verification
	// sends at minter-set and role write.
	t.Run("CapabilityProbeShapeIsAccepted", func(t *testing.T) {
		input := probeAssumeRoleInput(probeRole(roleARN))
		out, err := client.AssumeRole(ctx, input, rec.recordOption())
		if err != nil {
			t.Fatalf("the capability probe's own AssumeRole was refused: %v\n"+
				"That is the call verifySetCapability/verifyRoleCapability make, so every minter-set "+
				"and role write against this role would be rejected. Check the role's trust policy "+
				"names this IAM user and allows BOTH sts:AssumeRole and sts:TagSession.",
				scrubSecrets(err.Error(), rec.knownSecrets()...))
		}
		assertCredentialsComplete(t, out, rec)
		assertExpiryHonoured(t, out, time.Duration(probeDurationSeconds)*time.Second)
	})

	// The issuance shape, which differs from the probe's in the one way that
	// matters to a client: it asks for the role's real TTL rather than the floor.
	t.Run("IssuanceShapeHonoursRequestedTTL", func(t *testing.T) {
		role := probeRole(roleARN)
		input := buildAssumeRoleInput(role, role.Name, probeReqID)
		out, err := client.AssumeRole(ctx, input, rec.recordOption())
		if err != nil {
			t.Fatalf("issuance-shape AssumeRole failed: %v",
				scrubSecrets(err.Error(), rec.knownSecrets()...))
		}
		assertCredentialsComplete(t, out, rec)
		assertExpiryHonoured(t, out, issuanceTTL)

		// The session name is the plugin's only mark on an STS session, and the
		// reconciler's owner-prefix reasoning assumes it survives to AWS intact.
		wantSession := "cloud-creds-" + probeRoleName + "-" + probeReqID
		if arn := aws.ToString(out.AssumedRoleUser.Arn); !strings.HasSuffix(arn, "/"+wantSession) {
			t.Errorf("assumed-role ARN is %q, which does not end in the session name %q the plugin "+
				"sent — the owner prefix does not survive to AWS", redactIdentifiers(arn), wantSession)
		}
	})

	// A2, the half a fake cannot reach: does the credential WORK?
	t.Run("MintedCredentialAuthenticates", func(t *testing.T) {
		role := probeRole(roleARN)
		out, err := client.AssumeRole(ctx, buildAssumeRoleInput(role, role.Name, probeReqID),
			rec.recordOption())
		if err != nil {
			t.Fatalf("AssumeRole failed: %v", scrubSecrets(err.Error(), rec.knownSecrets()...))
		}
		registerMintedSecrets(out, rec)

		// Built here rather than by newRealSTSClient because the plugin's factory
		// takes no session token — it only ever holds long-lived minter keys. This
		// is the consumer's side of the envelope, not the plugin's.
		assumed := sts.New(sts.Options{
			Region: defaultRegion,
			Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
				aws.ToString(out.Credentials.AccessKeyId),
				aws.ToString(out.Credentials.SecretAccessKey),
				aws.ToString(out.Credentials.SessionToken),
			)),
		})
		who, err := assumed.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			t.Fatalf("the minted credential does not authenticate: %v\nThe plugin would hand a caller a "+
				"credential that cannot be used — the failure mode a fake can never show, because a "+
				"fake's credential is never used against anything.",
				scrubSecrets(err.Error(), rec.knownSecrets()...))
		}
		if arn := aws.ToString(who.Arn); !strings.Contains(arn, ":assumed-role/") {
			t.Errorf("the minted credential authenticates as %q, not an assumed role",
				redactIdentifiers(arn))
		}
		t.Logf("minted credential authenticates as %s", redactIdentifiers(aws.ToString(who.Arn)))
	})

	// A4: the bound path_roles.go enforces at role write is AWS's own.
	t.Run("DurationAboveSTSMaxIsRefused", func(t *testing.T) {
		role := probeRole(roleARN)
		input := buildAssumeRoleInput(role, role.Name, probeReqID)
		duration := int32(aboveSTSMaxSeconds)
		input.DurationSeconds = &duration

		if _, err := client.AssumeRole(ctx, input, rec.recordOption()); err == nil {
			t.Errorf("AWS accepted DurationSeconds=%d, above the documented 43200s ceiling. GOOD NEWS "+
				"AND A SPEC CHANGE: maxSTSTTL in path_roles.go is now stricter than AWS and should be "+
				"re-verified against the STS documentation.", aboveSTSMaxSeconds)
			return
		}
		t.Logf("DurationSeconds=%d refused, as maxSTSTTL assumes", aboveSTSMaxSeconds)
	})

	// A22: the narrowing fields are new, and a session policy is the kind of thing a
	// fake cannot validate — AWS parses the document and enforces the packed-policy
	// size. This proves STS accepts what the plugin now sends.
	t.Run("SessionPoliciesAreAccepted", func(t *testing.T) {
		role := probeRole(roleARN)
		role.PolicyARNs = []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"}
		role.InlinePolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":"sts:GetCallerIdentity","Resource":"*"}]}`

		out, err := client.AssumeRole(ctx, buildAssumeRoleInput(role, role.Name, probeReqID),
			rec.recordOption())
		if err != nil {
			t.Fatalf("AssumeRole with session policies was refused: %v\n"+
				"policy_arns and inline_policy narrow a session to the intersection of the target "+
				"role's permissions and the policy, so a refusal here means the plugin cannot honour "+
				"the narrowing contract it now advertises.",
				scrubSecrets(err.Error(), rec.knownSecrets()...))
		}
		assertCredentialsComplete(t, out, rec)
		t.Logf("STS accepted %d managed policy ARN(s) plus an inline session policy",
			len(role.PolicyARNs))
	})

	t.Run("MaxSessionDurationGap", func(t *testing.T) {
		assertMaxSessionDurationGap(t, client, rec)
	})
}

// assertCredentialsComplete checks every field the plugin reads. An empty field
// here is the bug class this whole layer exists for: the mint succeeds, the lease
// is created, and the caller receives a credential with a hole in it.
func assertCredentialsComplete(t *testing.T, out *sts.AssumeRoleOutput, rec *recordingTransport) {
	t.Helper()
	if out.Credentials == nil {
		t.Fatal("AssumeRole returned no Credentials block at all")
	}
	registerMintedSecrets(out, rec)
	for label, value := range map[string]string{
		elemAccessKeyID:   aws.ToString(out.Credentials.AccessKeyId),
		"SecretAccessKey": aws.ToString(out.Credentials.SecretAccessKey),
		"SessionToken":    aws.ToString(out.Credentials.SessionToken),
	} {
		if value == "" {
			t.Errorf("AWS returned an empty %s, or the plugin's client decodes it from the wrong "+
				"element — either way a caller would get an unusable credential", label)
		}
	}
	if out.Credentials.Expiration == nil {
		t.Error("AWS returned no Expiration; the plugin derives the entire lease TTL from it")
	}
	if out.AssumedRoleUser == nil || aws.ToString(out.AssumedRoleUser.Arn) == "" {
		t.Error("AWS returned no AssumedRoleUser.Arn; the envelope records it as provenance")
	}
}

// assertExpiryHonoured is the TTL-honesty assertion: the credential must live
// approximately as long as was asked, and never longer than the lease will claim.
func assertExpiryHonoured(t *testing.T, out *sts.AssumeRoleOutput, requested time.Duration) {
	t.Helper()
	if out.Credentials == nil || out.Credentials.Expiration == nil {
		return
	}
	granted := time.Until(*out.Credentials.Expiration)
	if granted > requested+expirySlack {
		t.Errorf("asked for %s, AWS granted %s — LONGER than requested. The lease would expire while "+
			"the credential still works, leaving a usable credential nobody is tracking.",
			requested, granted.Round(time.Second))
	}
	if granted < requested-expirySlack {
		t.Errorf("asked for %s, AWS granted only %s — SHORTER than requested. The lease would outlive "+
			"the credential (techrfc OBC-002), so a caller holding a valid lease gets AccessDenied. "+
			"The most likely cause is the target role's MaxSessionDuration being below the role TTL.",
			requested, granted.Round(time.Second))
	}
	t.Logf("asked for %s, AWS granted %s", requested, granted.Round(time.Second))
}

// registerMintedSecrets tells the recorder about credentials AWS has just issued,
// so no later recording can echo them in the clear. The response that FIRST
// carries them is protected by element-name redaction instead — there is no
// substring to search for until after it has been written.
func registerMintedSecrets(out *sts.AssumeRoleOutput, rec *recordingTransport) {
	if out == nil || out.Credentials == nil {
		return
	}
	rec.addSecret(aws.ToString(out.Credentials.SecretAccessKey))
	rec.addSecret(aws.ToString(out.Credentials.SessionToken))
}

// assertMaxSessionDurationGap covers the one hole the capability probe cannot see.
// The probe pins DurationSeconds to AWS's 900s floor (it cannot revoke what it
// mints), so a target role whose MaxSessionDuration is BELOW a role's TTL passes
// verification at config time and fails at issue time — the same shape as
// health-vs-capability, one level down.
//
// Demonstrating it needs a second role capped below the plugin's ceiling, which
// the minter deliberately cannot create (its IAM grant is assume-only, by design).
// So the gap is DECLARED when that role is absent rather than silently skipped,
// following the Harness.Skips discipline: an uncovered case must be visible.
func assertMaxSessionDurationGap(t *testing.T, client STSClient, rec *recordingTransport) {
	t.Helper()
	lowCapARN := strings.TrimSpace(os.Getenv(envRealAWSLowCapRole))
	if lowCapARN == "" {
		t.Logf("DECLARED GAP: %s is unset, so the MaxSessionDuration trap is not exercised. "+
			"The capability probe asks for %ds; a role whose MaxSessionDuration is lower still passes "+
			"role write and fails at issue time. To pin it, create a role with "+
			"--max-session-duration 3600 trusting the same minter and set %s to its ARN.",
			envRealAWSLowCapRole, probeDurationSeconds, envRealAWSLowCapRole)
		return
	}

	role := probeRole(lowCapARN)
	probeInput := probeAssumeRoleInput(role)
	if _, err := client.AssumeRole(t.Context(), probeInput, rec.recordOption()); err != nil {
		t.Fatalf("the 900s capability probe failed against the low-cap role, so this case cannot "+
			"demonstrate the gap: %v", scrubSecrets(err.Error(), rec.knownSecrets()...))
	}

	issueInput := buildAssumeRoleInput(role, role.Name, probeReqID)
	_, err := client.AssumeRole(t.Context(), issueInput, rec.recordOption())
	if err == nil {
		t.Errorf("the %s issuance succeeded against a role expected to cap sessions below it — either "+
			"its MaxSessionDuration is not lower than %s after all, or AWS now clamps instead of "+
			"refusing, which would CLOSE this gap and is worth confirming.", issuanceTTL, issuanceTTL)
		return
	}
	t.Logf("GAP CONFIRMED: the 900s probe passed and the %s issuance failed on the same role. An "+
		"operator sees this only at issue time, as: %s", issuanceTTL,
		scrubSecrets(err.Error(), rec.knownSecrets()...))
}
