package credentialaws

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
)

// This file is deliberately UNTAGGED: it runs in an ordinary, credential-free
// `go test`, and it is what makes a privileged real-cloud run worth its
// credentials. Two jobs:
//
//  1. **Scrub enforcement.** Recordings under testdata/cloud-real/ are committed
//     to a public repository. Every gate the recorder applies before writing is
//     re-applied here to the files as they actually sit on disk, so a leak cannot
//     survive by way of an edited recorder, a hand-added fixture, or a rule that
//     regressed after the recording was made.
//
//  2. **Fake parity.** AWS is an injected-client plugin (G8 in
//     docs/openbao-integration-gaps.md): there is no HTTP-level AWS fake to replay
//     a recording against, the way plugins/credential-do/fake_parity_test.go
//     replays DO's. So parity here is asserted at the level that *is* shared — the
//     set of fields the plugin reads out of an AssumeRole response. The recording
//     proves which elements STS really sends; fakeSTSClient must populate exactly
//     those. That catches the bug class a fake written from the docs cannot: the
//     plugin reading a field AWS does not send, or the fake inventing one.
//
// The shape regexes and redaction markers live HERE rather than in the tagged
// recorder because both builds need them, and a duplicated literal is both a
// goconst finding and a way for the two copies to drift.

const (
	// recordDir is relative to the package dir, so recordings live with the
	// plugin whose client produced them.
	recordDir = "testdata/cloud-real"

	// redactedPrefix opens every redaction marker. Braces, not angle brackets: the
	// body being scrubbed is XML, and a marker must not make it unparseable. Shared
	// by the tagged recorder, which writes markers, and the assertions here, which
	// check for them — one literal, so the writer and the checker cannot drift.
	redactedPrefix = "{redacted:"
)

// Identifier shapes. None of these is a credential, and that is exactly why the
// secret rules cannot see them: a real AWS account answers with the account
// number in every ARN, and with principal ids that identify the operator who ran
// the probe. Handled by value shape because the same value arrives under element
// names we cannot enumerate ahead of a response we have not seen.
var (
	// accountShaped is a 12-digit AWS account id.
	accountShaped = regexp.MustCompile(`\b\d{12}\b`)
	// accessKeyShaped covers long-term (AKIA) and temporary/session (ASIA) key ids.
	accessKeyShaped = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	// principalShaped covers IAM user (AIDA) and role (AROA) unique ids.
	principalShaped = regexp.MustCompile(`\b(?:AIDA|AROA)[0-9A-Z]{17,}\b`)
)

// secretElements are the XML elements whose text content is a credential in the
// clear. Redacted by element name rather than by value, because the minted secret
// and session token are unknown until the very response being written — there is
// no substring to search for yet.
var secretElements = []string{"SecretAccessKey", "SessionToken"}

// mintedFieldElements are the elements the plugin reads out of an AssumeRole
// response (path_creds.go buildCredsResponse + sts_client.go). A recording must
// carry every one of them, or the plugin is reading something STS does not send.
var mintedFieldElements = []string{
	elemAccessKeyID, "SecretAccessKey", "SessionToken", "Expiration", "Arn",
}

// unassertable lists recordings this test deliberately does not hold the fake to,
// each with a reason about the FAKE's design — the same discipline as
// plugintest.Harness.Skips. A recording that is neither asserted nor listed here
// fails TestEveryRecordingIsAssertedOrDeclared, so a privileged run cannot leave
// evidence that quietly rots.
var unassertable = map[string]string{
	"POST_GetCallerIdentity_200.json": "fakeSTSClient.GetCallerIdentity returns a fixed identity and the " +
		"plugin's health check only asks whether the call succeeded — no field of this body reaches " +
		"plugin logic, so there is nothing for the fake to be held to. Kept as the CONTROL: it proves " +
		"the minter key is live and is the IAM user we think it is, which is what makes a failure " +
		"elsewhere an authorization fact rather than a dead credential.",
}

// readRecording loads one scrubbed recording.
func readRecording(t *testing.T, name string) recordedResponse {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(recordDir, name))
	if err != nil {
		t.Fatalf("reading recording %s: %v", name, err)
	}
	var recorded recordedResponse
	if err := json.Unmarshal(raw, &recorded); err != nil {
		t.Fatalf("decoding recording %s: %v", name, err)
	}
	return recorded
}

// recordedResponse is the on-disk recording shape written by the tagged recorder.
// The body stays a string: STS answers in XML, and re-encoding it would lose
// exactly the element-level detail the parity assertions are about.
type recordedResponse struct {
	Request struct {
		Action string `json:"action"`
	} `json:"request"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

// recordingNames lists the recordings present, or nothing if the directory does
// not exist yet (no privileged run has happened on this checkout).
func recordingNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(recordDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("reading %s: %v", recordDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	return names
}

// TestRecordingsAreScrubbed re-applies every fail-closed gate to the files as
// committed. The recorder already refuses to write a leak; this is the check that
// keeps holding once the recorder is out of the picture.
func TestRecordingsAreScrubbed(t *testing.T) {
	names := recordingNames(t)
	if len(names) == 0 {
		t.Skip("no recordings yet — run `make test-cloud-real-aws` with real credentials to create them")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(recordDir, name))
			if err != nil {
				t.Fatalf("reading %s: %v", name, err)
			}
			assertNoIdentifiers(t, name, string(raw))
			assertSecretElementsRedacted(t, name, string(raw))
		})
	}
}

func assertNoIdentifiers(t *testing.T, name, body string) {
	t.Helper()
	for label, shape := range map[string]*regexp.Regexp{
		"AWS account id": accountShaped,
		"access key id":  accessKeyShaped,
		"principal id":   principalShaped,
	} {
		if match := shape.FindString(body); match != "" {
			t.Errorf("%s leaks a %s (%q). Recordings are committed to a public repo; extend the "+
				"recorder's redaction and re-record.", name, label, match)
		}
	}
}

func assertSecretElementsRedacted(t *testing.T, name, body string) {
	t.Helper()
	for _, element := range secretElements {
		for _, inner := range elementValues(body, element) {
			if !strings.HasPrefix(inner, redactedPrefix) {
				t.Errorf("%s carries an unredacted <%s> (%d chars). That is a live credential in a "+
					"public repo — delete the file and fix the recorder.", name, element, len(inner))
			}
		}
	}
}

// elementValues returns the text content of every occurrence of an XML element.
// A deliberately small reader: the recordings are STS responses, not arbitrary
// XML, and a real parser would have to cope with the redaction markers already
// substituted into them.
func elementValues(body, element string) []string {
	var out []string
	openTag, closeTag := "<"+element+">", "</"+element+">"
	rest := body
	for {
		start := strings.Index(rest, openTag)
		if start < 0 {
			return out
		}
		rest = rest[start+len(openTag):]
		end := strings.Index(rest, closeTag)
		if end < 0 {
			return out
		}
		out = append(out, rest[:end])
		rest = rest[end+len(closeTag):]
	}
}

// TestFakeSTSClientMatchesRecordedAssumeRole is the parity assertion: every
// element the plugin reads must be present in what STS really sent AND populated
// by the fake. Without this, the fake is only ever checked against the same
// reading of the docs that produced the plugin.
func TestFakeSTSClientMatchesRecordedAssumeRole(t *testing.T) {
	const name = "POST_AssumeRole_200.json"
	if _, err := os.Stat(filepath.Join(recordDir, name)); os.IsNotExist(err) {
		t.Skip("no AssumeRole recording yet — run `make test-cloud-real-aws` with real credentials")
	}
	recorded := readRecording(t, name)

	for _, element := range mintedFieldElements {
		if len(elementValues(recorded.Body, element)) == 0 {
			t.Errorf("real STS AssumeRole response has no <%s>, but the plugin reads it — either the "+
				"recording is stale or the plugin reads a field AWS does not send", element)
		}
	}

	fake := &fakeSTSClient{}
	duration := int32(probeDurationSeconds)
	out, err := fake.AssumeRole(t.Context(), &sts.AssumeRoleInput{DurationSeconds: &duration})
	if err != nil {
		t.Fatalf("fake AssumeRole: %v", err)
	}
	for label, value := range map[string]string{
		elemAccessKeyID:   aws.ToString(out.Credentials.AccessKeyId),
		"SecretAccessKey": aws.ToString(out.Credentials.SecretAccessKey),
		"SessionToken":    aws.ToString(out.Credentials.SessionToken),
		"AssumedRoleUser.Arn": func() string {
			if out.AssumedRoleUser == nil {
				return ""
			}
			return aws.ToString(out.AssumedRoleUser.Arn)
		}(),
	} {
		if value == "" {
			t.Errorf("fakeSTSClient leaves %s empty, but real STS populates it — a plugin bug that "+
				"depends on that field would pass every in-process test", label)
		}
	}
	if out.Credentials.Expiration == nil {
		t.Error("fakeSTSClient leaves Expiration nil, but real STS populates it and the plugin " +
			"derives the whole lease TTL from it")
	}
}

// TestRecordedValidationErrorIsClassifiedFromTheCloudsOwnWords holds the KI-010
// fix to the evidence that motivated it.
//
// AWS's envelope says <Type>Sender</Type> — the CALLER is at fault — and the
// message is specific and permanent ("Member must have value less than or equal to
// 43200"). Before the fix, classifyAWSError had no ValidationError branch and fell
// through to a synthetic 500, so the client was told `internal` (the plugin broke,
// stop retrying) and the recovery state machine counted a fault against a perfectly
// healthy minter.
//
// This is the surfacing behaviour of the MaxSessionDuration gap declared in
// real_cloud_test.go: a target role capped below a role's TTL passes capability
// verification (which asks for the 900s floor) and then fails every issuance with
// exactly this response. The assertions below are what stop it regressing — they
// are written against the recorded bytes, so a change in AWS's envelope breaks them
// rather than silently defeating the string matching.
func TestRecordedValidationErrorIsClassifiedFromTheCloudsOwnWords(t *testing.T) {
	const name = "POST_AssumeRole_400.json"
	if _, err := os.Stat(filepath.Join(recordDir, name)); os.IsNotExist(err) {
		t.Skip("no ValidationError recording yet — run `make test-cloud-real-aws` with real credentials")
	}
	recorded := readRecording(t, name)

	if recorded.Status != http.StatusBadRequest {
		t.Errorf("expected AWS to refuse an over-long duration with 400, got %d", recorded.Status)
	}
	for _, want := range []string{"<Code>ValidationError</Code>", "<Type>Sender</Type>"} {
		if !strings.Contains(recorded.Body, want) {
			t.Errorf("recorded refusal does not contain %s; AWS's error envelope has changed shape and "+
				"classifyAWSError's string matching is written against it", want)
		}
	}

	status := classifyAWSError(errors.New(recorded.Body))
	if status != http.StatusBadRequest {
		t.Errorf("classifyAWSError maps AWS's own ValidationError to %d, want %d (KI-010)",
			status, http.StatusBadRequest)
	}

	code := credenvelope.Classify(status, nil)
	if code != credenvelope.ErrUpstreamRequestInvalid {
		t.Errorf("a ValidationError reaches the client as %q, want %q — `internal` told the caller to "+
			"stop retrying and page an engineer about its own bad request", code,
			credenvelope.ErrUpstreamRequestInvalid)
	}
	if credenvelope.IndictsMinter(code) {
		t.Error("a ValidationError counts against the minter's health. The credential is fine; the " +
			"request was not. This is what drove healthy minters toward AuthFailing.")
	}
}

// TestEveryRecordingIsAssertedOrDeclared keeps the evidence honest: a recording is
// only worth having if something asserts on it, or a reason says why not.
func TestEveryRecordingIsAssertedOrDeclared(t *testing.T) {
	asserted := map[string]bool{
		"POST_AssumeRole_200.json": true,
		"POST_AssumeRole_400.json": true,
	}
	for _, name := range recordingNames(t) {
		if asserted[name] {
			continue
		}
		reason, declared := unassertable[name]
		if !declared {
			t.Errorf("recording %s is neither asserted nor declared unassertable. Assert it, or add a "+
				"reason about the FAKE's design to unassertable.", name)
			continue
		}
		t.Logf("unassertable: %s — %s", name, reason)
	}
	for name := range unassertable {
		if _, err := os.Stat(filepath.Join(recordDir, name)); os.IsNotExist(err) {
			t.Errorf("unassertable names %s, which does not exist — a stale declaration hides the fact "+
				"that nothing is checking it", name)
		}
	}
}
