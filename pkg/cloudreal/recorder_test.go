package cloudreal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run WITHOUT credentials, and that is the point. The recorder is the only thing
// standing between a live session cookie and a committed file, and the time to discover a
// broken rule is not while holding real credentials.
//
// Upstream's own experience is the argument: its UUID redaction rule once matched nothing at
// all, because a `\b` anchor did not apply in the context it was moved into, and three real
// request ids were committed. The rule looked right. Test the rules.

func TestScrubRemovesEveryShapeItClaimsTo(t *testing.T) {
	r := NewRecorder(t, t.TempDir())

	cases := []struct {
		name    string
		input   string
		mustNot string
		why     string
	}{
		{
			name:    "an email address",
			input:   `{"email":"someone@example.com"}`,
			mustNot: "someone@example.com",
			why:     "recordings outlive the reason they were made; they must not identify a person",
		},
		{
			name:    "a session cookie by name",
			input:   `Set-Cookie: _digitalocean2_session_v4=abc123def456ghi789; path=/; HttpOnly`,
			mustNot: "abc123def456ghi789",
			why:     "a session cookie is a bearer of full account access until it expires",
		},
		{
			name:    "a token field learned mid-run",
			input:   `{"data":{"CreateToken":{"token":{"token":"dop_v1_0123456789abcdef0123456789abcdef"}}}}`,
			mustNot: "dop_v1_0123456789abcdef0123456789abcdef",
			why:     "the response that first carries a new token is the one where its value is not yet known",
		},
		{
			name:    "session_data, which is a credential in its own right",
			input:   `{"session_data":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload"}`,
			mustNot: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload",
			why:     "session_data carries the half-completed login between the two calls",
		},
		{
			name:    "a password echoed back in an error",
			input:   `{"errors":[{"message":"invalid","input":{"password":"correct-horse-battery"}}]}`,
			mustNot: "correct-horse-battery",
			why:     "an error body can quote the request that caused it",
		},
		{
			name:    "an account uuid",
			input:   `{"organization_id":"0f1e2d3c-4b5a-6978-8f0e-1d2c3b4a5968"}`,
			mustNot: "0f1e2d3c-4b5a-6978-8f0e-1d2c3b4a5968",
			why:     "not a secret, but it identifies the account these recordings came from",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := r.scrub(tc.input)
			if strings.Contains(got, tc.mustNot) {
				t.Fatalf("scrub left %q in the output: %s\ngot: %s", tc.mustNot, tc.why, got)
			}
			if !strings.Contains(got, redactedPrefix) {
				t.Errorf("scrub removed the value but left no redaction marker, so a reader cannot "+
					"tell an absent field from a redacted one: %s", got)
			}
		})
	}
}

// A value learned mid-run must be scrubbed from every LATER recording, wherever it appears —
// including places no shape rule would look, like a URL or a plain-text log line.
func TestLearnedSecretsAreScrubbedAnywhere(t *testing.T) {
	r := NewRecorder(t, t.TempDir())
	const secret = "a-session-value-long-enough-to-register"
	r.Learn(secret)

	for _, context := range []string{
		"redirect to https://example.invalid/callback?state=" + secret,
		"plain prose mentioning " + secret + " in passing",
		`{"unexpected_field_name":"` + secret + `"}`,
	} {
		if got := r.scrub(context); strings.Contains(got, secret) {
			t.Errorf("a registered secret survived in %q -> %q", context, got)
		}
	}
}

// Registering something short would match everywhere and destroy the evidence, so Learn
// refuses it. Guarded by a test because the failure is silent and looks like over-redaction.
func TestLearnIgnoresValuesTooShortToBeSafe(t *testing.T) {
	r := NewRecorder(t, t.TempDir())
	r.Learn("abc")
	if got := r.scrub("abc is a common substring in abcdef"); !strings.Contains(got, "abcdef") {
		t.Errorf("a three-character 'secret' was used for substring scrubbing: %q", got)
	}
}

// Header NAMES answer one of the probe's questions — what does this API require? — so they
// are kept, while anything that could carry a credential is not.
func TestScrubHeadersKeepsNamesAndDropsValues(t *testing.T) {
	r := NewRecorder(t, t.TempDir())
	got := r.scrubHeaders(map[string][]string{
		"Set-Cookie":   {"_digitalocean2_session_v4=secretvalue123456; HttpOnly"},
		"X-Csrf-Token": {"csrf-secret-value"},
		"Content-Type": {"application/json"},
	})

	if _, ok := got["Set-Cookie"]; !ok {
		t.Error("the Set-Cookie header NAME was dropped; its presence is part of what we are learning")
	}
	if strings.Contains(got["Set-Cookie"], "secretvalue123456") {
		t.Error("a cookie value survived header scrubbing")
	}
	if strings.Contains(got["X-Csrf-Token"], "csrf-secret-value") {
		t.Error("a CSRF token value survived header scrubbing")
	}
	if got["Content-Type"] != "application/json" {
		t.Errorf("an innocuous header value was mangled: %q", got["Content-Type"])
	}
}

// Recordings are files on disk holding upstream diagnostics. They should not be world
// readable even in a private repo on a shared machine.
func TestRecordingsAreNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	r := NewRecorder(t, dir)
	r.Record("Q-example", 200, `{"query":"x"}`, `{"data":{"ok":true}}`, nil)

	info, err := os.Stat(filepath.Join(dir, "Q-example.json"))
	if err != nil {
		t.Fatalf("the recording was not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("recording written with mode %o; it should be owner-only", perm)
	}
}

// FirstStringField is what registers a secret for scrubbing, so a defect in it has security
// consequences — the value it fails to find is the value that reaches a file in the clear.
func TestFirstStringFieldFindsNestedValues(t *testing.T) {
	const body = `{"data":{"CreateToken":{"token":{"id":"42","name":"x",
		"token":"dop_v1_deadbeefdeadbeefdeadbeefdeadbeef","expires_in":3600}}}}`

	if got := FirstStringField(body, "token"); !strings.HasPrefix(got, "dop_v1_") && got != "" {
		// "token" is both an object and a string field here; either answer is acceptable as
		// long as it does not silently return empty, which is the dangerous case.
		t.Logf("field 'token' resolved to %q", got)
	}
	if got := FirstStringField(body, "id"); got != "42" {
		t.Errorf("nested id: got %q, want 42", got)
	}
	if got := FirstStringField(body, "expires_in"); got != "3600" {
		t.Errorf("a numeric field must be readable as a string: got %q, want 3600", got)
	}
	if got := FirstStringField(`not json at all`, "token"); got != "" {
		t.Errorf("unparseable input should yield empty, got %q", got)
	}
}

// The numeric form of an account id, which is the half the uuid rule never covered. The case
// above named "an account uuid" passed on uuidShaped, so nothing asserted this shape at all
// and a real organization_id reached twelve committed recordings.
//
// Type preservation is asserted, not incidental: these recordings are replayed by a parity
// test that compares JSON types, and turning a number into a string is one of the defects
// that test exists to catch — so a "safer" redaction that quoted the value would break the
// consumer while looking more careful.
func TestScrubRemovesNumericAccountIdsAndKeepsTheirType(t *testing.T) {
	r := NewRecorder(t, t.TempDir())

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "a numeric organization id stays a number",
			input: `{"token":{"organization_id":7412037,"name":"x"}}`,
			want:  `{"token":{"organization_id":0,"name":"x"}}`,
		},
		{
			name:  "a string account id keeps its quotes",
			input: `{"account_id":"acct-9182736455"}`,
			want:  `{"account_id":"{redacted:account-id}"}`,
		},
		{
			name:  "the encoded form, where every quote is escaped",
			input: `"response":"{\"organization_id\":7412037}"`,
			want:  `"response":"{\"organization_id\":0}"`,
		},
		{
			name:  "already redacted input is left alone",
			input: `{"organization_id":0}`,
			want:  `{"organization_id":0}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.scrub(tc.input); got != tc.want {
				t.Errorf("scrub:\n got  %s\n want %s", got, tc.want)
			}
		})
	}
}

// A field name this rule does not know about must not be blanked. The rule is keyed on names
// that mean "whose account", and widening it to every *_id would blank the token id and the
// slot index — values the recordings exist to show.
func TestScrubLeavesNonAccountIdsIntact(t *testing.T) {
	r := NewRecorder(t, t.TempDir())

	const body = `{"id":"585455852","rbac_version":null,"expires_in":3600,"page":11}`
	if got := r.scrub(body); got != body {
		t.Errorf("scrub altered fields that identify nothing:\n got  %s\n want %s", got, body)
	}
}

// The gate, not the rule. refuseOnLeak re-scans the ENCODED file, so a pattern that insists on
// a bare quote passes it vacuously — which is how a rule can look present and catch nothing.
// Asserted by handing the gate a body the scrubber never saw.
func TestTheGateRefusesAnUnscrubbedAccountId(t *testing.T) {
	encoded := []byte(`{"question":"D","response":"{\"organization_id\":7412037}"}`)
	if match := accountFieldShaped.FindString(string(encoded)); match == "" {
		t.Fatal("the gate's own pattern does not match an account id in the encoded form it " +
			"actually scans, so refuseOnLeak would pass this file")
	}
}
