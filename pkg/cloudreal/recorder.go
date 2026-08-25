// Package cloudreal is the shared machinery for validating a cloud fake against the real API.
//
// A run with real credentials is rare and privileged, so what it observes has to outlive it:
// every response is scrubbed and written to testdata, and an ordinary credential-free test then
// holds the fake to those recordings. That is what turns one privileged run into permanent
// coverage, and it is the mechanism that stops a fake drifting into agreement with whoever wrote
// it — which is not hypothetical here. A fake in this project was once written to match the
// plugin's assumption rather than the API, and every credential that plugin issued was unusable
// while every test passed.
//
// It is here rather than inside a plugin because nothing about scrubbing is cloud-specific.
// (The DO and AWS plugins each carry their own recorder, predating this package; both are
// candidates to migrate onto it, which would remove two copies of these rules.) What IS
// cloud-specific — a distinctive cookie name, a credential format worth naming — a caller adds
// with WithRules.
package cloudreal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// The recorder is FAIL-CLOSED. It does not redact as best it can and hope; it proves a
// payload is clean and refuses to write it otherwise. Everything it handles is a live
// credential or a real person's identity:
//
//   - the account password and the second-factor seed (supplied, so searchable by value);
//   - the session cookie (learned mid-run — a bearer of full account access until it expires);
//   - every minted token (learned mid-run, and the thing this whole project exists to keep
//     short-lived);
//   - email addresses and account/organization ids (not secrets, but they identify real
//     people and a real account, and recordings outlive the reason they were made).
//
// The two "learned mid-run" cases are why value-based scrubbing alone is not enough: the
// first response carrying a new secret is the one response in which that secret is not yet
// known. Those are caught by SHAPE — a cookie name, a `token` field, a base64-ish blob in a
// known position — and by refusing to write anything whose shape says "credential" and whose
// content is not already a redaction marker.
//
// This mirrors the upstream DO and AWS recorders, hardened for a login flow rather than a
// single API call. Upstream's own lesson applies: its UUID rule once matched nothing at all
// because a `\b` anchor did not apply in its new context, and three real request ids were
// committed. Test the rules, do not trust them.

const (
	recordDirPerm  os.FileMode = 0o700
	recordFilePerm os.FileMode = 0o600

	// redactedPrefix begins every replacement, so refuseOnLeak can tell a redaction from
	// the real thing it replaced.
	redactedPrefix = "{redacted:"

	// redactedLenFormat keeps the LENGTH of a secret and nothing else. Length is
	// diagnostically useful — it distinguishes an empty field from a populated one, which
	// is how you tell "the API returned no token" from "we failed to read it".
	redactedLenFormat = redactedPrefix + "%d chars}"
	redactedTagFormat = redactedPrefix + "%s}"

	// minSecretLen is the shortest value worth registering for substring scrubbing. Below
	// this a "secret" matches everywhere and turns every recording into confetti, which is
	// its own way of destroying the evidence.
	minSecretLen = 8
)

// Shapes that mean "this is a credential or an identity", independent of whether we know
// its value yet. Deliberately broad: a false positive costs a less useful recording, a
// false negative commits a secret.
var (
	// emailShaped catches both the operator's address and any DO staff address quoted back
	// in an error message.
	emailShaped = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

	// cookieShaped catches ANY cookie whose name suggests a session, wherever it appears — a
	// Set-Cookie header, a request echo, an error body. Deliberately by name rather than by a
	// specific cookie: a caller that knows its cloud's exact cookie name adds a rule for it,
	// and this catches the ones nobody thought to name.
	cookieShaped = regexp.MustCompile(`(?i)([0-9A-Za-z_\-]*(?:session|sess|sid|csrf|xsrf)[0-9A-Za-z_\-]*)=([^;"\\\s]+)`)

	// tokenFieldShaped catches a JSON field whose NAME says it carries a credential. This is
	// the rule that protects the response in which a token is first learned.
	tokenFieldShaped = regexp.MustCompile(`"(token|session_data|password|access_token|secret|code)"\s*:\s*"([^"]*)"`)

	// prefixedSecretShaped catches the widely-used "<prefix>_<random>" credential format even
	// outside a known field — DigitalOcean's dop_v1_, GitHub's ghp_, Slack's xoxb_ and so on.
	// A credential quoted in an error body appears in no field this could match by name.
	prefixedSecretShaped = regexp.MustCompile(`\b[a-z]{2,6}(?:_v?\d)?_[A-Za-z0-9]{16,}\b`)

	// idShaped catches the long numeric/uuid ids that identify the account itself.
	uuidShaped = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
)

// Rule is a caller-supplied redaction: a shape this recorder does not know about, and the
// label that replaces it. A cloud whose session cookie or credential format is distinctive adds
// one rather than widening the shared rules — which is also how a rule that would reveal
// something stays with the caller that needs it.
type Rule struct {
	// Shape matches what must not be written.
	Shape *regexp.Regexp
	// Label names what was removed, for a reader of the recording.
	Label string
}

// Recorder scrubs and writes what a real-cloud run observes.
type Recorder struct {
	t     *testing.T
	dir   string
	rules []Rule

	mu sync.Mutex
	// secrets grows as the run learns them: a session cookie after login, a token after
	// each create. Registering one protects every LATER recording; shape rules protect the
	// response that first carried it.
	secrets []string
}

// NewRecorder returns a recorder seeded with the credentials the caller already holds.
func NewRecorder(t *testing.T, dir string, known ...string) *Recorder {
	t.Helper()
	r := &Recorder{t: t, dir: dir}
	for _, s := range known {
		r.Learn(s)
	}
	return r
}

// WithRules adds caller-supplied redactions. They are applied BEFORE the shared ones and are
// enforced by the same fail-closed gate, so a rule a caller adds is a rule the recorder will
// refuse to write around.
func (r *Recorder) WithRules(rules ...Rule) *Recorder {
	r.rules = append(r.rules, rules...)
	return r
}

// Learn registers a credential the probe has just been handed, so no later recording can
// contain it in the clear.
func (r *Recorder) Learn(secret string) {
	if len(secret) < minSecretLen {
		// Refuse to register something short: it would match everywhere and turn every
		// recording into confetti, which is its own way of losing the evidence.
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secrets = append(r.secrets, secret)
}

func (r *Recorder) known() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.secrets...)
}

// Record writes one observation: what was asked, what came back, scrubbed. name becomes the
// filename, so use the question number — the point of these files is to be readable next to
// docs/probe-plan.md.
func (r *Recorder) Record(name string, status int, requestBody, responseBody string, headers map[string][]string) {
	r.t.Helper()
	r.RecordObservation(Observation{
		Name: name, Status: status, Request: requestBody, Response: responseBody, Headers: headers,
	})
}

// Observation is one recorded call. A struct because six positional arguments — two of them
// adjacent strings — is exactly the shape where a call site silently swaps two of them.
type Observation struct {
	// Name becomes the filename, so use something readable next to the plan it answers.
	Name   string
	Status int
	// Request and Response are the raw bodies; both are scrubbed before anything is written.
	Request  string
	Response string
	Headers  map[string][]string
	// Extra carries facts a later credential-free test must read back out of the recording
	// rather than re-derive. Scrubbed like everything else: a caller cannot smuggle a secret
	// past the gate by choosing its own field name.
	Extra map[string]interface{}
}

// RecordObservation is Record plus caller-supplied fields, for facts a later credential-free
// test needs to read back out of the recording rather than re-derive.
//
// The responder header is the case that motivated it: the conclusion drawn from these
// recordings — that a path is closed to bearer auth rather than to this credential — lives in
// WHICH LAYER answered, and an untagged parity test has to be able to check that the recorded
// evidence still supports the conclusion drawn from it.
//
// Extra fields are scrubbed like everything else. A caller cannot smuggle a secret past the
// gate by putting it in a field of its own choosing.
func (r *Recorder) RecordObservation(o Observation) {
	r.t.Helper()
	name := o.Name

	entry := map[string]interface{}{
		"question": name,
		"status":   o.Status,
		"request":  r.scrub(o.Request),
		"response": r.scrub(o.Response),
		"headers":  r.scrubHeaders(o.Headers),
	}
	for key, value := range o.Extra {
		if text, ok := value.(string); ok {
			entry[key] = r.scrub(text)
			continue
		}
		entry[key] = value
	}
	encoded, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		r.t.Logf("could not encode the recording for %s: %v", name, err)
		return
	}
	encoded = append(encoded, '\n')

	// Nothing below this line may write a file that leaks.
	r.refuseOnLeak(name, encoded)

	if err := os.MkdirAll(r.dir, recordDirPerm); err != nil {
		r.t.Logf("could not create %s: %v", r.dir, err)
		return
	}
	path := filepath.Join(r.dir, name+".json")
	if err := os.WriteFile(path, encoded, recordFilePerm); err != nil {
		r.t.Logf("could not write %s: %v", path, err)
		return
	}
	r.t.Logf("recorded %s (status %d) -> %s", name, o.Status, path)
}

// scrub applies the shape rules first, then the known values. Order matters: shape rules
// catch what is not yet known, and value rules catch what a shape rule might have missed.
func (r *Recorder) scrub(body string) string {
	if body == "" {
		return ""
	}
	out := body
	for _, rule := range r.rules {
		out = rule.Shape.ReplaceAllString(out, fmt.Sprintf(redactedTagFormat, rule.Label))
	}
	out = cookieShaped.ReplaceAllString(out, "$1="+fmt.Sprintf(redactedTagFormat, "session-cookie"))
	out = tokenFieldShaped.ReplaceAllStringFunc(out, func(match string) string {
		parts := tokenFieldShaped.FindStringSubmatch(match)
		return fmt.Sprintf("%q:%q", parts[1], fmt.Sprintf(redactedLenFormat, len(parts[2])))
	})
	out = prefixedSecretShaped.ReplaceAllString(out, fmt.Sprintf(redactedTagFormat, "prefixed-secret"))
	out = emailShaped.ReplaceAllString(out, fmt.Sprintf(redactedTagFormat, "email"))
	out = uuidShaped.ReplaceAllString(out, fmt.Sprintf(redactedTagFormat, "uuid"))
	for _, secret := range r.known() {
		out = strings.ReplaceAll(out, secret, fmt.Sprintf(redactedLenFormat, len(secret)))
	}
	return out
}

// scrubHeaders keeps header NAMES — which answer "what does this API require?", one of the
// probe's questions — and redacts every value that could carry a credential.
func (r *Recorder) scrubHeaders(headers map[string][]string) map[string]string {
	out := make(map[string]string, len(headers))
	for name, values := range headers {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "cookie") || strings.Contains(lower, "auth") ||
			strings.Contains(lower, "token") || strings.Contains(lower, "csrf") {
			out[name] = fmt.Sprintf(redactedTagFormat, "value")
			continue
		}
		out[name] = r.scrub(strings.Join(values, ", "))
	}
	return out
}

// refuseOnLeak is the gate. Each branch names what to fix, because whoever trips it is
// holding live credentials and needs to know whether to re-record or to delete a file.
func (r *Recorder) refuseOnLeak(name string, encoded []byte) {
	r.t.Helper()
	text := string(encoded)

	for _, secret := range r.known() {
		if strings.Contains(text, secret) {
			r.t.Fatalf("REFUSING TO WRITE %s: a credential this run already knows survived scrubbing. "+
				"Fix the rule in recorder.go before re-running; do not delete the check.", name)
		}
	}
	for _, rule := range r.rules {
		if match := rule.Shape.FindString(text); match != "" && !strings.Contains(match, redactedPrefix) {
			r.t.Fatalf("REFUSING TO WRITE %s: %s survived redaction (%q). The rule was supplied by "+
				"the caller, so fix it there rather than lowering the bar here.", name, rule.Label, match)
		}
	}
	for label, shape := range map[string]*regexp.Regexp{
		"an email address":           emailShaped,
		"a session cookie":           cookieShaped,
		"a prefixed secret":          prefixedSecretShaped,
		"a credential-bearing field": tokenFieldShaped,
		"a uuid":                     uuidShaped,
	} {
		if match := shape.FindString(text); match != "" && !strings.Contains(match, redactedPrefix) {
			r.t.Fatalf("REFUSING TO WRITE %s: %s survived redaction (%q). These recordings are "+
				"committed; extend the rule rather than lowering the bar.", name, label, match)
		}
	}
}
