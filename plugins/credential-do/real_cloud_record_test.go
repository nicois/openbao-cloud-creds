//go:build cloud_real

package credentialdo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// A real-cloud run is only worth its credentials if it leaves evidence behind.
// Every response the probe sees is written to testdata/cloud-real/ as a scrubbed
// recording, so that:
//
//   - a shape mismatch is diagnosable after the fact (which field DO actually
//     sends, not which field the plugin hoped for);
//   - the recordings become fixtures an ORDINARY, credential-free `go test` can
//     check the cloud fake against — the fixture-parity idea in
//     docs/free-account-viability.md. One privileged run, a permanent test.
//
// Scrubbing is FAIL-CLOSED: if a secret survives into the bytes about to be
// written, the test fails instead of writing the file. A leaked PAT in testdata/
// would be worse than the gap this whole layer closes.

const (
	// recordDir is relative to the package dir, so recordings live with the
	// plugin whose client produced them.
	recordDir = "testdata/cloud-real"

	recordDirPerm  os.FileMode = 0o755
	recordFilePerm os.FileMode = 0o644

	// redactedFormat keeps the length (useful — it tells us whether a field held
	// a credential) and nothing else.
	redactedFormat = "<redacted:%d chars>"

	// doTokenPrefix is DigitalOcean's public, non-secret PAT prefix. Any string
	// carrying it is a credential by construction.
	doTokenPrefix = "dop_v1_"

	// idSegmentMinLen is when a path segment starts looking like an entity id
	// rather than a route, so recordings get stable filenames across runs.
	idSegmentMinLen = 8
)

// redactKeys are JSON object keys whose string values are always credentials.
//
// `secret_key` and `access_key` are the Spaces mint response's two halves. The secret is
// plainly a credential; the access key is redacted too because it is the other half of
// one and it identifies the account's key, and nothing a fixture asserts needs its value
// — only that the field was populated, which the recorded length still shows.
//
// This is defence in depth rather than the primary control: a field name DigitalOcean
// uses that is not listed here would be missed, which is why the Spaces probe withholds
// its recordings and registers the secret it actually received (see withhold/release).
var redactKeys = map[string]bool{
	"access_token":  true,
	"refresh_token": true,
	"token":         true,
	"secret":        true,
	"secret_key":    true,
	"access_key":    true,
	"password":      true,
}

// redactIdentifierKeys are keys whose values are neither credentials nor protocol, but
// the account's own data. A bucket name is the clearest case: a Spaces listing carries
// the names of every bucket a key is granted on, which in a real account names what the
// account stores — and no fixture is about that. The permission beside it is exactly the
// part worth keeping, so the redaction is per-key rather than per-object.
var redactIdentifierKeys = map[string]bool{
	"bucket": true,
}

// Recordings are COMMITTED, to a public repository, and a real cloud account
// answers with more than protocol: /v2/account returns the owner's email address
// (twice — DO uses it as the account `name` too) and the account and team UUIDs.
// None of that is a credential, so the secret rules above do not see it, and none
// of it is what a fixture is for. Both are therefore handled by value shape rather
// than by key, since the same value arrives under keys we cannot enumerate ahead
// of a response we have not seen.
var (
	emailShaped = regexp.MustCompile(`[\w.+%-]+@[\w-]+\.[\w.-]+`)
	// No \b anchors: in a recording the UUID sits inside JSON-escaped XML
	// (`\u003e24027357-...`), and `\u003e` ENDS in a word character, so a leading
	// word boundary never matches and the rule silently found nothing. Copied from
	// the DO recorder, where UUIDs sit in quoted JSON values and the anchors did
	// work — a guard carried across without checking it still applies, which is the
	// audit's own cross-cutting finding happening inside the fix for it.
	// Over-matching is the safe direction for a scrubber.
	uuidShaped = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
)

// redactedIdentifier replaces an account identifier. Unlike a credential it keeps
// no length: length is diagnostically useful for "did the plugin read the right
// field", and useless here.
const redactedIdentifier = "<redacted:%s>"

// recordingTransport records every response, then hands it back untouched.
type recordingTransport struct {
	t    *testing.T
	base http.RoundTripper
	// dir is where recordings land. A field rather than the recordDir constant so a test
	// of the recorder itself cannot write into the committed fixture set.
	dir string

	// mu guards everything below it: responders remembers which layer of DO answered
	// each call (the plugin's client returns a decoded body and a status, not headers, so
	// this is how an assertion downstream of a doClient method can still ask "who refused
	// this?" — the question the fence finding turns on), while secrets and the withheld
	// queue are both mutated by release() from the test goroutine while a transport call
	// may still be in flight.
	mu         sync.Mutex
	responders map[string]string
	secrets    []string
	holding    bool
	withheld   []withheldRecording
}

// withheldRecording is a response held back until the credential it carries is known.
// The body is kept RAW: scrubbing has to happen after release registers the secret,
// otherwise the secret would already be baked into the scrubbed copy.
type withheldRecording struct {
	method      string
	path        string
	status      int
	contentType string
	responder   string
	body        []byte
}

func newRecordingTransport(t *testing.T, secrets ...string) *recordingTransport {
	t.Helper()
	return &recordingTransport{
		t:          t,
		base:       http.DefaultTransport,
		dir:        recordDir,
		secrets:    secrets,
		responders: make(map[string]string),
	}
}

// withhold stops writing recordings and queues them instead.
//
// It exists for a call whose response carries a credential the recorder cannot name in
// advance: the Spaces mint returns key material, and while the documented field names are
// in redactKeys, a name DigitalOcean uses that we have not seen would sail straight
// through every generic rule into a file destined for a public repository. Holding the
// bytes until the caller has decoded the response and can say "this exact string is a
// secret" converts that from an unbounded guess into a check against the real value.
func (rt *recordingTransport) withhold() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.holding = true
}

// release registers the now-known secrets, writes everything withheld, and resumes
// ordinary recording. The error is the fail-closed refusal — a caller that gets one has
// evidence it cannot publish, which is a finding about the redaction rules and not a
// reason to write the file anyway.
func (rt *recordingTransport) release(secrets ...string) error {
	rt.mu.Lock()
	rt.secrets = append(rt.secrets, secrets...)
	queued := rt.withheld
	rt.withheld = nil
	rt.holding = false
	rt.mu.Unlock()

	var refusals []error
	for _, recording := range queued {
		if err := rt.emit(recording); err != nil {
			refusals = append(refusals, err)
		}
	}
	return errors.Join(refusals...)
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	rt.mu.Lock()
	rt.responders[responderKey(req.Method, req.URL.Path)] = responderOf(resp)
	rt.mu.Unlock()

	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if readErr != nil {
		rt.t.Logf("recorder could not read the response body for %s %s: %v",
			req.Method, req.URL.Path, readErr)
		return resp, nil
	}

	rt.record(req, resp, body)
	return resp, nil
}

// record either queues the response (see withhold) or writes it now. A refusal on the
// immediate path is fatal: it means bytes that must not be committed were produced by a
// call nobody arranged to withhold, and continuing would produce more of them.
func (rt *recordingTransport) record(req *http.Request, resp *http.Response, body []byte) {
	recording := withheldRecording{
		method:      req.Method,
		path:        req.URL.Path,
		status:      resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
		responder:   responderOf(resp),
		body:        body,
	}

	rt.mu.Lock()
	holding := rt.holding
	if holding {
		rt.withheld = append(rt.withheld, recording)
	}
	rt.mu.Unlock()
	if holding {
		return
	}

	if err := rt.emit(recording); err != nil {
		rt.t.Fatal(err)
	}
}

// emit assembles the recording and refuses to write a file that still contains a secret.
// The refusal is an error rather than a t.Fatalf so that release can report it to the
// caller that knows what was being recorded — and so these gates are themselves testable.
func (rt *recordingTransport) emit(recording withheldRecording) error {
	rt.mu.Lock()
	secrets := append([]string(nil), rt.secrets...)
	rt.mu.Unlock()

	body := map[string]any{
		"request": map[string]string{
			"method": recording.method,
			// The COLLAPSED path, not the raw one. A DELETE addresses a credential by id —
			// a token uuid, or a Spaces ACCESS KEY, which is half a credential — and a path
			// is not JSON, so the structural redaction never sees it. Collapsing here means
			// the filename and the recorded path agree by construction, and the uuid gate
			// below is left as a backstop rather than the only thing standing between an id
			// and a public repository (A29).
			"path": sanitizedPath(recording.path),
		},
		"status":       recording.status,
		"content_type": recording.contentType,
		"responded_by": recording.responder,
		"body":         scrubBody(recording.body, secrets),
	}

	encoded, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		rt.t.Logf("recorder could not encode the recording for %s %s: %v",
			recording.method, recording.path, err)
		return nil
	}
	encoded = append(encoded, '\n')

	// Fail closed. Nothing below this line may write a file that leaks.
	for _, secret := range secrets {
		if secret != "" && bytes.Contains(encoded, []byte(secret)) {
			return fmt.Errorf("REFUSING TO WRITE %s %s: a credential survived scrubbing. The "+
				"recorder's redaction rules need the field DO used here before this run can leave "+
				"evidence.", recording.method, recording.path)
		}
	}
	if bytes.Contains(encoded, []byte(doTokenPrefix)) {
		return fmt.Errorf("REFUSING TO WRITE %s %s: the bytes contain %q, so something token-shaped "+
			"is unredacted", recording.method, recording.path, doTokenPrefix)
	}
	if match := uuidShaped.Find(encoded); match != nil {
		return fmt.Errorf("REFUSING TO WRITE %s %s: a UUID survived redaction (%q). "+
			"redactIdentifiers replaces UUIDs in JSON string VALUES, but a request path is written "+
			"raw — so a DELETE /v2/tokens/<uuid> recording would have committed it (A29).",
			recording.method, recording.path, match)
	}
	if match := emailShaped.Find(encoded); match != nil {
		return fmt.Errorf("REFUSING TO WRITE %s %s: an email address survived redaction (%d chars). "+
			"Recordings are committed to a public repo, so the account owner's identity must not "+
			"reach one — extend redactIdentifiers for whatever shape this is.",
			recording.method, recording.path, len(match))
	}

	if err := os.MkdirAll(rt.dir, recordDirPerm); err != nil {
		rt.t.Logf("recorder could not create %s: %v", rt.dir, err)
		return nil
	}
	path := filepath.Join(rt.dir, recordingName(recording))
	if err := os.WriteFile(path, encoded, recordFilePerm); err != nil {
		rt.t.Logf("recorder could not write %s: %v", path, err)
		return nil
	}
	rt.t.Logf("recorded %s %s -> %d in %s", recording.method, recording.path, recording.status, path)
	return nil
}

// scrubBody redacts credentials structurally where the body is JSON, and by
// substring where it is not. The secrets are passed in rather than read off the
// transport because release can extend them while a call is in flight.
func scrubBody(body []byte, secrets []string) any {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return redactIdentifiers(scrubSecrets(string(body), secrets...))
	}
	return scrubValue(parsed, "", secrets)
}

func scrubValue(value any, key string, secrets []string) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			out[k] = scrubValue(v, k, secrets)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, v := range typed {
			out[i] = scrubValue(v, key, secrets)
		}
		return out
	case string:
		lowered := strings.ToLower(key)
		if redactKeys[lowered] || strings.Contains(typed, doTokenPrefix) ||
			containsAny(typed, secrets) {
			return fmt.Sprintf(redactedFormat, len(typed))
		}
		if redactIdentifierKeys[lowered] {
			return fmt.Sprintf(redactedIdentifier, lowered)
		}
		return redactIdentifiers(typed)
	default:
		return value
	}
}

// responderOf records WHICH layer of DigitalOcean answered — see headerResponder.
// It is the one response header worth keeping: for /v2/tokens it is the whole
// evidence that the 403 comes from DO's edge gateway rather than from a service
// weighing the token's privileges, and a body alone cannot show that. Recorded
// rather than merely asserted so the finding outlives this run (KI-009).
func responderOf(resp *http.Response) string {
	if responder := resp.Header.Get(headerResponder); responder != "" {
		return responder
	}
	return responderUnobserved
}

// redactIdentifiers removes the account's identity from a value that is otherwise
// worth keeping: the shape of a response, minus who it belongs to.
func redactIdentifiers(value string) string {
	value = emailShaped.ReplaceAllString(value, fmt.Sprintf(redactedIdentifier, "email"))
	return uuidShaped.ReplaceAllString(value, fmt.Sprintf(redactedIdentifier, "uuid"))
}

func responderKey(method, path string) string { return method + " " + path }

// responderSeen reports which layer answered the client's own last call to
// method+path — so the fence assertion is made about the POST DO actually
// refused, not about a similar-looking GET issued afterwards.
func responderSeen(client *doClient, method, path string) string {
	rt, ok := client.httpClient.Transport.(*recordingTransport)
	if !ok {
		return responderUnobserved
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if responder, seen := rt.responders[responderKey(method, path)]; seen {
		return responder
	}
	return responderUnobserved
}

// recordingName gives a stable, self-describing filename: entity ids in the path
// are collapsed so the same call records to the same file on every run.
func recordingName(recording withheldRecording) string {
	path := strings.ReplaceAll(strings.Trim(sanitizedPath(recording.path), "/"), "/", "_")
	return fmt.Sprintf("%s_%s_%d.json", recording.method, path, recording.status)
}

// sanitizedPath replaces entity ids with a placeholder, so the same call records to the
// same file on every run AND so an id never reaches the recording.
func sanitizedPath(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if looksLikeID(segment) {
			segments[i] = "id"
		}
	}
	return strings.Join(segments, "/")
}

// looksLikeID recognises the two id shapes this plugin's paths carry: a token uuid
// (lower-case hex and dashes) and a Spaces access key (upper-case alphanumeric, always
// containing digits — DigitalOcean's begin `DO00`). Route segments are lower-case words,
// so the upper-case rule cannot swallow one; the length floor keeps it off short ones.
func looksLikeID(segment string) bool {
	if len(segment) < idSegmentMinLen {
		return false
	}
	hex, upper, digits := true, true, false
	for _, r := range segment {
		digit := r >= '0' && r <= '9'
		digits = digits || digit
		hex = hex && (digit || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '-')
		upper = upper && (digit || (r >= 'A' && r <= 'Z'))
	}
	return hex || (upper && digits)
}

func containsAny(value string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

// scrubSecrets removes credentials from a string destined for a log line or a
// failure message. Upstream error bodies are echoed verbatim in this package's
// errors, and a 4xx body can quote the request.
func scrubSecrets(value string, secrets ...string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		value = strings.ReplaceAll(value, secret, fmt.Sprintf(redactedFormat, len(secret)))
	}
	return value
}
