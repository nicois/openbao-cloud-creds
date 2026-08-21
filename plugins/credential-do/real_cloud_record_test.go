//go:build cloud_real

package credentialdo

import (
	"bytes"
	"encoding/json"
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
var redactKeys = map[string]bool{
	"access_token":  true,
	"refresh_token": true,
	"token":         true,
	"secret":        true,
	"password":      true,
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
	uuidShaped  = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
)

// redactedIdentifier replaces an account identifier. Unlike a credential it keeps
// no length: length is diagnostically useful for "did the plugin read the right
// field", and useless here.
const redactedIdentifier = "<redacted:%s>"

// recordingTransport records every response, then hands it back untouched.
type recordingTransport struct {
	t       *testing.T
	base    http.RoundTripper
	secrets []string

	// mu guards responders, which remembers which layer of DO answered each
	// call. The plugin's client returns a decoded body and a status, not headers,
	// so this is how an assertion downstream of a doClient method can still ask
	// "who refused this?" — the question the fence finding turns on.
	mu         sync.Mutex
	responders map[string]string
}

func newRecordingTransport(t *testing.T, secrets ...string) *recordingTransport {
	t.Helper()
	return &recordingTransport{
		t:          t,
		base:       http.DefaultTransport,
		secrets:    secrets,
		responders: make(map[string]string),
	}
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

	rt.write(req, resp, body)
	return resp, nil
}

// write assembles the recording and refuses to write a file that still contains a
// secret.
func (rt *recordingTransport) write(req *http.Request, resp *http.Response, body []byte) {
	recording := map[string]interface{}{
		"request": map[string]string{
			"method": req.Method,
			"path":   req.URL.Path,
		},
		"status":       resp.StatusCode,
		"content_type": resp.Header.Get("Content-Type"),
		"responded_by": responderOf(resp),
		"body":         rt.scrubBody(body),
	}

	encoded, err := json.MarshalIndent(recording, "", "  ")
	if err != nil {
		rt.t.Logf("recorder could not encode the recording for %s %s: %v",
			req.Method, req.URL.Path, err)
		return
	}
	encoded = append(encoded, '\n')

	// Fail closed. Nothing below this line may write a file that leaks.
	for _, secret := range rt.secrets {
		if secret != "" && bytes.Contains(encoded, []byte(secret)) {
			rt.t.Fatalf("REFUSING TO WRITE %s %s: a credential survived scrubbing. The recorder's "+
				"redaction rules need the field DO used here before this run can leave evidence.",
				req.Method, req.URL.Path)
		}
	}
	if bytes.Contains(encoded, []byte(doTokenPrefix)) {
		rt.t.Fatalf("REFUSING TO WRITE %s %s: the bytes contain %q, so something token-shaped is "+
			"unredacted", req.Method, req.URL.Path, doTokenPrefix)
	}
	if match := emailShaped.Find(encoded); match != nil {
		rt.t.Fatalf("REFUSING TO WRITE %s %s: an email address survived redaction (%d chars). "+
			"Recordings are committed to a public repo, so the account owner's identity must not "+
			"reach one — extend redactIdentifiers for whatever shape this is.",
			req.Method, req.URL.Path, len(match))
	}

	if err := os.MkdirAll(recordDir, recordDirPerm); err != nil {
		rt.t.Logf("recorder could not create %s: %v", recordDir, err)
		return
	}
	path := filepath.Join(recordDir, recordingName(req, resp.StatusCode))
	if err := os.WriteFile(path, encoded, recordFilePerm); err != nil {
		rt.t.Logf("recorder could not write %s: %v", path, err)
		return
	}
	rt.t.Logf("recorded %s %s -> %d in %s", req.Method, req.URL.Path, resp.StatusCode, path)
}

// scrubBody redacts credentials structurally where the body is JSON, and by
// substring where it is not.
func (rt *recordingTransport) scrubBody(body []byte) interface{} {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return redactIdentifiers(scrubSecrets(string(body), rt.secrets...))
	}
	return rt.scrubValue(parsed, "")
}

func (rt *recordingTransport) scrubValue(value interface{}, key string) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for k, v := range typed {
			out[k] = rt.scrubValue(v, k)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i, v := range typed {
			out[i] = rt.scrubValue(v, key)
		}
		return out
	case string:
		if redactKeys[strings.ToLower(key)] || strings.Contains(typed, doTokenPrefix) ||
			containsAny(typed, rt.secrets) {
			return fmt.Sprintf(redactedFormat, len(typed))
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
func recordingName(req *http.Request, status int) string {
	segments := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	for i, segment := range segments {
		if looksLikeID(segment) {
			segments[i] = "id"
		}
	}
	return fmt.Sprintf("%s_%s_%d.json", req.Method, strings.Join(segments, "_"), status)
}

// looksLikeID is a filename heuristic, not a security control.
func looksLikeID(segment string) bool {
	if len(segment) < idSegmentMinLen {
		return false
	}
	for _, r := range segment {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex && r != '-' {
			return false
		}
	}
	return true
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
