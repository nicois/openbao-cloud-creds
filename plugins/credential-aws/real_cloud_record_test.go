//go:build cloud_real

package credentialaws

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// A real-cloud run is only worth its credentials if it leaves evidence behind.
// Every response the probe sees is written to testdata/cloud-real/ as a scrubbed
// recording, so that a shape mismatch is diagnosable after the fact (which
// element STS actually sends, not which one the plugin hoped for), and so the
// recordings become fixtures an ordinary credential-free `go test` can check the
// fake against — see fake_parity_test.go, which also owns the shared scrub
// regexes and re-applies every gate below to the committed files.
//
// Scrubbing is FAIL-CLOSED: if a credential or an account identifier survives
// into the bytes about to be written, the test fails instead of writing the file.
//
// AWS differs from the DO recorder in two ways worth knowing. STS is a single
// endpoint (`POST /`) with the operation named in the form body, so recordings are
// keyed by **Action** rather than by URL path. And responses are XML, so scrubbing
// is by element name and value shape rather than by structural JSON walk — with
// the secret elements redacted by NAME because the minted secret and session
// token are unknown until the very response being written: there is no substring
// to search for yet, which is precisely the case a value-based scrubber misses.

const (
	recordDirPerm  os.FileMode = 0o755
	recordFilePerm os.FileMode = 0o644

	// redactedFormat keeps the length — it tells us whether a field held a
	// credential at all — and nothing else.
	redactedFormat = redactedPrefix + "%d chars}"

	// redactedIdentifierFormat replaces an identifier rather than a secret, so it
	// keeps no length: length is diagnostically useful for "did the plugin read the
	// right field" and useless for an account number.
	redactedIdentifierFormat = redactedPrefix + "%s}"
)

// redactIdentifiers removes the account's identity from a value otherwise worth
// keeping: the shape of a response, minus whose account it is.
func redactIdentifiers(value string) string {
	value = accessKeyShaped.ReplaceAllString(value, fmt.Sprintf(redactedIdentifierFormat, "access-key-id"))
	value = principalShaped.ReplaceAllString(value, fmt.Sprintf(redactedIdentifierFormat, "principal-id"))
	return accountShaped.ReplaceAllString(value, fmt.Sprintf(redactedIdentifierFormat, "account-id"))
}

// recordingTransport records every response, then hands it back untouched.
type recordingTransport struct {
	t    *testing.T
	base http.RoundTripper

	// mu guards secrets, which grows as the probe learns them: a minted session
	// token is a secret only after AWS has answered with it. Element-name
	// redaction is what protects the response that first carries it; registering
	// it here protects every LATER recording that might echo it back.
	mu      sync.Mutex
	secrets []string
}

func newRecordingTransport(t *testing.T, secrets ...string) *recordingTransport {
	t.Helper()
	return &recordingTransport{t: t, base: http.DefaultTransport, secrets: secrets}
}

// addSecret registers a credential the probe has just been handed, so no
// subsequent recording can contain it in the clear.
func (rt *recordingTransport) addSecret(secret string) {
	if secret == "" {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.secrets = append(rt.secrets, secret)
}

func (rt *recordingTransport) knownSecrets() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return append([]string(nil), rt.secrets...)
}

// httpClient wraps the transport for injection into an sts.Options.HTTPClient.
func (rt *recordingTransport) httpClient() *http.Client {
	return &http.Client{Transport: rt}
}

// recordOption injects the recorder into ONE call on the plugin's own STS client,
// through the per-operation options the STSClient interface already exposes. That
// is what lets the probe drive the client the plugin builds — the same
// credentials, signing and decoding path — while still seeing the wire bytes.
func (rt *recordingTransport) recordOption() func(*sts.Options) {
	return func(o *sts.Options) { o.HTTPClient = rt.httpClient() }
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	action := actionOf(req)

	resp, err := rt.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}

	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if readErr != nil {
		rt.t.Logf("recorder could not read the response body for %s: %v", action, readErr)
		return resp, nil
	}

	rt.write(action, resp, body)
	return resp, nil
}

// actionOf reads the STS operation name out of the request's form body, leaving
// the body intact for the real round trip.
func actionOf(req *http.Request) string {
	if req.Body == nil {
		return "unknown"
	}
	raw, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		return "unknown"
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil || values.Get("Action") == "" {
		return "unknown"
	}
	return values.Get("Action")
}

// write assembles the recording and refuses to write a file that still leaks.
func (rt *recordingTransport) write(action string, resp *http.Response, body []byte) {
	recording := map[string]interface{}{
		"request":      map[string]string{"action": action},
		"status":       resp.StatusCode,
		"content_type": resp.Header.Get("Content-Type"),
		"body":         rt.scrubBody(body),
	}

	encoded, err := json.MarshalIndent(recording, "", "  ")
	if err != nil {
		rt.t.Logf("recorder could not encode the recording for %s: %v", action, err)
		return
	}
	encoded = append(encoded, '\n')

	// Fail closed. Nothing below this line may write a file that leaks.
	rt.refuseOnLeak(action, encoded)

	if err := os.MkdirAll(recordDir, recordDirPerm); err != nil {
		rt.t.Logf("recorder could not create %s: %v", recordDir, err)
		return
	}
	path := filepath.Join(recordDir, fmt.Sprintf("POST_%s_%d.json", action, resp.StatusCode))
	if err := os.WriteFile(path, encoded, recordFilePerm); err != nil {
		rt.t.Logf("recorder could not write %s: %v", path, err)
		return
	}
	rt.t.Logf("recorded %s -> %d in %s", action, resp.StatusCode, path)
}

// refuseOnLeak is the fail-closed gate. Each branch names what to fix, because
// the person who trips it is holding a live credential and needs to know whether
// to re-record or to delete a file.
func (rt *recordingTransport) refuseOnLeak(action string, encoded []byte) {
	for _, secret := range rt.knownSecrets() {
		if secret != "" && bytes.Contains(encoded, []byte(secret)) {
			rt.t.Fatalf("REFUSING TO WRITE %s: a credential survived scrubbing. The recorder needs the "+
				"element AWS used here before this run can leave evidence.", action)
		}
	}
	for _, element := range secretElements {
		for _, inner := range elementValues(string(encoded), element) {
			if !strings.HasPrefix(inner, redactedPrefix) {
				rt.t.Fatalf("REFUSING TO WRITE %s: <%s> is unredacted (%d chars), so a live credential "+
					"would reach a committed file.", action, element, len(inner))
			}
		}
	}
	for label, shape := range map[string]*regexp.Regexp{
		"AWS account id": accountShaped,
		"access key id":  accessKeyShaped,
		"principal id":   principalShaped,
	} {
		if match := shape.Find(encoded); match != nil {
			rt.t.Fatalf("REFUSING TO WRITE %s: a %s survived redaction (%q). Recordings are committed "+
				"to a public repo, so the account's identity must not reach one — extend "+
				"redactIdentifiers for whatever shape this is.", action, label, match)
		}
	}
}

// scrubBody redacts the XML body: credential-bearing elements by name, account
// identity by value shape, then any credential already known by substring.
func (rt *recordingTransport) scrubBody(body []byte) string {
	out := string(body)
	for _, element := range secretElements {
		out = redactElement(out, element)
	}
	out = redactIdentifiers(out)
	return scrubSecrets(out, rt.knownSecrets()...)
}

// redactElement replaces the text of every occurrence of an XML element with a
// length-preserving marker.
func redactElement(body, element string) string {
	shape := regexp.MustCompile(`(?s)<` + element + `>(.*?)</` + element + `>`)
	return shape.ReplaceAllStringFunc(body, func(match string) string {
		inner := shape.FindStringSubmatch(match)[1]
		return fmt.Sprintf("<%s>%s</%s>", element, fmt.Sprintf(redactedFormat, len(inner)), element)
	})
}

// scrubSecrets removes credentials from a string destined for a recording, a log
// line or a failure message. Upstream error bodies are echoed in this package's
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
