//go:build cloud_real

package credentialdo

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The recorder's fail-closed gates, tested. These need NO credentials and touch no
// network — they are named TestRealDO* only so the cloud_real make targets run them,
// because the recorder itself lives behind that tag and would otherwise be exercised
// exclusively by the runs whose evidence it is supposed to be safe to commit.
//
// What they exist for: recordings go to a PUBLIC repository, and the Spaces mint
// response carries a credential whose field name the recorder cannot know in advance.
// The generic rules (redactKeys, the dop_v1_ prefix, the uuid/email shapes) only catch
// what was anticipated, so the probe registers the secret it just learned and the
// recording is withheld until then. That mechanism is the difference between a leaked
// key and a refused write, so it does not get to be untested.

// spacesSecretShaped stands in for a real Spaces secret: 43 characters of base64, in no
// documented format the scrubber could recognise by shape. That is the whole point — an
// unanticipated credential is caught by REGISTRATION, not by pattern matching.
const spacesSecretShaped = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

func TestRealDORecorderWithholdsARecordingUntilTheSecretIsKnown(t *testing.T) {
	rt := testRecorder(t)
	body := []byte(`{"key":{"name":"cloud-creds-probe","mystery_field":"` + spacesSecretShaped + `"}}`)

	rt.withhold()
	rt.record(recorderRequest(t, http.MethodPost, spacesKeysPath), recorderResponse(http.StatusCreated), body)

	if names := recordedFiles(t, rt.dir); len(names) != 0 {
		t.Fatalf("a withheld recording was written anyway (%v): the secret was not yet known, so "+
			"the bytes on disk could not have been checked against it", names)
	}

	if err := rt.release(spacesSecretShaped); err != nil {
		t.Fatalf("release with the secret registered should write the recording, got: %v", err)
	}
	recorded := onlyRecording(t, rt.dir)
	if strings.Contains(recorded, spacesSecretShaped) {
		t.Error("the secret survived into the recording even though it was registered before release")
	}
	if !strings.Contains(recorded, "redacted") {
		t.Errorf("the secret's field was dropped rather than redacted, so the recording no longer "+
			"shows the response's shape:\n%s", recorded)
	}
}

func TestRealDORecorderRefusesToWriteACredentialItWasNeverTold(t *testing.T) {
	rt := testRecorder(t)
	// A NON-JSON body, because that is where the structural rules cannot help: inside JSON
	// a token-shaped value is redacted wherever it appears, but an HTML or plain-text error
	// page — which DigitalOcean's edge does return — is scrubbed only by substring against
	// the secrets the recorder was told about. So this is the shape where the final gate is
	// the only thing left, and a PAT-shaped string stands in for the credential nobody
	// registered.
	body := []byte("<html><body>request denied for " + doTokenPrefix + "abc123</body></html>")

	rt.withhold()
	rt.record(recorderRequest(t, http.MethodPost, tokensPath), recorderResponse(http.StatusForbidden), body)

	err := rt.release()
	if err == nil {
		t.Fatal("release wrote a recording containing a token-shaped string: the gate must REFUSE " +
			"rather than write, since a leaked credential in testdata/ is worse than a missing fixture")
	}
	if !strings.Contains(err.Error(), doTokenPrefix) {
		t.Errorf("the refusal does not say what it found, so nobody can extend the rules: %v", err)
	}
	if names := recordedFiles(t, rt.dir); len(names) != 0 {
		t.Errorf("the write was refused but files exist: %v", names)
	}
}

// TestRealDORecorderRedactsSpacesKeyMaterialByKeyName is the defence in depth: the
// probe's registration is what catches an unexpected field, and these are the fields
// DigitalOcean's documented shape uses, so a recording must be safe even if a future
// caller forgets to withhold.
func TestRealDORecorderRedactsSpacesKeyMaterialByKeyName(t *testing.T) {
	rt := testRecorder(t)
	body := []byte(`{"key":{"access_key":"DO00PROBEACCESSKEY","secret_key":"` + spacesSecretShaped +
		`","grants":[{"bucket":"acme-corp-backups","permission":"read"}]}}`)

	rt.record(recorderRequest(t, http.MethodGet, spacesKeysPath), recorderResponse(http.StatusOK), body)

	recorded := onlyRecording(t, rt.dir)
	for _, leaked := range []string{spacesSecretShaped, "DO00PROBEACCESSKEY", "acme-corp-backups"} {
		if strings.Contains(recorded, leaked) {
			t.Errorf("%q reached the recording. A Spaces secret is a credential, an access key is "+
				"half of one and identifies the account, and a bucket name is the account's own "+
				"data — none of them is what a fixture is for.\n%s", leaked, recorded)
		}
	}
	if !strings.Contains(recorded, "read") {
		t.Errorf("the grant's PERMISSION was redacted too, which is the part a fixture needs:\n%s", recorded)
	}
}

// TestRealDORecorderKeepsAnAccessKeyOutOfTheRecordedPath covers the one place a
// credential travels OUTSIDE a JSON body: a Spaces key is deleted by its access key, so
// the id is in the URL, and a URL is not something the structural redaction can reach.
// The uuid gate caught the token case (A29); an access key is not uuid-shaped and would
// have gone straight to disk, in the filename as well as the body.
func TestRealDORecorderKeepsAnAccessKeyOutOfTheRecordedPath(t *testing.T) {
	rt := testRecorder(t)
	const accessKey = "DO00PROBE123ACCESSKEY"

	rt.record(recorderRequest(t, http.MethodDelete, spacesKeysPath+"/"+accessKey),
		recorderResponse(http.StatusNoContent), nil)

	names := recordedFiles(t, rt.dir)
	if len(names) != 1 {
		t.Fatalf("expected one recording, found %v", names)
	}
	if strings.Contains(names[0], accessKey) {
		t.Errorf("the access key is in the FILENAME %q, so it would be committed as a path in the "+
			"repository even if the file's contents were clean", names[0])
	}
	recorded := onlyRecording(t, rt.dir)
	if strings.Contains(recorded, accessKey) {
		t.Errorf("the access key reached the recording:\n%s", recorded)
	}
	// The route itself must survive, or the recording stops saying which endpoint answered.
	if !strings.Contains(recorded, spacesKeysPath) {
		t.Errorf("the route was collapsed along with the id, leaving nothing to identify the "+
			"call:\n%s", recorded)
	}
}

func testRecorder(t *testing.T) *recordingTransport {
	t.Helper()
	rt := newRecordingTransport(t)
	// Never the committed fixture directory: a test recording landing there would be a
	// recording no real run produced, which fake_parity_test.go would then demand an
	// assertion for.
	rt.dir = t.TempDir()
	return rt
}

func recorderRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, realDOBaseURL+path, http.NoBody)
	if err != nil {
		t.Fatalf("building the request failed: %v", err)
	}
	return req
}

func recorderResponse(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{headerResponder: []string{responderService}},
	}
}

func recordedFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("cannot read %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func onlyRecording(t *testing.T, dir string) string {
	t.Helper()
	names := recordedFiles(t, dir)
	if len(names) != 1 {
		t.Fatalf("expected exactly one recording in %s, found %v", dir, names)
	}
	raw, err := os.ReadFile(filepath.Join(dir, names[0]))
	if err != nil {
		t.Fatalf("cannot read the recording: %v", err)
	}
	return string(raw)
}
