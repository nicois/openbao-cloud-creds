package credentialdo

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// Fixture parity: the DO fake answers for real DigitalOcean, so where a real
// response has been recorded (real_cloud_test.go, build tag cloud_real), this
// ORDINARY credential-free test holds the fake to it. That is what turns one
// privileged run into permanent coverage — see docs/free-account-viability.md.
//
// Every recording must be either asserted here or listed in unassertable with a
// reason, so adding a recording forces a decision instead of quietly sitting
// unused — the same declared-gap discipline as Harness.Skips.

const (
	parityRecordDir = "testdata/cloud-real"
	tokensPath      = "/v2/tokens"
	jsonContentType = "application/json"
	mintRequestBody = `{"name":"parity-probe","scopes":["account:read"]}`
)

// The responder constants. DigitalOcean states which layer answered a request in
// this header: a request that reached DigitalOcean's backend says "service", and
// one the edge decided by itself says "Edge-Gateway". That single difference is
// what separates "your token lacks a privilege" (a service verdict) from "this
// path is not open to API tokens at all" (an edge verdict) — the distinction
// KI-009 rests on, and one no status code can express.
//
// They live HERE, in the untagged file, rather than with the probe that asserts
// on them: this test reads the value back out of the recordings, so it has to
// compile without the cloud_real tag.
const (
	headerResponder     = "X-Response-From"
	responderEdge       = "Edge-Gateway"
	responderService    = "service"
	responderUnobserved = "(no " + headerResponder + " header)"
)

// recordedResponse is the on-disk shape written by recordingTransport.write.
type recordedResponse struct {
	Request struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	} `json:"request"`
	Status      int         `json:"status"`
	RespondedBy string      `json:"responded_by"`
	Body        interface{} `json:"body"`
}

// unassertable names recordings the fake is deliberately not held to, with the
// reason. A reason must be about the fake's design, not about effort.
var unassertable = map[string]string{
	"GET_v2_account_403.json": "the fake's only 403 on /v2/account is SetNextStatus, an INJECTED error " +
		"({\"id\":\"server_error\"}) that makes no claim about DO's wire format; the real 403 here comes " +
		"from a scoped PAT, a state the fake has no knob for and no plugin behaviour depends on " +
		"(docs/do-api-verification-2026-08-21.md R2). Recorded before the responder header was " +
		"captured, and not reproducible now the probe account's PAT is full-access",
	"GET_v2_tokens_403.json": "same: the fake reaches 403 on list only via the injected-error knob, " +
		"whose body is deliberately synthetic",
	"GET_v2_account_200.json": "nothing decodes this body — doClient.CheckHealth discards it and " +
		"returns the status alone — so byte equality would assert on one account's droplet limits and " +
		"nothing the plugin depends on. It is kept as the CONTROL for KI-009: same token, answered by " +
		responderService + ", which is what makes the " + responderEdge + " 403s a statement about the " +
		"path rather than about the credential (asserted by TestRecordedEvidenceForFencedTokenEndpoint)",
}

func TestDOFakeMatchesRecordedRealResponses(t *testing.T) {
	entries, err := os.ReadDir(parityRecordDir)
	if err != nil {
		t.Fatalf("cannot read %s: %v\nRecordings are committed; a missing directory means they were "+
			"deleted, not that there are none.", parityRecordDir, err)
	}

	asserted := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		if reason, skipped := unassertable[name]; skipped {
			t.Logf("not asserted: %s — %s", name, reason)
			continue
		}

		recorded := readRecording(t, name)
		switch {
		case recorded.Request.Method == http.MethodPost &&
			recorded.Request.Path == tokensPath &&
			recorded.Status == http.StatusForbidden:
			fakeStatus, fakeBody := fakeMintForbiddenBody(t)
			assertFakeBody(t, name, recorded, fakeStatus, fakeBody)
			asserted++
		default:
			t.Errorf("recording %s is neither asserted nor listed in unassertable. Either drive the "+
				"fake to produce this response and compare, or say in unassertable why the fake is not "+
				"answerable for it.", name)
		}
	}

	if asserted == 0 {
		t.Error("no recording was asserted against the fake: this test would pass with a fake that " +
			"resembles nothing")
	}
}

// TestRecordedEvidenceForFencedTokenEndpoint pins KI-009's evidence in an
// ORDINARY, credential-free run. It does not re-prove the fence — only
// `make test-cloud-real-do` can do that, against live DO — it guards the recorded
// proof from being edited into something that no longer supports the conclusion
// drawn from it. The conclusion is comparative, so both halves are checked: the
// same PAT is served by DigitalOcean's backend on /v2/account and refused by its
// EDGE on /v2/tokens. Without the first half the second is just a permissions
// error; with it, the path itself is closed to API tokens.
//
// The plugin's own error handling is nonetheless held to the edge's body
// (POST_v2_tokens_403 above), because that body is what an operator's minter
// really receives — the fake stands in for what DO answers, not for what DO
// documents.
func TestRecordedEvidenceForFencedTokenEndpoint(t *testing.T) {
	control := readRecording(t, "GET_v2_account_200.json")
	if control.Status != http.StatusOK || control.RespondedBy != responderService {
		t.Errorf("the control recording no longer shows a working, backend-served call: %s -> %d by "+
			"%q, want 200 by %q. KI-009's reasoning depends on the SAME token succeeding elsewhere.",
			control.Request.Path, control.Status, control.RespondedBy, responderService)
	}

	for _, name := range []string{"GET_v2_tokens_403.json", "POST_v2_tokens_403.json"} {
		recorded := readRecording(t, name)
		if recorded.Request.Path != tokensPath {
			t.Errorf("%s: records %q, not %s", name, recorded.Request.Path, tokensPath)
		}
		if recorded.Status != http.StatusForbidden {
			t.Errorf("%s: records %d, want %d", name, recorded.Status, http.StatusForbidden)
		}
		if recorded.RespondedBy != responderEdge {
			t.Errorf("%s: %s is %q, want %q. If the refusal was not from the edge then it was a "+
				"privilege decision, and KI-009 ('no PAT can mint') does not follow from it — a "+
				"differently-privileged credential might pass. Re-run make test-cloud-real-do.",
				name, headerResponder, recorded.RespondedBy, responderEdge)
		}
	}
}

// fakeMintForbiddenBody drives the fake to the one state whose real counterpart is
// recorded: a minter that authenticates but may not manage tokens.
func fakeMintForbiddenBody(t *testing.T) (status int, body interface{}) {
	t.Helper()
	server := fakes.NewDOServer()
	defer server.Close()
	server.SetForbidCreate(true)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+tokensPath,
		strings.NewReader(mintRequestBody))
	if err != nil {
		t.Fatalf("building the request failed: %v", err)
	}
	req.Header.Set("Content-Type", jsonContentType)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("posting to the fake failed: %v", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the fake's body failed: %v", err)
	}
	var decoded interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("the fake returned non-JSON (%q): %v", string(raw), err)
	}
	return resp.StatusCode, decoded
}

func assertFakeBody(t *testing.T, name string, recorded recordedResponse, fakeStatus int, fakeBody interface{}) {
	t.Helper()
	if fakeStatus != recorded.Status {
		t.Errorf("%s: fake answered %d, real DO answered %d", name, fakeStatus, recorded.Status)
	}
	if !reflect.DeepEqual(fakeBody, recorded.Body) {
		t.Errorf("%s: the fake's body does not match what real DO sent.\n  fake: %s\n  real: %s\n"+
			"A fake that invents friendlier errors is a fake whose error handling is untested.",
			name, mustJSON(t, fakeBody), mustJSON(t, recorded.Body))
	}
}

func readRecording(t *testing.T, name string) recordedResponse {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(parityRecordDir, name))
	if err != nil {
		t.Fatalf("cannot read recording %s: %v", name, err)
	}
	var recorded recordedResponse
	if err := json.Unmarshal(raw, &recorded); err != nil {
		t.Fatalf("recording %s is not the shape recordingTransport writes: %v", name, err)
	}
	return recorded
}

func mustJSON(t *testing.T, value interface{}) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("cannot re-encode for the failure message: %v", err)
	}
	return string(encoded)
}
