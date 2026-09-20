package credentialdo

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
	spacesKeysPath  = "/v2/spaces/keys"
	jsonContentType = "application/json"
	mintRequestBody = `{"name":"parity-probe","scopes":["account:read"]}`
	// The grant is per-bucket because an account-wide one is expressed as an EMPTY bucket,
	// which would leave `grants[].bucket` out of the shape entirely.
	spacesCreateRequestBody = `{"name":"parity-probe","grants":[{"bucket":"parity","permission":"read"}]}`
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
	Status      int    `json:"status"`
	RespondedBy string `json:"responded_by"`
	Body        any    `json:"body"`
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
		// The Spaces recordings are compared by SHAPE, not bytes — see
		// TestJSONShapeDescribesFieldsAndTypes. They appear the first time
		// `make test-cloud-real-do-spaces` runs; until then these branches are the
		// standing arrangement that a run's evidence is checked rather than filed.
		case recorded.Request.Method == http.MethodPost &&
			recorded.Request.Path == spacesKeysPath &&
			recorded.Status == http.StatusCreated:
			fakeStatus, fakeBody := fakeSpacesKeyCreate(t)
			assertFakeShape(t, name, recorded, fakeStatus, fakeBody)
			asserted++
		case recorded.Request.Method == http.MethodGet &&
			recorded.Request.Path == spacesKeysPath &&
			recorded.Status == http.StatusOK:
			fakeStatus, fakeBody := fakeSpacesKeyList(t)
			assertFakeShape(t, name, recorded, fakeStatus, fakeBody)
			asserted++
		case recorded.Request.Method == http.MethodDelete &&
			strings.HasPrefix(recorded.Request.Path, spacesKeysPath+"/") &&
			recorded.Status == http.StatusNoContent:
			fakeStatus, fakeBody := fakeSpacesKeyDelete(t)
			assertFakeShape(t, name, recorded, fakeStatus, fakeBody)
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

// TestJSONShapeDescribesFieldsAndTypes covers the comparison the Spaces recordings need.
//
// The token recordings are compared byte for byte, because an error body is entirely
// protocol. A Spaces recording cannot be: its values are the account's own — a redacted
// access key, a real created_at, whatever buckets the account has — so what the fake is
// answerable for is the SHAPE. That is also the part that actually breaks things: a
// mint response whose secret arrives under a different key hands out an empty credential,
// and no assertion on values would notice while an assertion on shape does.
func TestJSONShapeDescribesFieldsAndTypes(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  []string
	}{
		{
			name: "nested objects and arrays",
			value: mustDecode(t, `{"key":{"name":"probe","access_key":"DO00X","grants":`+
				`[{"bucket":"b","permission":"read"}]}}`),
			want: []string{
				"key.access_key: string",
				"key.grants[].bucket: string",
				"key.grants[].permission: string",
				"key.name: string",
			},
		},
		{
			// The envelope is the whole point of one of the assumptions being pinned: a
			// listing under any other key decodes as empty and reclaims nothing.
			name:  "list envelope",
			value: mustDecode(t, `{"keys":[{"name":"probe"}]}`),
			want:  []string{"keys[].name: string"},
		},
		{
			// A type change is a shape change: created_at as a number would not parse, and
			// the reconciler's confirmation hold would never clear.
			name:  "leaf types are part of the shape",
			value: mustDecode(t, `{"key":{"created_at":1700000000}}`),
			want:  []string{"key.created_at: number"},
		},
		{
			// An empty collection must not read as "no such field", or a fake that sends
			// nothing would match a real response that sends a populated list.
			name:  "empty collections are named",
			value: mustDecode(t, `{"keys":[],"meta":{}}`),
			want:  []string{"keys: empty array", "meta: empty object"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := jsonShape(tc.value)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("jsonShape() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The field paths DigitalOcean's OpenAPI spec gives the Spaces-key endpoints. Written out
// as literals, from the spec rather than from the fake, so that editing the fake's field
// names cannot quietly keep this test passing — the plugin's client and the fake are both
// written from one reading of that spec, which is exactly the agreement no in-process test
// can question.
//
// This is the best available stand-in and not the real thing: it pins the fake to the SPEC,
// while `make test-cloud-real-do-spaces` pins it to DigitalOcean. When a recording exists,
// TestDOFakeMatchesRecordedRealResponses compares the same shapes against the real
// response and this test becomes the lesser of the two.
var (
	documentedSpacesCreateShape = []string{
		"key.access_key: string",
		"key.created_at: string",
		"key.grants[].bucket: string",
		"key.grants[].permission: string",
		"key.name: string",
		// Only here, and nowhere else in the key's life.
		"key.secret_key: string",
	}
	documentedSpacesListShape = []string{
		"keys[].access_key: string",
		"keys[].created_at: string",
		"keys[].grants[].bucket: string",
		"keys[].grants[].permission: string",
		"keys[].name: string",
		// The listing is PAGINATED, which the first transcription of this list missed — the
		// spec composes the response from `pagination` and `meta` as well as `keys`, and
		// marks meta required. `links` is empty on a single-page listing (the spec types
		// `pages` as an anyOf including the empty object) and carries pages.next/last when
		// pages remain; a client that ignores it sees 20 of an account's keys.
		"links: empty object",
		"meta.total: number",
	}
)

func TestDOFakeSpacesShapesMatchTheDocumentedAPI(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		status, body := fakeSpacesKeyCreate(t)
		assertShape(t, "POST "+spacesKeysPath, status, http.StatusCreated, body, documentedSpacesCreateShape)
	})
	t.Run("list", func(t *testing.T) {
		status, body := fakeSpacesKeyList(t)
		assertShape(t, "GET "+spacesKeysPath, status, http.StatusOK, body, documentedSpacesListShape)
	})
	t.Run("delete", func(t *testing.T) {
		status, body := fakeSpacesKeyDelete(t)
		// 204 with NO body: DeleteSpacesKey accepts only 204, so this is the one shape a
		// revoke may be answered with, and a body would mean the fake had invented one.
		assertShape(t, "DELETE "+spacesKeysPath+"/<access key>", status, http.StatusNoContent, body, nil)
	})
}

// fakeSpacesKeyCreate drives the fake's mint over HTTP and returns what a client sees.
// Over HTTP rather than by calling the handler, because the JSON encoding is the part
// being compared.
func fakeSpacesKeyCreate(t *testing.T) (status int, body any) {
	t.Helper()
	server := fakes.NewDOServer()
	defer server.Close()
	return callFake(t, server.URL+spacesKeysPath, http.MethodPost, spacesCreateRequestBody)
}

func fakeSpacesKeyList(t *testing.T) (status int, body any) {
	t.Helper()
	server := fakes.NewDOServer()
	defer server.Close()
	// Seeded through the mint path, so the listing reports a key the fake really issued
	// rather than one planted in its map with whatever fields a test chose.
	if status, _ := callFake(t, server.URL+spacesKeysPath, http.MethodPost, spacesCreateRequestBody); status != http.StatusCreated {
		t.Fatalf("seeding a key through the fake's mint returned %d", status)
	}
	return callFake(t, server.URL+spacesKeysPath, http.MethodGet, "")
}

func fakeSpacesKeyDelete(t *testing.T) (status int, body any) {
	t.Helper()
	server := fakes.NewDOServer()
	defer server.Close()
	created, decoded := callFake(t, server.URL+spacesKeysPath, http.MethodPost, spacesCreateRequestBody)
	if created != http.StatusCreated {
		t.Fatalf("seeding a key through the fake's mint returned %d", created)
	}
	accessKey := accessKeyOf(t, decoded)
	return callFake(t, server.URL+spacesKeysPath+"/"+accessKey, http.MethodDelete, "")
}

// accessKeyOf reads the access key out of a mint response the way the plugin's client
// does, so a fake that renamed the field fails here rather than silently.
func accessKeyOf(t *testing.T, body any) string {
	t.Helper()
	wrapper, ok := body.(map[string]any)
	if !ok {
		t.Fatalf("the fake's mint response is not a JSON object: %T", body)
	}
	key, ok := wrapper["key"].(map[string]any)
	if !ok {
		t.Fatalf("the fake's mint response has no `key` object: %v", wrapper)
	}
	accessKey, ok := key["access_key"].(string)
	if !ok || accessKey == "" {
		t.Fatalf("the fake's mint response has no access_key: %v", key)
	}
	return accessKey
}

// callFake performs one request against the fake and decodes the response. An empty
// requestBody sends none.
func callFake(t *testing.T, url, method, requestBody string) (status int, body any) {
	t.Helper()
	reader := io.Reader(http.NoBody)
	if requestBody != "" {
		reader = strings.NewReader(requestBody)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, url, reader)
	if err != nil {
		t.Fatalf("building the %s request failed: %v", method, err)
	}
	if requestBody != "" {
		req.Header.Set("Content-Type", jsonContentType)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s to the fake failed: %v", method, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the fake's body failed: %v", err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		return resp.StatusCode, nil
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("the fake returned non-JSON (%q): %v", string(raw), err)
	}
	return resp.StatusCode, decoded
}

// assertFakeShape compares a recording to the fake by field paths and leaf types.
func assertFakeShape(t *testing.T, name string, recorded recordedResponse, fakeStatus int, fakeBody any) {
	t.Helper()
	assertShape(t, name, fakeStatus, recorded.Status, fakeBody, jsonShape(recorded.Body))
}

func assertShape(t *testing.T, subject string, gotStatus, wantStatus int, gotBody any, wantShape []string) {
	t.Helper()
	if gotStatus != wantStatus {
		t.Errorf("%s: the fake answered %d, want %d", subject, gotStatus, wantStatus)
	}
	got := jsonShape(gotBody)
	if len(got) == 0 && len(wantShape) == 0 {
		return
	}
	if !reflect.DeepEqual(got, wantShape) {
		t.Errorf("%s: the fake's response shape does not match.\n  fake: %v\n  want: %v\n"+
			"A field name only the fake uses is a field the plugin decodes in tests and misses in "+
			"production — for the mint response that means an empty credential returned as a success.",
			subject, got, wantShape)
	}
}

// mustDecode is how these cases are written: as the JSON a response really carries,
// rather than as hand-built Go maps that could not have come off the wire.
func mustDecode(t *testing.T, raw string) any {
	t.Helper()
	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("test fixture %q is not JSON: %v", raw, err)
	}
	return decoded
}

// fakeMintForbiddenBody drives the fake to the one state whose real counterpart is
// recorded: a minter that authenticates but may not manage tokens.
func fakeMintForbiddenBody(t *testing.T) (status int, body any) {
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
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("the fake returned non-JSON (%q): %v", string(raw), err)
	}
	return resp.StatusCode, decoded
}

func assertFakeBody(t *testing.T, name string, recorded recordedResponse, fakeStatus int, fakeBody any) {
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

// jsonShape renders a decoded body as its sorted field paths and leaf types, so two
// responses can be compared without comparing one account's data to a fake's invented
// values. Array elements collapse to one `[]` path: the fake sends one key and a real
// account sends however many it has, and the difference is not a shape difference.
func jsonShape(value any) []string {
	if value == nil {
		// No body at all — a 204, which is the only thing a Spaces delete may answer with.
		// Reported as no shape rather than as a null leaf so that "empty" compares equal
		// however the empty response reached here.
		return nil
	}
	seen := make(map[string]bool)
	collectShape(value, "", seen)
	shape := make([]string, 0, len(seen))
	for path := range seen {
		shape = append(shape, path)
	}
	sort.Strings(shape)
	return shape
}

func collectShape(value any, path string, seen map[string]bool) {
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) == 0 {
			seen[describeLeaf(path, "empty object")] = true
			return
		}
		for key, nested := range typed {
			child := key
			if path != "" {
				child = path + "." + key
			}
			collectShape(nested, child, seen)
		}
	case []any:
		if len(typed) == 0 {
			seen[describeLeaf(path, "empty array")] = true
			return
		}
		for _, element := range typed {
			collectShape(element, path+"[]", seen)
		}
	case string:
		seen[describeLeaf(path, "string")] = true
	case float64:
		seen[describeLeaf(path, "number")] = true
	case bool:
		seen[describeLeaf(path, "bool")] = true
	default:
		// Explicit null. Kept as its own type rather than folded into the field's other
		// shape: a field that is sometimes null is something a decoder has to handle.
		seen[describeLeaf(path, "null")] = true
	}
}

func describeLeaf(path, kind string) string {
	if path == "" {
		return kind
	}
	return path + ": " + kind
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

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("cannot re-encode for the failure message: %v", err)
	}
	return string(encoded)
}
