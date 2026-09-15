package fakes_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// createSpacesKey posts a create request and returns the decoded `key` object.
func createSpacesKey(t *testing.T, srv *fakes.DOServer, body string) map[string]interface{} {
	t.Helper()
	resp, err := http.Post(srv.URL+"/v2/spaces/keys", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, data)
	}
	var result struct {
		Key map[string]interface{} `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decoding the create response failed: %v", err)
	}
	return result.Key
}

func TestDOFake_CreateSpacesKey(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	key := createSpacesKey(t, srv,
		`{"name":"cloud-creds-test-lease1","grants":[{"bucket":"backups","permission":"read"}]}`)

	for _, field := range []string{"name", "access_key", "secret_key", "created_at"} {
		if key[field] == nil || key[field] == "" {
			t.Errorf("the create response has no %q; a plugin cannot use or revoke the key without it", field)
		}
	}
	if key["name"] != "cloud-creds-test-lease1" {
		t.Errorf("name round-trip failed: got %v", key["name"])
	}
	grants, ok := key["grants"].([]interface{})
	if !ok || len(grants) != 1 {
		t.Fatalf("grants did not round-trip: got %v", key["grants"])
	}
	grant := grants[0].(map[string]interface{})
	if grant["bucket"] != "backups" || grant["permission"] != "read" {
		t.Errorf("the grant round-trip lost a field: got %v", grant)
	}
}

// The single most load-bearing fact about this credential type: DigitalOcean returns the
// secret ONCE, on create. A fake that also returned it on list would let a plugin that
// re-read the secret from a listing pass every test and then fail in production.
func TestDOFake_SpacesKeySecretIsReturnedOnlyOnCreate(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	created := createSpacesKey(t, srv, `{"name":"cloud-creds-test-lease1","grants":[]}`)

	resp, err := http.Get(srv.URL + "/v2/spaces/keys")
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from list, got %d", resp.StatusCode)
	}
	var listed struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatalf("decoding the list response failed: %v", err)
	}
	if len(listed.Keys) != 1 {
		t.Fatalf("expected exactly the one created key, got %d", len(listed.Keys))
	}
	if _, present := listed.Keys[0]["secret_key"]; present {
		t.Error("the list response carries secret_key; DigitalOcean returns the secret only at " +
			"creation, and a fake that leaks it lets a plugin depend on recovering it")
	}
	if listed.Keys[0]["access_key"] != created["access_key"] {
		t.Errorf("the listed access_key does not match the created one: %v vs %v",
			listed.Keys[0]["access_key"], created["access_key"])
	}
}

func TestDOFake_DeleteSpacesKeyByAccessKey(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	key := createSpacesKey(t, srv, `{"name":"cloud-creds-test-lease1","grants":[]}`)
	accessKey := key["access_key"].(string)

	if !srv.HasSpacesKey(accessKey) {
		t.Fatal("the fake does not hold the key it just created")
	}

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v2/spaces/keys/"+accessKey, http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	if srv.HasSpacesKey(accessKey) {
		t.Error("the key survived its delete, so a hard revoke would silently leave it live")
	}
}

// KI-009 as DigitalOcean actually presents it: the edge gateway fences the /v2/tokens
// ROUTE, so listing is refused exactly as creating is, while everything else on the same
// PAT is served. That matters beyond minting — a reconciler that treated one class failing
// to list as a failed pass would disable orphan reclamation for Spaces keys, the class
// that works, on every real DigitalOcean account.
func TestDOFake_FencingTokenManagementRefusesListingAsWellAsCreating(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	srv.SetFenceTokenManagement(true)

	for _, path := range []string{"/v2/tokens"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s failed: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s: expected the fence to refuse listing with 403, got %d", path, resp.StatusCode)
		}
	}

	create, err := http.Post(srv.URL+"/v2/tokens", "application/json",
		bytes.NewBufferString(`{"name":"x","scopes":[]}`))
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	create.Body.Close()
	if create.StatusCode != http.StatusForbidden {
		t.Errorf("expected the fence to refuse creating with 403, got %d", create.StatusCode)
	}

	// The fence is a property of one route, not of the credential: Spaces keys and the
	// account endpoint keep working, which is the asymmetry the whole design turns on.
	spaces, err := http.Get(srv.URL + "/v2/spaces/keys")
	if err != nil {
		t.Fatalf("spaces list failed: %v", err)
	}
	spaces.Body.Close()
	if spaces.StatusCode != http.StatusOK {
		t.Errorf("the token fence also blocked Spaces keys, which real DigitalOcean does not; got %d",
			spaces.StatusCode)
	}
}

// The capability category needs a refusal that is MINT-ONLY and sticky: a minter that
// authenticates (GET /v2/account keeps answering 200) but may not create a Spaces key.
// Separate from SetForbidCreate, because a PAT can hold spaces_key:create_credentials
// without holding token-management rights and vice versa — one knob for both could not
// express the case that actually matters on this cloud.
func TestDOFake_ForbidSpacesKeyCreateLeavesTheHealthCheckWorking(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	srv.SetForbidSpacesKeyCreate(true)

	resp, err := http.Post(srv.URL+"/v2/spaces/keys", "application/json",
		bytes.NewBufferString(`{"name":"cloud-creds-test-probe","grants":[]}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected the mint to be refused with 403, got %d", resp.StatusCode)
	}

	health, err := http.Get(srv.URL + "/v2/account")
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("the health check must keep succeeding while the mint is refused — that asymmetry "+
			"is the whole point of the capability category; got %d", health.StatusCode)
	}
}

// listSpacesKeys performs a raw listing and returns the decoded envelope, so a test can
// assert on the pagination fields the typed client discards.
func listSpacesKeys(t *testing.T, srv *fakes.DOServer, query string) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(srv.URL + "/v2/spaces/keys" + query)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, data)
	}
	var envelope map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decoding the list response failed: %v", err)
	}
	return envelope
}

func listedKeyCount(t *testing.T, envelope map[string]interface{}) int {
	t.Helper()
	keys, ok := envelope["keys"].([]interface{})
	if !ok {
		t.Fatalf("the listing has no `keys` array: %v", envelope)
	}
	return len(keys)
}

// DigitalOcean paginates this endpoint — `per_page` defaults to 20 and caps at 200 — and
// answers with `links` plus a required `meta.total` alongside `keys`. A fake that returns
// every key in one unpaginated envelope lets a client that reads only the first page pass
// every test here and then, against real DO, see 20 of an account's 200 keys. That matters
// more for this credential type than for any other: a Spaces key has NO upstream expiry,
// so the owner-tag reconciler is the only thing that ever reclaims a leaked one, and what
// it cannot see it cannot reclaim.
func TestDOFake_SpacesKeyListingIsPaginatedLikeTheRealAPI(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	const total = 45
	for i := 0; i < total; i++ {
		createSpacesKey(t, srv, `{"name":"cloud-creds-test-`+strconv.Itoa(i)+`","grants":[]}`)
	}

	t.Run("the default page size is DO's 20, not everything", func(t *testing.T) {
		envelope := listSpacesKeys(t, srv, "")
		if got := listedKeyCount(t, envelope); got != 20 {
			t.Errorf("expected DO's default per_page of 20 keys, got %d — a fake that returns "+
				"everything hides a client that never asks for page 2", got)
		}
	})

	t.Run("meta.total reports the account's whole holding", func(t *testing.T) {
		envelope := listSpacesKeys(t, srv, "")
		meta, ok := envelope["meta"].(map[string]interface{})
		if !ok {
			t.Fatalf("no `meta` object; DO's spec marks meta REQUIRED on this response: %v", envelope)
		}
		if meta["total"] != float64(total) {
			t.Errorf("meta.total = %v, want %d", meta["total"], total)
		}
	})

	t.Run("links.pages.next appears while pages remain and is absent on the last", func(t *testing.T) {
		first := listSpacesKeys(t, srv, "")
		if nextPageLink(t, first) == "" {
			t.Error("no links.pages.next on the first of three pages, so a client following the " +
				"links would stop after 20 keys")
		}
		last := listSpacesKeys(t, srv, "?page=3")
		if link := nextPageLink(t, last); link != "" {
			t.Errorf("links.pages.next = %q on the last page; a client following it would loop", link)
		}
	})

	t.Run("per_page and page select a window", func(t *testing.T) {
		if got := listedKeyCount(t, listSpacesKeys(t, srv, "?per_page=200")); got != total {
			t.Errorf("per_page=200 (DO's maximum) returned %d of %d keys", got, total)
		}
		if got := listedKeyCount(t, listSpacesKeys(t, srv, "?per_page=20&page=3")); got != 5 {
			t.Errorf("the third page of 20 should hold the remaining 5, got %d", got)
		}
		if got := listedKeyCount(t, listSpacesKeys(t, srv, "?per_page=20&page=9")); got != 0 {
			t.Errorf("a page past the end should be empty, got %d", got)
		}
	})

	t.Run("every key is reachable across pages, exactly once", func(t *testing.T) {
		seen := map[string]bool{}
		for page := 1; page <= 3; page++ {
			envelope := listSpacesKeys(t, srv, "?per_page=20&page="+strconv.Itoa(page))
			for _, entry := range envelope["keys"].([]interface{}) {
				accessKey, _ := entry.(map[string]interface{})["access_key"].(string)
				if seen[accessKey] {
					t.Errorf("access key %q appeared on two pages; a paging client would double-count",
						accessKey)
				}
				seen[accessKey] = true
			}
		}
		if len(seen) != total {
			t.Errorf("paging saw %d distinct keys, want %d", len(seen), total)
		}
	})
}

// nextPageLink digs out links.pages.next, tolerating each level being absent — DO's spec
// types `pages` as an anyOf that includes the empty object, which is what a single-page
// listing answers with.
func nextPageLink(t *testing.T, envelope map[string]interface{}) string {
	t.Helper()
	links, ok := envelope["links"].(map[string]interface{})
	if !ok {
		t.Fatalf("no `links` object in the listing; DO sends one (empty when there is no next "+
			"page), and a shape comparison against a real recording fails without it: %v", envelope)
	}
	pages, ok := links["pages"].(map[string]interface{})
	if !ok {
		return ""
	}
	next, _ := pages["next"].(string)
	return next
}
