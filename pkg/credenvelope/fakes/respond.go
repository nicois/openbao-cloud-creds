package fakes

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// JSON keys shared across multiple cloud fakes. goconst counts string literals
// package-wide, so these live in one place rather than being duplicated.
const (
	jsonKeyError            = "error"
	jsonKeyMessage          = "message"
	jsonKeyCode             = "code"
	jsonKeyErrorDescription = "error_description"
	jsonKeyAccessToken      = "access_token"
	jsonKeyName             = "name"
	jsonKeyAccount          = "account"
	jsonKeyCreatedAt        = "created_at"
	jsonKeyErrorCode        = "error_code"
	jsonKeyErrorMessage     = "error_message"
	jsonKeyAccessKey        = "access_key"
	jsonKeySecretKey        = "secret_key"
	jsonKeyGrants           = "grants"
)

// schemeHTTPS is named by two fakes: Akamai reconstructs the URL a client signed, and
// paginateDO builds a link back to itself. Hoisted for the same package-wide goconst
// reason as the JSON keys above, kept out of that block because it is not a JSON key.
const schemeHTTPS = "https"

// errCodeServerError is the body error_code value the fakes stamp on injected
// 5xx / disabled-by-knob responses.
const errCodeServerError = "SERVER_ERROR"

// The refusal a cloud sends a credential that authenticates but may not perform the
// operation. Both values are DigitalOcean's own wording, recorded from a real account
// (plugins/credential-do/testdata/cloud-real/POST_v2_tokens_403.json) — a fake that
// invents friendlier errors is a fake whose error handling is untested — and Akamai's
// title happens to match, which is why they live here rather than in one cloud's file.
const (
	titleForbidden       = "Forbidden"
	msgOperationNotAllow = "You are not authorized to perform this operation"
)

// msgHealthCheckDisabledByKnob is the body message the fakes stamp on a health
// check failed by a SetFailHealth* test knob (shared across cloud fakes so the
// literal lives in one place).
const msgHealthCheckDisabledByKnob = "health check disabled by test knob"

// fakeCreatedAt is the deterministic creation timestamp the fakes stamp on
// entities minted through their create paths (RFC3339). Tests that need a
// specific age use the AddRaw*WithCreatedAt helpers to override it.
const fakeCreatedAt = "2026-01-01T00:00:00Z"

// injectedErrorValue is the body value used for one-shot injected error
// responses across the fakes.
const injectedErrorValue = "server_error"

// fakeStartID / fakeStartCredID seed the per-fake monotonic ID counters; the
// gap keeps client IDs and credential IDs visibly distinct in test output.
const (
	fakeStartID     = 1000
	fakeStartCredID = 5000
)

// fakeTokenExpirySeconds is the "expires_in" value (1 hour) returned by the
// OAuth2 token endpoints of the OVH and Azure fakes.
const fakeTokenExpirySeconds = 3600 // 1h

// writeJSON encodes v as JSON to the response writer, panicking on failure
// (acceptable in a test fake).
func writeJSON(w http.ResponseWriter, v interface{}) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(fmt.Sprintf("fake server: failed to encode JSON: %v", err))
	}
}

// DigitalOcean's documented per_page bounds: it defaults to 20 and refuses more than 200.
// A fake that answered every listing in one page would let a client that never asks for
// page 2 pass every test here and then, in production, see 20 of an account's 200
// credentials — and what a reconciler cannot see it cannot reclaim.
const (
	doDefaultPageSize = 20
	doMaxPageSize     = 200
)

// paginateDO windows entries the way a DigitalOcean list endpoint does, returning the whole
// response envelope: the window under listKey, the `links` object (carrying pages.next and
// pages.last while pages remain, and empty on the final page — DO's spec types `pages` as an
// anyOf that includes the empty object) and the `meta.total` its spec marks required.
//
// entries must arrive in a STABLE order — a property of this fake, not a claim about
// DigitalOcean's own ordering, which its spec leaves to optional sort parameters. A fake
// paging over Go's randomised map iteration would hand out overlapping pages, so a client
// that pages *correctly* would still see duplicates and misses — a bug belonging to the
// fake alone, which is the one kind of finding a fake must never manufacture.
func paginateDO(r *http.Request, listKey string, entries []map[string]interface{}) map[string]interface{} {
	perPage := clampedQueryInt(r, "per_page", doDefaultPageSize, 1, doMaxPageSize)
	page := clampedQueryInt(r, "page", 1, 1, math.MaxInt32)

	start := min((page-1)*perPage, len(entries))
	end := min(start+perPage, len(entries))
	window := entries[start:end]
	if window == nil {
		// A JSON `null` is not an empty list: a client decoding one gets no error and no
		// entries, which is exactly the silence this fake exists to make loud.
		window = []map[string]interface{}{}
	}

	links := map[string]interface{}{}
	if end < len(entries) {
		lastPage := (len(entries) + perPage - 1) / perPage
		links["pages"] = map[string]interface{}{
			"next": pageURL(r, perPage, page+1),
			"last": pageURL(r, perPage, lastPage),
		}
	}
	return map[string]interface{}{
		listKey: window,
		"links": links,
		"meta":  map[string]interface{}{"total": len(entries)},
	}
}

// pageURL builds an absolute link to another page of the same listing, as DigitalOcean
// does. It is rooted at the request's own host so that a client which follows the link
// reaches this fake rather than the real api.digitalocean.com.
func pageURL(r *http.Request, perPage, page int) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = schemeHTTPS
	}
	query := url.Values{
		"per_page": []string{strconv.Itoa(perPage)},
		"page":     []string{strconv.Itoa(page)},
	}
	return scheme + "://" + r.Host + r.URL.Path + "?" + query.Encode()
}

// clampedQueryInt reads a positive integer query parameter, falling back to fallback when
// it is absent or unparseable and clamping it to [low, high]. DO's spec declares the
// bounds (per_page minimum 1, maximum 200) but not what it does with a value outside them,
// so the fake clamps: clamping cannot fail a request DigitalOcean would have accepted,
// whereas a 400 invented here could.
func clampedQueryInt(r *http.Request, name string, fallback, low, high int) int {
	value, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return fallback
	}
	return min(max(value, low), high)
}

// deleteByID removes the entry keyed by the last path segment of r.URL.Path
// from store (guarded by mu). It writes 404 with no body if the entry was
// absent, otherwise successStatus with no body. The cloud fakes share this
// because their delete-by-id handlers are mechanically identical apart from the
// success code and the map they mutate.
func deleteByID(
	w http.ResponseWriter,
	r *http.Request,
	mu *sync.Mutex,
	store map[string]map[string]interface{},
	successStatus int,
) {
	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]

	mu.Lock()
	_, exists := store[id]
	if exists {
		delete(store, id)
	}
	mu.Unlock()

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(successStatus)
}
