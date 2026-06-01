package fakes

import (
	"encoding/json"
	"fmt"
	"net/http"
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
)

// errCodeServerError is the body error_code value the fakes stamp on injected
// 5xx / disabled-by-knob responses.
const errCodeServerError = "SERVER_ERROR"

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
