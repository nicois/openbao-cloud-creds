package fakes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
)

type DOServer struct {
	*httptest.Server
	mu           sync.Mutex
	tokens       map[string]map[string]interface{}
	nextID       atomic.Int64
	nextStatus   int
	forbidCreate bool
}

func NewDOServer() *DOServer {
	s := &DOServer{
		tokens: make(map[string]map[string]interface{}),
	}
	s.nextID.Store(fakeStartID)
	s.Server = httptest.NewServer(s.handler())
	return s
}

// ProvisionedCount returns the number of tokens currently held by the fake.
func (s *DOServer) ProvisionedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

// AddRawToken injects a token with an arbitrary id and name directly into the
// fake, bypassing the create path. Test-only: used to plant foreign-named
// (non-cloud-creds-) entities that the reconciler must never delete.
func (s *DOServer) AddRawToken(id, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[id] = map[string]interface{}{
		"id":        id,
		jsonKeyName: name,
	}
}

// AddRawTokenWithCreatedAt injects a token with an arbitrary id, name and
// created_at (RFC3339) directly into the fake. Test-only: used to plant an
// orphan with a controlled age so the fail-closed reconciler's confirmation
// hold can be exercised (delete-vs-skip by age).
func (s *DOServer) AddRawTokenWithCreatedAt(id, name, createdAt string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[id] = map[string]interface{}{
		"id":             id,
		jsonKeyName:      name,
		jsonKeyCreatedAt: createdAt,
	}
}

// HasToken reports whether a token with the given id is still held by the fake.
func (s *DOServer) HasToken(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tokens[id]
	return ok
}

func (s *DOServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

// SetForbidCreate makes POST /v2/tokens refuse with 403 until it is called again
// with false, while GET /v2/account (the health check) keeps succeeding. Unlike
// SetNextStatus this is sticky and mint-specific, which is the shape the shared
// capability suite needs: a minter that authenticates but may not mint, across
// however many calls one configuration write makes.
func (s *DOServer) SetForbidCreate(forbid bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forbidCreate = forbid
}

func (s *DOServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/account", s.getAccount)
	mux.HandleFunc("POST /v2/tokens", s.createToken)
	mux.HandleFunc("DELETE /v2/tokens/", s.deleteToken)
	mux.HandleFunc("GET /v2/tokens", s.listTokens)
	return mux
}

func (s *DOServer) checkInjectedError(w http.ResponseWriter) bool {
	s.mu.Lock()
	status := s.nextStatus
	s.nextStatus = 0
	s.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		writeJSON(w, map[string]interface{}{
			"id":           injectedErrorValue,
			jsonKeyMessage: fmt.Sprintf("injected %d", status),
		})
		return true
	}
	return false
}

func (s *DOServer) createToken(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	forbidCreate := s.forbidCreate
	s.mu.Unlock()
	if forbidCreate {
		w.WriteHeader(http.StatusForbidden)
		// Byte-for-byte what real DO returns to a PAT that is live but not
		// authorized for token management — recorded from a real account in
		// plugins/credential-do/testdata/cloud-real/POST_v2_tokens_403.json.
		// The capitalised "Forbidden" and the generic message are DO's, not a
		// convenience for the test: a fake that invents friendlier errors is a
		// fake whose error handling is untested.
		writeJSON(w, map[string]interface{}{
			"id":           "Forbidden",
			jsonKeyMessage: "You are not authorized to perform this operation",
		})
		return
	}

	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	id := fmt.Sprintf("tok-%d", s.nextID.Add(1))
	token := map[string]interface{}{
		"id":               id,
		jsonKeyName:        req.Name,
		"scopes":           req.Scopes,
		jsonKeyAccessToken: fmt.Sprintf("dop_v1_fake_%s", id),
		jsonKeyCreatedAt:   fakeCreatedAt,
	}

	s.mu.Lock()
	s.tokens[id] = token
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]interface{}{"token": token})
}

func (s *DOServer) deleteToken(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}
	deleteByID(w, r, &s.mu, s.tokens, http.StatusNoContent)
}

func (s *DOServer) listTokens(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	tokens := make([]map[string]interface{}, 0, len(s.tokens))
	for _, t := range s.tokens {
		tokens = append(tokens, t)
	}
	s.mu.Unlock()

	writeJSON(w, map[string]interface{}{"tokens": tokens})
}

func (s *DOServer) getAccount(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}
	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]interface{}{
		jsonKeyAccount: map[string]interface{}{
			"uuid":   "fake-account-uuid",
			"status": "active",
		},
	})
}
