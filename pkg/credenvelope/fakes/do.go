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
	mu         sync.Mutex
	tokens     map[string]map[string]interface{}
	nextID     atomic.Int64
	nextStatus int
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
