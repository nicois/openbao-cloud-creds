package fakes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
)

const jsonKeyKeyID = "key-id"

type ExoscaleServer struct {
	*httptest.Server
	mu         sync.Mutex
	apiKeys    map[string]map[string]interface{}
	nextID     atomic.Int64
	nextStatus int
}

func NewExoscaleServer() *ExoscaleServer {
	s := &ExoscaleServer{
		apiKeys: make(map[string]map[string]interface{}),
	}
	s.nextID.Store(fakeStartID)
	s.Server = httptest.NewServer(s.handler())
	return s
}

// ProvisionedCount returns the number of API keys currently held by the fake.
func (s *ExoscaleServer) ProvisionedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.apiKeys)
}

// AddRawAPIKey injects an API key with an arbitrary key-id and name directly
// into the fake, bypassing the create path. Test-only: used to plant
// foreign-named (non-cloud-creds-) entities that the reconciler must never
// delete.
func (s *ExoscaleServer) AddRawAPIKey(keyID, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys[keyID] = map[string]interface{}{
		jsonKeyKeyID: keyID,
		jsonKeyName:  name,
	}
}

// HasAPIKey reports whether an API key with the given key-id is still held by
// the fake.
func (s *ExoscaleServer) HasAPIKey(keyID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.apiKeys[keyID]
	return ok
}

func (s *ExoscaleServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

func (s *ExoscaleServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/zone", s.listZones)
	mux.HandleFunc("POST /v2/api-key", s.createAPIKey)
	mux.HandleFunc("DELETE /v2/api-key/", s.deleteAPIKey)
	mux.HandleFunc("GET /v2/api-key", s.listAPIKeys)
	return mux
}

func (s *ExoscaleServer) checkInjectedError(w http.ResponseWriter) bool {
	s.mu.Lock()
	status := s.nextStatus
	s.nextStatus = 0
	s.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		writeJSON(w, map[string]interface{}{
			jsonKeyError: map[string]interface{}{
				jsonKeyCode:    errCodeServerError,
				jsonKeyMessage: fmt.Sprintf("injected %d", status),
			},
		})
		return true
	}
	return false
}

func (s *ExoscaleServer) checkBearerAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) <= 7 {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]interface{}{
			jsonKeyError: map[string]interface{}{
				jsonKeyCode:    "UNAUTHORIZED",
				jsonKeyMessage: "missing or invalid bearer token",
			},
		})
		return false
	}
	return true
}

func (s *ExoscaleServer) createAPIKey(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	var req struct {
		Name   string `json:"name"`
		RoleID string `json:"role-id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	keyID := fmt.Sprintf("exo-key-%d", s.nextID.Add(1))
	keySecret := fmt.Sprintf("EXOsecret_fake_%s", keyID)

	apiKey := map[string]interface{}{
		"key":        keySecret,
		jsonKeyKeyID: keyID,
		jsonKeyName:  req.Name,
		"role-id":    req.RoleID,
	}

	s.mu.Lock()
	s.apiKeys[keyID] = apiKey
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	writeJSON(w, apiKey)
}

func (s *ExoscaleServer) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}
	deleteByID(w, r, &s.mu, s.apiKeys, http.StatusOK)
}

func (s *ExoscaleServer) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	keys := make([]map[string]interface{}, 0, len(s.apiKeys))
	for _, k := range s.apiKeys {
		// List does not return the secret key value
		keys = append(keys, map[string]interface{}{
			jsonKeyKeyID: k[jsonKeyKeyID],
			jsonKeyName:  k[jsonKeyName],
			"role-id":    k["role-id"],
		})
	}
	s.mu.Unlock()

	writeJSON(w, map[string]interface{}{"api-keys": keys})
}

func (s *ExoscaleServer) listZones(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}
	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]interface{}{
		"zones": []map[string]interface{}{
			{jsonKeyName: "ch-gva-2"},
			{jsonKeyName: "ch-dk-2"},
			{jsonKeyName: "de-fra-1"},
		},
	})
}
