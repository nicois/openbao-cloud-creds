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
	s.nextID.Store(1000)
	s.Server = httptest.NewServer(s.handler())
	return s
}

// ProvisionedCount returns the number of API keys currently held by the fake.
func (s *ExoscaleServer) ProvisionedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.apiKeys)
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
			"error": map[string]interface{}{
				"code":    "SERVER_ERROR",
				"message": fmt.Sprintf("injected %d", status),
			},
		})
		return true
	}
	return false
}

func (s *ExoscaleServer) checkBearerAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) <= 7 {
		w.WriteHeader(401)
		writeJSON(w, map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "UNAUTHORIZED",
				"message": "missing or invalid bearer token",
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
		w.WriteHeader(400)
		return
	}

	keyID := fmt.Sprintf("exo-key-%d", s.nextID.Add(1))
	keySecret := fmt.Sprintf("EXOsecret_fake_%s", keyID)

	apiKey := map[string]interface{}{
		"key":     keySecret,
		"key-id":  keyID,
		"name":    req.Name,
		"role-id": req.RoleID,
	}

	s.mu.Lock()
	s.apiKeys[keyID] = apiKey
	s.mu.Unlock()

	w.WriteHeader(200)
	writeJSON(w, apiKey)
}

func (s *ExoscaleServer) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	keyID := parts[len(parts)-1]

	s.mu.Lock()
	_, exists := s.apiKeys[keyID]
	if exists {
		delete(s.apiKeys, keyID)
	}
	s.mu.Unlock()

	if !exists {
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
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
			"key-id":  k["key-id"],
			"name":    k["name"],
			"role-id": k["role-id"],
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
	w.WriteHeader(200)
	writeJSON(w, map[string]interface{}{
		"zones": []map[string]interface{}{
			{"name": "ch-gva-2"},
			{"name": "ch-dk-2"},
			{"name": "de-fra-1"},
		},
	})
}
