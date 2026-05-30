package fakes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type UpCloudServer struct {
	*httptest.Server
	mu         sync.Mutex
	tokens     map[string]map[string]interface{}
	nextID     atomic.Int64
	nextStatus int
}

func NewUpCloudServer() *UpCloudServer {
	s := &UpCloudServer{
		tokens: make(map[string]map[string]interface{}),
	}
	s.nextID.Store(1000)
	s.Server = httptest.NewServer(s.handler())
	return s
}

func (s *UpCloudServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

func (s *UpCloudServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /1.3/account", s.getAccount)
	mux.HandleFunc("POST /1.3/account/tokens", s.createToken)
	mux.HandleFunc("DELETE /1.3/account/tokens/", s.deleteToken)
	mux.HandleFunc("GET /1.3/account/tokens", s.listTokens)
	return mux
}

func (s *UpCloudServer) checkInjectedError(w http.ResponseWriter) bool {
	s.mu.Lock()
	status := s.nextStatus
	s.nextStatus = 0
	s.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		writeJSON(w, map[string]interface{}{
			"error": map[string]interface{}{
				"error_code":    "SERVER_ERROR",
				"error_message": fmt.Sprintf("injected %d", status),
			},
		})
		return true
	}
	return false
}

func (s *UpCloudServer) checkBasicAuth(w http.ResponseWriter, r *http.Request) bool {
	username, password, ok := r.BasicAuth()
	if !ok || username == "" || password == "" {
		w.WriteHeader(401)
		writeJSON(w, map[string]interface{}{
			"error": map[string]interface{}{
				"error_code":    "AUTHENTICATION_FAILED",
				"error_message": "missing or invalid credentials",
			},
		})
		return false
	}
	return true
}

func (s *UpCloudServer) createToken(w http.ResponseWriter, r *http.Request) {
	if !s.checkBasicAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	var req struct {
		Name            string `json:"name"`
		ExpiresIn       string `json:"expires_in"`
		CanCreateTokens bool   `json:"can_create_tokens"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		return
	}

	id := fmt.Sprintf("uctkn-%d", s.nextID.Add(1))

	// Parse expires_in to compute expires_at
	expiresAt := time.Now().Add(1 * time.Hour) // default 1h
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err == nil {
			expiresAt = time.Now().Add(d)
		}
	}

	token := map[string]interface{}{
		"id":         id,
		"name":       req.Name,
		"token":      fmt.Sprintf("ucat_fake_%s", id),
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	}

	s.mu.Lock()
	s.tokens[id] = token
	s.mu.Unlock()

	w.WriteHeader(201)
	writeJSON(w, token)
}

func (s *UpCloudServer) deleteToken(w http.ResponseWriter, r *http.Request) {
	if !s.checkBasicAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]

	s.mu.Lock()
	_, exists := s.tokens[id]
	if exists {
		delete(s.tokens, id)
	}
	s.mu.Unlock()

	if !exists {
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(204)
}

func (s *UpCloudServer) listTokens(w http.ResponseWriter, r *http.Request) {
	if !s.checkBasicAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	tokens := make([]map[string]interface{}, 0, len(s.tokens))
	for _, t := range s.tokens {
		tokens = append(tokens, t)
	}
	s.mu.Unlock()

	// UpCloud's GET /1.3/account/tokens returns a bare JSON array (verified
	// against the live API), not an object with a "tokens" key.
	writeJSON(w, tokens)
}

func (s *UpCloudServer) getAccount(w http.ResponseWriter, r *http.Request) {
	if !s.checkBasicAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}
	w.WriteHeader(200)
	writeJSON(w, map[string]interface{}{
		"account": map[string]interface{}{
			"username": "test-user",
			"credits":  100.0,
		},
	})
}
