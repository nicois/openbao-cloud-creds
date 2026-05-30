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

type VultrServer struct {
	*httptest.Server
	mu         sync.Mutex
	users      map[string]map[string]interface{}
	nextID     atomic.Int64
	nextStatus int
}

func NewVultrServer() *VultrServer {
	s := &VultrServer{
		users: make(map[string]map[string]interface{}),
	}
	s.nextID.Store(1000)
	s.Server = httptest.NewServer(s.handler())
	return s
}

// ProvisionedCount returns the number of sub-users currently held by the fake.
func (s *VultrServer) ProvisionedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.users)
}

func (s *VultrServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

func (s *VultrServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/account", s.getAccount)
	mux.HandleFunc("POST /v2/users", s.createUser)
	mux.HandleFunc("DELETE /v2/users/", s.deleteUser)
	mux.HandleFunc("GET /v2/users", s.listUsers)
	return mux
}

func (s *VultrServer) checkInjectedError(w http.ResponseWriter) bool {
	s.mu.Lock()
	status := s.nextStatus
	s.nextStatus = 0
	s.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		writeJSON(w, map[string]interface{}{
			"error":   "server_error",
			"message": fmt.Sprintf("injected %d", status),
		})
		return true
	}
	return false
}

func (s *VultrServer) checkBearerAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) <= 7 {
		w.WriteHeader(401)
		writeJSON(w, map[string]interface{}{
			"error":   "unauthorized",
			"message": "missing or invalid bearer token",
		})
		return false
	}
	return true
}

func (s *VultrServer) createUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	var req struct {
		Email      string   `json:"email"`
		Name       string   `json:"name"`
		APIEnabled bool     `json:"api_enabled"`
		ACLs       []string `json:"acls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		return
	}

	id := fmt.Sprintf("vultr-user-%d", s.nextID.Add(1))
	apiKey := fmt.Sprintf("vultr_fake_key_%s", id)

	user := map[string]interface{}{
		"id":          id,
		"name":        req.Name,
		"email":       req.Email,
		"api_enabled": req.APIEnabled,
		"acls":        req.ACLs,
		"api_key":     apiKey,
	}

	s.mu.Lock()
	s.users[id] = user
	s.mu.Unlock()

	w.WriteHeader(201)
	writeJSON(w, map[string]interface{}{"user": user})
}

func (s *VultrServer) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]

	s.mu.Lock()
	_, exists := s.users[id]
	if exists {
		delete(s.users, id)
	}
	s.mu.Unlock()

	if !exists {
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(204)
}

func (s *VultrServer) listUsers(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	users := make([]map[string]interface{}, 0, len(s.users))
	for _, u := range s.users {
		// List does not return api_key
		users = append(users, map[string]interface{}{
			"id":          u["id"],
			"name":        u["name"],
			"email":       u["email"],
			"api_enabled": u["api_enabled"],
			"acls":        u["acls"],
		})
	}
	s.mu.Unlock()

	writeJSON(w, map[string]interface{}{
		"users": users,
		"meta": map[string]interface{}{
			"total": len(users),
		},
	})
}

func (s *VultrServer) getAccount(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}
	w.WriteHeader(200)
	writeJSON(w, map[string]interface{}{
		"account": map[string]interface{}{
			"name":    "fake-vultr-account",
			"email":   "admin@example.com",
			"balance": -100.00,
		},
	})
}
