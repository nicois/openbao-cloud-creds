package fakes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

const jsonKeyEmail = "email"

type VultrServer struct {
	*httptest.Server
	mu         sync.Mutex
	users      map[string]map[string]interface{}
	nextID     atomic.Int64
	nextStatus int
	// ungrantableACL, when non-empty, makes POST /v2/users return 403 for any
	// request whose acls list contains it, while GET /v2/account still succeeds.
	// Test-only: reproduces Vultr refusing to grant a sub-user an ACL the creating
	// key does not itself hold — a minter that is healthy but cannot serve a role.
	ungrantableACL string
}

func NewVultrServer() *VultrServer {
	s := &VultrServer{
		users: make(map[string]map[string]interface{}),
	}
	s.nextID.Store(fakeStartID)
	s.Server = httptest.NewServer(s.handler())
	return s
}

// ProvisionedCount returns the number of sub-users currently held by the fake.
func (s *VultrServer) ProvisionedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.users)
}

// AddRawUser injects a sub-user with an arbitrary id and name directly into the
// fake, bypassing the create path. Test-only: used to plant foreign-named
// (non-cloud-creds-) entities that the reconciler must never delete.
func (s *VultrServer) AddRawUser(id, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[id] = map[string]interface{}{
		"id":        id,
		jsonKeyName: name,
	}
}

// HasUser reports whether a sub-user with the given id is still held by the fake.
func (s *VultrServer) HasUser(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.users[id]
	return ok
}

func (s *VultrServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

// SetUngrantableACL makes POST /v2/users return 403 whenever the requested acls
// contain acl (empty disables), leaving the account health check unaffected.
// Test-only: this is the "authenticates but cannot mint this role" condition the
// capability probe exists to catch.
func (s *VultrServer) SetUngrantableACL(acl string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ungrantableACL = acl
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
			jsonKeyError:   injectedErrorValue,
			jsonKeyMessage: fmt.Sprintf("injected %d", status),
		})
		return true
	}
	return false
}

func (s *VultrServer) checkBearerAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) <= 7 {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]interface{}{
			jsonKeyError:   "unauthorized",
			jsonKeyMessage: "missing or invalid bearer token",
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	forbidden := s.ungrantableACL
	s.mu.Unlock()
	if forbidden != "" && slices.Contains(req.ACLs, forbidden) {
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]interface{}{
			jsonKeyError: fmt.Sprintf("your API key does not hold the %q ACL, so it cannot grant it", forbidden),
		})
		return
	}

	id := fmt.Sprintf("vultr-user-%d", s.nextID.Add(1))
	apiKey := fmt.Sprintf("vultr_fake_key_%s", id)

	user := map[string]interface{}{
		"id":          id,
		jsonKeyName:   req.Name,
		jsonKeyEmail:  req.Email,
		"api_enabled": req.APIEnabled,
		"acls":        req.ACLs,
		"api_key":     apiKey,
	}

	s.mu.Lock()
	s.users[id] = user
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]interface{}{"user": user})
}

func (s *VultrServer) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}
	deleteByID(w, r, &s.mu, s.users, http.StatusNoContent)
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
			jsonKeyName:   u[jsonKeyName],
			jsonKeyEmail:  u[jsonKeyEmail],
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
	// fakeAccountBalance is an arbitrary negative balance for the test account.
	const fakeAccountBalance = -100.00
	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]interface{}{
		jsonKeyAccount: map[string]interface{}{
			jsonKeyName:  "fake-vultr-account",
			jsonKeyEmail: "admin@example.com",
			"balance":    fakeAccountBalance,
		},
	})
}
