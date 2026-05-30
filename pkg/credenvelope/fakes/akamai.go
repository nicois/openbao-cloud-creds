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

type AkamaiServer struct {
	*httptest.Server
	mu         sync.Mutex
	clients    map[string]map[string]interface{}
	nextID     atomic.Int64
	nextCredID atomic.Int64
	nextStatus int
	// lastClientToken records the client_token parsed from the EdgeGrid
	// Authorization header of the most recent createClient call, so tests can
	// assert which minter's triple actually signed the request.
	lastClientToken string
}

func NewAkamaiServer() *AkamaiServer {
	s := &AkamaiServer{
		clients: make(map[string]map[string]interface{}),
	}
	s.nextID.Store(1000)
	s.nextCredID.Store(5000)
	s.Server = httptest.NewServer(s.handler())
	return s
}

// ProvisionedCount returns the number of API clients currently held by the fake.
func (s *AkamaiServer) ProvisionedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

// AddRawClient injects an API client with an arbitrary clientId and clientName
// directly into the fake, bypassing the create path. Test-only: used to plant
// foreign-named (non-cloud-creds-) entities that the reconciler must never
// delete.
func (s *AkamaiServer) AddRawClient(clientID, clientName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[clientID] = map[string]interface{}{
		"clientId":   clientID,
		"clientName": clientName,
		"isLocked":   false,
	}
}

// HasClient reports whether an API client with the given clientId is still held
// by the fake.
func (s *AkamaiServer) HasClient(clientID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.clients[clientID]
	return ok
}

func (s *AkamaiServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

func (s *AkamaiServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /identity-management/v3/api-clients/self", s.getSelf)
	mux.HandleFunc("GET /identity-management/v3/api-clients", s.listClients)
	mux.HandleFunc("POST /identity-management/v3/api-clients", s.createClient)
	mux.HandleFunc("DELETE /identity-management/v3/api-clients/", s.deleteClient)
	return mux
}

func (s *AkamaiServer) checkInjectedError(w http.ResponseWriter) bool {
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

// LastSigningClientToken returns the client_token extracted from the EdgeGrid
// Authorization header of the most recent successfully-authenticated request.
// Tests use this to prove a role signed with its own minter set's triple.
func (s *AkamaiServer) LastSigningClientToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastClientToken
}

// parseClientToken pulls the client_token value out of an EdgeGrid
// Authorization header of the form
// "EG1-HMAC-SHA256 client_token=...;access_token=...;...".
func parseClientToken(auth string) string {
	for _, part := range strings.Split(auth, ";") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "EG1-HMAC-SHA256 ")
		if strings.HasPrefix(part, "client_token=") {
			return strings.TrimPrefix(part, "client_token=")
		}
	}
	return ""
}

func (s *AkamaiServer) checkEdgeGridAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "EG1-HMAC-SHA256") {
		w.WriteHeader(401)
		writeJSON(w, map[string]interface{}{
			"type":   "https://problems.luna.akamaiapis.net/identity-management/unauthorized",
			"title":  "Unauthorized",
			"detail": "Missing or invalid EdgeGrid authorization",
		})
		return false
	}
	s.mu.Lock()
	s.lastClientToken = parseClientToken(auth)
	s.mu.Unlock()
	return true
}

func (s *AkamaiServer) createClient(w http.ResponseWriter, r *http.Request) {
	if !s.checkEdgeGridAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	// Check for createCredential query param
	createCred := r.URL.Query().Get("createCredential") == "true"

	var req struct {
		ClientName      string      `json:"clientName"`
		AuthorizedUsers []string    `json:"authorizedUsers"`
		APIAccess       interface{} `json:"apiAccess"`
		GroupAccess     interface{} `json:"groupAccess"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		writeJSON(w, map[string]interface{}{
			"type":   "https://problems.luna.akamaiapis.net/identity-management/bad-request",
			"title":  "Bad Request",
			"detail": "Invalid request body",
		})
		return
	}

	clientID := fmt.Sprintf("akamai-client-%d", s.nextID.Add(1))

	client := map[string]interface{}{
		"clientId":        clientID,
		"clientName":      req.ClientName,
		"authorizedUsers": req.AuthorizedUsers,
		"apiAccess":       req.APIAccess,
		"groupAccess":     req.GroupAccess,
		"isLocked":        false,
		"createdDate":     "2026-01-01T00:00:00Z",
	}

	var credentials []map[string]interface{}
	if createCred {
		credID := s.nextCredID.Add(1)
		credentials = append(credentials, map[string]interface{}{
			"credentialId": credID,
			"clientToken":  fmt.Sprintf("akab-ct-%s", clientID),
			"clientSecret": fmt.Sprintf("akab-cs-%s-secret", clientID),
			"accessToken":  fmt.Sprintf("akab-at-%s", clientID),
			"expiresOn":    "2028-01-01T00:00:00Z",
			"isActive":     true,
		})
		client["credentials"] = credentials
	}

	s.mu.Lock()
	s.clients[clientID] = client
	s.mu.Unlock()

	w.WriteHeader(201)
	writeJSON(w, client)
}

func (s *AkamaiServer) deleteClient(w http.ResponseWriter, r *http.Request) {
	if !s.checkEdgeGridAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	clientID := parts[len(parts)-1]

	s.mu.Lock()
	_, exists := s.clients[clientID]
	if exists {
		delete(s.clients, clientID)
	}
	s.mu.Unlock()

	if !exists {
		w.WriteHeader(404)
		writeJSON(w, map[string]interface{}{
			"type":   "https://problems.luna.akamaiapis.net/identity-management/not-found",
			"title":  "Not Found",
			"detail": "API client not found",
		})
		return
	}
	w.WriteHeader(204)
}

func (s *AkamaiServer) listClients(w http.ResponseWriter, r *http.Request) {
	if !s.checkEdgeGridAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	clients := make([]map[string]interface{}, 0, len(s.clients))
	for _, c := range s.clients {
		// List does not return credentials
		clients = append(clients, map[string]interface{}{
			"clientId":   c["clientId"],
			"clientName": c["clientName"],
			"isLocked":   c["isLocked"],
		})
	}
	s.mu.Unlock()

	writeJSON(w, clients)
}

func (s *AkamaiServer) getSelf(w http.ResponseWriter, r *http.Request) {
	if !s.checkEdgeGridAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	w.WriteHeader(200)
	writeJSON(w, map[string]interface{}{
		"clientId":    "minter-self-id",
		"clientName":  "cloud-creds-minter",
		"isLocked":    false,
		"createdDate": "2025-01-01T00:00:00Z",
	})
}
