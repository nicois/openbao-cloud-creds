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

type AzureServer struct {
	*httptest.Server
	mu                sync.Mutex
	passwords         map[string]map[string]interface{} // keyId -> password credential
	nextID            atomic.Int64
	nextStatus        int
	tokenRequestCount atomic.Int64
	validClientID     string
	validClientSecret string
	appObjectID       string
	// tokenCreds records every (client_id, client_secret) pair presented to
	// the OAuth2 token endpoint, in order. Tests use this to prove which
	// minter's credentials actually reached Graph (no cross-minter bleed).
	tokenCreds [][2]string
}

func NewAzureServer() *AzureServer {
	s := &AzureServer{
		passwords:         make(map[string]map[string]interface{}),
		validClientID:     "fake-client-id",
		validClientSecret: "fake-client-secret",
		appObjectID:       "fake-app-object-id",
	}
	s.nextID.Store(1000)
	s.Server = httptest.NewServer(s.handler())
	return s
}

func (s *AzureServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

func (s *AzureServer) TokenRequestCount() int64 {
	return s.tokenRequestCount.Load()
}

func (s *AzureServer) PasswordCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.passwords)
}

// TokenCreds returns a copy of every (client_id, client_secret) pair presented
// to the OAuth2 token endpoint, in request order.
func (s *AzureServer) TokenCreds() [][2]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][2]string, len(s.tokenCreds))
	copy(out, s.tokenCreds)
	return out
}

func (s *AzureServer) handler() http.Handler {
	mux := http.NewServeMux()
	// OAuth2 token endpoint (login endpoint)
	mux.HandleFunc("POST /{tenant_id}/oauth2/v2.0/token", s.tokenEndpoint)
	// Graph API endpoints
	mux.HandleFunc("POST /v1.0/applications/{app_id}/addPassword", s.addPassword)
	mux.HandleFunc("POST /v1.0/applications/{app_id}/removePassword", s.removePassword)
	mux.HandleFunc("GET /v1.0/applications/{app_id}", s.getApplication)
	return mux
}

func (s *AzureServer) checkInjectedError(w http.ResponseWriter) bool {
	s.mu.Lock()
	status := s.nextStatus
	s.nextStatus = 0
	s.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		writeJSON(w, map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "ServerError",
				"message": fmt.Sprintf("injected %d", status),
			},
		})
		return true
	}
	return false
}

func (s *AzureServer) checkBearerAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) <= 7 {
		w.WriteHeader(401)
		writeJSON(w, map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "InvalidAuthenticationToken",
				"message": "Access token is empty.",
			},
		})
		return false
	}
	return true
}

func (s *AzureServer) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	s.tokenRequestCount.Add(1)

	if s.checkInjectedError(w) {
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(400)
		writeJSON(w, map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "failed to parse form",
		})
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		w.WriteHeader(400)
		writeJSON(w, map[string]interface{}{
			"error":             "unsupported_grant_type",
			"error_description": "only client_credentials is supported",
		})
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	s.mu.Lock()
	s.tokenCreds = append(s.tokenCreds, [2]string{clientID, clientSecret})
	s.mu.Unlock()

	if clientID == "" || clientSecret == "" {
		w.WriteHeader(401)
		writeJSON(w, map[string]interface{}{
			"error":             "invalid_client",
			"error_description": "client_id and client_secret are required",
		})
		return
	}

	// Return a fake token
	w.WriteHeader(200)
	writeJSON(w, map[string]interface{}{
		"token_type":   "Bearer",
		"expires_in":   3600,
		"access_token": fmt.Sprintf("eyJ0eXAiOi_fake_token_%s", clientID),
	})
}

func (s *AzureServer) addPassword(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	var req struct {
		PasswordCredential struct {
			DisplayName string `json:"displayName"`
			EndDateTime string `json:"endDateTime"`
		} `json:"passwordCredential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		writeJSON(w, map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "Request_BadRequest",
				"message": "unable to parse request body",
			},
		})
		return
	}

	keyID := fmt.Sprintf("azure-key-%d", s.nextID.Add(1))
	secretText := fmt.Sprintf("azs_fake_secret_%s", keyID)

	endDateTime := req.PasswordCredential.EndDateTime
	if endDateTime == "" {
		endDateTime = time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	}

	password := map[string]interface{}{
		"keyId":       keyID,
		"secretText":  secretText,
		"displayName": req.PasswordCredential.DisplayName,
		"endDateTime": endDateTime,
	}

	s.mu.Lock()
	s.passwords[keyID] = password
	s.mu.Unlock()

	w.WriteHeader(200)
	writeJSON(w, password)
}

func (s *AzureServer) removePassword(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	var req struct {
		KeyID string `json:"keyId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		return
	}

	s.mu.Lock()
	_, exists := s.passwords[req.KeyID]
	if exists {
		delete(s.passwords, req.KeyID)
	}
	s.mu.Unlock()

	if !exists {
		w.WriteHeader(404)
		writeJSON(w, map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "Request_ResourceNotFound",
				"message": "password credential not found",
			},
		})
		return
	}
	w.WriteHeader(204)
}

func (s *AzureServer) getApplication(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	passwords := make([]map[string]interface{}, 0, len(s.passwords))
	for _, p := range s.passwords {
		// List doesn't return secretText
		passwords = append(passwords, map[string]interface{}{
			"keyId":       p["keyId"],
			"displayName": p["displayName"],
			"endDateTime": p["endDateTime"],
		})
	}
	s.mu.Unlock()

	w.WriteHeader(200)
	writeJSON(w, map[string]interface{}{
		"id":                  s.appObjectID,
		"appId":               s.validClientID,
		"displayName":         "TestApp",
		"passwordCredentials": passwords,
	})
}
