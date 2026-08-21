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

const (
	jsonKeyAzureKeyID    = "keyId"
	jsonKeyDisplayName   = "displayName"
	jsonKeyEndDateTime   = "endDateTime"
	jsonKeyStartDateTime = "startDateTime"
)

type AzureServer struct {
	*httptest.Server
	mu         sync.Mutex
	passwords  map[string]map[string]interface{} // keyId -> password credential
	nextID     atomic.Int64
	nextStatus int
	failGetApp bool
	// forbiddenApps names app registrations whose addPassword returns 403,
	// modelling a service principal that may read an application but is not an
	// owner of it (Application.ReadWrite.OwnedBy without ownership).
	forbiddenApps     map[string]bool
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
		forbiddenApps:     make(map[string]bool),
	}
	s.nextID.Store(fakeStartID)
	s.Server = httptest.NewServer(s.handler())
	return s
}

func (s *AzureServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

// SetFailGetApplication makes every GetApplication request return 500 until
// reset. Test-only: lets a test fail a minter's CheckHealth (which calls
// GetApplication) deterministically, e.g. to exercise the rotate
// successor-health-check-failed path.
func (s *AzureServer) SetFailGetApplication(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failGetApp = fail
}

// SetAddPasswordForbidden makes addPassword on the named app registration
// return 403 while every other app keeps working. Test-only: models the minter
// that authenticates, and can even read the application, but cannot mint on it.
func (s *AzureServer) SetAddPasswordForbidden(appObjectID string, forbidden bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forbiddenApps[appObjectID] = forbidden
}

func (s *AzureServer) TokenRequestCount() int64 {
	return s.tokenRequestCount.Load()
}

func (s *AzureServer) PasswordCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.passwords)
}

// ProvisionedCount returns the number of password credentials currently held by the fake.
func (s *AzureServer) ProvisionedCount() int {
	return s.PasswordCount()
}

// AddRawPassword injects a password credential with an arbitrary keyId and
// displayName directly into the fake, bypassing addPassword. Test-only: used to
// plant foreign-named (non-cloud-creds-) entities that the reconciler must
// never delete. The password is attached to the fake's single application
// (the one returned by GetApplication).
func (s *AzureServer) AddRawPassword(keyID, displayName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwords[keyID] = map[string]interface{}{
		jsonKeyAzureKeyID:  keyID,
		jsonKeyDisplayName: displayName,
		jsonKeyEndDateTime: "2099-01-01T00:00:00Z",
	}
}

// AddRawPasswordWithStartDateTime injects a password credential with an
// arbitrary keyId, displayName and startDateTime (RFC3339) directly into the
// fake. Test-only: used to plant an orphan with a controlled age for the
// fail-closed reconciler's confirmation hold.
func (s *AzureServer) AddRawPasswordWithStartDateTime(keyID, displayName, startDateTime string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwords[keyID] = map[string]interface{}{
		jsonKeyAzureKeyID:    keyID,
		jsonKeyDisplayName:   displayName,
		jsonKeyEndDateTime:   "2099-01-01T00:00:00Z",
		jsonKeyStartDateTime: startDateTime,
	}
}

// HasPassword reports whether a password credential with the given keyId is
// still held by the fake.
func (s *AzureServer) HasPassword(keyID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.passwords[keyID]
	return ok
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
			jsonKeyError: map[string]interface{}{
				jsonKeyCode:    "ServerError",
				jsonKeyMessage: fmt.Sprintf("injected %d", status),
			},
		})
		return true
	}
	return false
}

func (s *AzureServer) checkBearerAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) <= 7 {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]interface{}{
			jsonKeyError: map[string]interface{}{
				jsonKeyCode:    "InvalidAuthenticationToken",
				jsonKeyMessage: "Access token is empty.",
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
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]interface{}{
			jsonKeyError:            "invalid_request",
			jsonKeyErrorDescription: "failed to parse form",
		})
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]interface{}{
			jsonKeyError:            "unsupported_grant_type",
			jsonKeyErrorDescription: "only client_credentials is supported",
		})
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	s.mu.Lock()
	s.tokenCreds = append(s.tokenCreds, [2]string{clientID, clientSecret})
	s.mu.Unlock()

	if clientID == "" || clientSecret == "" {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]interface{}{
			jsonKeyError:            "invalid_client",
			jsonKeyErrorDescription: "client_id and client_secret are required",
		})
		return
	}

	// Return a fake token
	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]interface{}{
		"token_type":       "Bearer",
		"expires_in":       fakeTokenExpirySeconds,
		jsonKeyAccessToken: fmt.Sprintf("eyJ0eXAiOi_fake_token_%s", clientID),
	})
}

func (s *AzureServer) addPassword(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	appID := r.PathValue("app_id")
	s.mu.Lock()
	forbidden := s.forbiddenApps[appID]
	s.mu.Unlock()
	if forbidden {
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]interface{}{
			jsonKeyError: map[string]interface{}{
				jsonKeyCode:    "Authorization_RequestDenied",
				jsonKeyMessage: "Insufficient privileges to complete the operation.",
			},
		})
		return
	}

	var req struct {
		PasswordCredential struct {
			DisplayName string `json:"displayName"`
			EndDateTime string `json:"endDateTime"`
		} `json:"passwordCredential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]interface{}{
			jsonKeyError: map[string]interface{}{
				jsonKeyCode:    "Request_BadRequest",
				jsonKeyMessage: "unable to parse request body",
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
		jsonKeyAzureKeyID:    keyID,
		"secretText":         secretText,
		jsonKeyDisplayName:   req.PasswordCredential.DisplayName,
		jsonKeyEndDateTime:   endDateTime,
		jsonKeyStartDateTime: time.Now().UTC().Format(time.RFC3339),
	}

	s.mu.Lock()
	s.passwords[keyID] = password
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	_, exists := s.passwords[req.KeyID]
	if exists {
		delete(s.passwords, req.KeyID)
	}
	s.mu.Unlock()

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]interface{}{
			jsonKeyError: map[string]interface{}{
				jsonKeyCode:    "Request_ResourceNotFound",
				jsonKeyMessage: "password credential not found",
			},
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *AzureServer) getApplication(w http.ResponseWriter, r *http.Request) {
	if !s.checkBearerAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	failGetApp := s.failGetApp
	s.mu.Unlock()
	if failGetApp {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]interface{}{
			jsonKeyError: map[string]interface{}{
				jsonKeyCode:    "ServerError",
				jsonKeyMessage: "get application disabled by test knob",
			},
		})
		return
	}

	s.mu.Lock()
	passwords := make([]map[string]interface{}, 0, len(s.passwords))
	for _, p := range s.passwords {
		// List doesn't return secretText
		passwords = append(passwords, map[string]interface{}{
			jsonKeyAzureKeyID:    p[jsonKeyAzureKeyID],
			jsonKeyDisplayName:   p[jsonKeyDisplayName],
			jsonKeyEndDateTime:   p[jsonKeyEndDateTime],
			jsonKeyStartDateTime: p[jsonKeyStartDateTime],
		})
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]interface{}{
		"id":                  s.appObjectID,
		"appId":               s.validClientID,
		jsonKeyDisplayName:    "TestApp",
		"passwordCredentials": passwords,
	})
}
