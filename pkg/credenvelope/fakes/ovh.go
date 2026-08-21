package fakes

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
)

// OVHServer is a fake OVH OAuth2 token endpoint for integration tests.
type OVHServer struct {
	*httptest.Server
	mu         sync.Mutex
	nextStatus int
	forbidMint bool
	tokenCount atomic.Int64
	// ValidClients maps client_id -> client_secret for validation
	ValidClients map[string]string
}

// NewOVHServer creates a new fake OVH OAuth2 token server with a default valid client.
func NewOVHServer() *OVHServer {
	s := &OVHServer{
		ValidClients: map[string]string{
			"test-client-id": "test-client-secret",
		},
	}
	s.Server = httptest.NewServer(s.handler())
	return s
}

// SetNextStatus injects a one-shot HTTP status code for the next request.
func (s *OVHServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

// SetForbidMint makes the token endpoint refuse every mint with 403
// insufficient_scope until it is called again with false. Unlike SetNextStatus
// this is sticky, which is what the shared capability suite needs: the "minter
// authenticates but may not mint" shape must persist across the several calls a
// configuration write makes. On OVH minting IS the health check — the same
// endpoint answers both — so a forbidden mint necessarily also fails health;
// that is a property of the cloud, not of this fake.
func (s *OVHServer) SetForbidMint(forbid bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forbidMint = forbid
}

// TokenCount returns the total number of tokens issued by this fake.
func (s *OVHServer) TokenCount() int64 {
	return s.tokenCount.Load()
}

// ProvisionedCount returns the number of tokens issued by the fake.
func (s *OVHServer) ProvisionedCount() int {
	return int(s.TokenCount())
}

func (s *OVHServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/oauth2/token", s.tokenEndpoint)
	return mux
}

func (s *OVHServer) checkInjectedError(w http.ResponseWriter) bool {
	s.mu.Lock()
	status := s.nextStatus
	s.nextStatus = 0
	s.mu.Unlock()

	if status != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		writeJSON(w, map[string]interface{}{
			jsonKeyError:            injectedErrorValue,
			jsonKeyErrorDescription: fmt.Sprintf("injected %d", status),
		})
		return true
	}
	return false
}

func (s *OVHServer) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}

	if err := r.ParseForm(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]interface{}{
			jsonKeyError:            "invalid_request",
			jsonKeyErrorDescription: "failed to parse form",
		})
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]interface{}{
			jsonKeyError:            "unsupported_grant_type",
			jsonKeyErrorDescription: fmt.Sprintf("unsupported grant_type: %s", grantType),
		})
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	s.mu.Lock()
	expectedSecret, clientExists := s.ValidClients[clientID]
	forbidMint := s.forbidMint
	s.mu.Unlock()

	if forbidMint {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]interface{}{
			jsonKeyError:            "insufficient_scope",
			jsonKeyErrorDescription: "this service account may not mint tokens",
		})
		return
	}

	if !clientExists || clientSecret != expectedSecret {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]interface{}{
			jsonKeyError:            "invalid_client",
			jsonKeyErrorDescription: "invalid client_id or client_secret",
		})
		return
	}

	n := s.tokenCount.Add(1)
	token := fmt.Sprintf("ovh-fake-token-%d", n)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]interface{}{
		jsonKeyAccessToken: token,
		"token_type":       "Bearer",
		"expires_in":       fakeTokenExpirySeconds,
	})
}

// AddClient registers a valid client_id/client_secret pair.
func (s *OVHServer) AddClient(clientID, clientSecret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ValidClients[clientID] = clientSecret
}

// TokensIssued returns the raw token map for assertions.
// For OVH, tokens are ephemeral and not tracked server-side.
func (s *OVHServer) TokensIssued() int64 {
	return s.tokenCount.Load()
}

// TokenEndpointURL returns the full URL for the token endpoint.
func (s *OVHServer) TokenEndpointURL() string {
	return s.URL + "/auth/oauth2/token"
}
