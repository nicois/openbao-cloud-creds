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

// jsonKeyCanCreateTokens is the UpCloud token field marking a token as itself
// able to create further tokens (mint-capable). Recorded by the fake so a
// rotation test can assert the successor was minted mint-capable.
const jsonKeyCanCreateTokens = "can_create_tokens"

type UpCloudServer struct {
	*httptest.Server
	mu         sync.Mutex
	tokens     map[string]map[string]interface{}
	nextID     atomic.Int64
	nextStatus int
	// failHealthPrefix, when non-empty, makes GET /1.3/account return 500 for any
	// request whose basic-auth password has it as a prefix. Test-only: lets a
	// test fail freshly-minted successor tokens' CheckHealth deterministically
	// (the successor authenticates AS its own token, which the fake mints with a
	// distinct prefix) without disturbing the minting client's health.
	failHealthPrefix string
	// noMintPrefix, when non-empty, makes POST /1.3/account/tokens return 403 for
	// any request whose basic-auth password has it as a prefix. Test-only: models
	// an UpCloud token that authenticates but was created WITHOUT
	// can_create_tokens, which is invisible to GET /1.3/account.
	noMintPrefix string
}

func NewUpCloudServer() *UpCloudServer {
	s := &UpCloudServer{
		tokens: make(map[string]map[string]interface{}),
	}
	s.nextID.Store(fakeStartID)
	s.Server = httptest.NewServer(s.handler())
	return s
}

// ProvisionedCount returns the number of tokens currently held by the fake.
func (s *UpCloudServer) ProvisionedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

// AddRawToken injects a token with an arbitrary id and name directly into the
// fake, bypassing the create path. Test-only: used to plant foreign-named
// (non-cloud-creds-) entities that the reconciler must never delete.
func (s *UpCloudServer) AddRawToken(id, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[id] = map[string]interface{}{
		"id":        id,
		jsonKeyName: name,
	}
}

// AddRawTokenWithCreatedAt injects a token with an arbitrary id, name and
// created timestamp (RFC3339) directly into the fake. Test-only: used to plant
// an orphan with a controlled age for the fail-closed reconciler's confirmation
// hold.
func (s *UpCloudServer) AddRawTokenWithCreatedAt(id, name, created string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[id] = map[string]interface{}{
		"id":        id,
		jsonKeyName: name,
		"created":   created,
	}
}

// HasToken reports whether a token with the given id is still held by the fake.
func (s *UpCloudServer) HasToken(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tokens[id]
	return ok
}

func (s *UpCloudServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

// SetFailHealthForTokenPrefix makes GET /1.3/account return 500 for any request
// whose basic-auth password starts with prefix (empty disables). Test-only: the
// rotate successor health-check builds a client AS the successor token, which
// the fake mints with the "ucat_fake_" prefix, so failing that prefix exercises
// the successor-health-check-failed path while the minting client (a token with
// a different prefix) stays healthy.
func (s *UpCloudServer) SetFailHealthForTokenPrefix(prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failHealthPrefix = prefix
}

// SetForbidMintForTokenPrefix makes POST /1.3/account/tokens return 403 for any
// request whose basic-auth password starts with prefix (empty disables).
// Test-only: a token minted by this fake carries the "ucat_fake_" prefix, so
// forbidding that prefix models a rotation successor that is live and healthy
// but was not given can_create_tokens, while the operator-provided minters keep
// minting.
func (s *UpCloudServer) SetForbidMintForTokenPrefix(prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noMintPrefix = prefix
}

// CanCreateTokens reports the can_create_tokens flag recorded for a created
// token id (false if absent). Test-only: lets a rotation test assert the
// successor was minted itself-mint-capable.
func (s *UpCloudServer) CanCreateTokens(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[id]; ok {
		v, _ := t[jsonKeyCanCreateTokens].(bool)
		return v
	}
	return false
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
			jsonKeyError: map[string]interface{}{
				jsonKeyErrorCode:    errCodeServerError,
				jsonKeyErrorMessage: fmt.Sprintf("injected %d", status),
			},
		})
		return true
	}
	return false
}

func (s *UpCloudServer) checkBasicAuth(w http.ResponseWriter, r *http.Request) bool {
	username, password, ok := r.BasicAuth()
	if !ok || username == "" || password == "" {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]interface{}{
			jsonKeyError: map[string]interface{}{
				jsonKeyErrorCode:    "AUTHENTICATION_FAILED",
				jsonKeyErrorMessage: "missing or invalid credentials",
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

	_, password, _ := r.BasicAuth()
	s.mu.Lock()
	noMint := s.noMintPrefix
	s.mu.Unlock()
	if noMint != "" && strings.HasPrefix(password, noMint) {
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]interface{}{
			jsonKeyError: map[string]interface{}{
				"error_code":    "FORBIDDEN",
				"error_message": "this token is not permitted to create tokens",
			},
		})
		return
	}

	var req struct {
		Name            string `json:"name"`
		ExpiresIn       string `json:"expires_in"`
		CanCreateTokens bool   `json:"can_create_tokens"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
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
		"id":                   id,
		jsonKeyName:            req.Name,
		"token":                fmt.Sprintf("ucat_fake_%s", id),
		"expires_at":           expiresAt.UTC().Format(time.RFC3339),
		"created":              fakeCreatedAt,
		jsonKeyCanCreateTokens: req.CanCreateTokens,
	}

	s.mu.Lock()
	s.tokens[id] = token
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, token)
}

func (s *UpCloudServer) deleteToken(w http.ResponseWriter, r *http.Request) {
	if !s.checkBasicAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}
	deleteByID(w, r, &s.mu, s.tokens, http.StatusNoContent)
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

	// Per-token health failure: when the request authenticates as a token whose
	// value carries the prefix a test marked via SetFailHealthForTokenPrefix,
	// fail just those tokens' health checks.
	_, password, _ := r.BasicAuth()
	s.mu.Lock()
	failPrefix := s.failHealthPrefix
	s.mu.Unlock()
	if failPrefix != "" && strings.HasPrefix(password, failPrefix) {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]interface{}{
			jsonKeyError: map[string]interface{}{
				jsonKeyErrorCode:    errCodeServerError,
				jsonKeyErrorMessage: msgHealthCheckDisabledByKnob,
			},
		})
		return
	}
	// fakeAccountCredits is an arbitrary non-zero balance for the test account.
	const fakeAccountCredits = 100.0
	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]interface{}{
		jsonKeyAccount: map[string]interface{}{
			"username": "test-user",
			"credits":  fakeAccountCredits,
		},
	})
}
