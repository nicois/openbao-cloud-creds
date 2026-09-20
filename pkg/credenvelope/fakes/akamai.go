package fakes

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
)

// akamaiMaxBodyHashBytes mirrors the plugin's EdgeGrid cap on the number of
// body bytes folded into the content hash.
const akamaiMaxBodyHashBytes = 131072

// fakeIdentityManagementAPIID is the per-account apiId the fake returns for the
// Identity-Management API in the allowed-apis lookup. The plugin resolves this
// at rotation time rather than hard-coding it.
const fakeIdentityManagementAPIID = 4200

// accessLevelRW is the Akamai grant level the fake reports and accepts.
const accessLevelRW = "READ-WRITE"

// JSON keys of the apiAccess / groupAccess grant bodies the fake reports and
// parses.
const (
	jsonKeyAPIID       = "apiId"
	jsonKeyAPIName     = "apiName"
	jsonKeyAccessLevel = "accessLevel"
)

// fakeContentAPIID is the apiId of a non-Identity-Management API the fake's
// default self-grants include, standing in for whatever content API a minter
// hands out to its roles. Rotation must copy it onto the successor.
const fakeContentAPIID = 4300

// fakeSelfGroupID is the groupId in the fake's default self group-access.
const fakeSelfGroupID = 7700

// fakeIdentityManagementAPIName is the apiName the fake reports for the
// Identity-Management API; it must match the name the plugin matches on.
const fakeIdentityManagementAPIName = "Identity Management: API Clients"

const (
	jsonKeyClientID    = "clientId"
	jsonKeyClientName  = "clientName"
	jsonKeyIsLocked    = "isLocked"
	jsonKeyType        = "type"
	jsonKeyTitle       = "title"
	jsonKeyDetail      = "detail"
	jsonKeyCreatedDate = "createdDate"
)

type AkamaiServer struct {
	*httptest.Server
	mu         sync.Mutex
	clients    map[string]map[string]any
	nextID     atomic.Int64
	nextCredID atomic.Int64
	nextStatus int
	// lastClientToken records the client_token parsed from the EdgeGrid
	// Authorization header of the most recent createClient call, so tests can
	// assert which minter's triple actually signed the request.
	lastClientToken string
	// expectedSecrets maps client_token -> client_secret, for signature
	// validation. Tokens with no registered secret skip validation.
	expectedSecrets map[string]string
	// failHealthPrefix, when non-empty, makes GET /api-clients/self return 500
	// for any request whose signing client_token starts with the prefix. Lets a
	// rotation test fail only the successor's health check (the fake mints
	// successor tokens with the "akab-ct-" prefix) while the minting client
	// stays healthy.
	failHealthPrefix string
	// identityManagementAPIID is the per-account apiId returned by the
	// allowed-apis lookup for the Identity-Management API.
	identityManagementAPIID int
	// selfAPIAccess / selfGroupAccess are the grants GET /api-clients/self reports
	// for the signing credential. Rotation replicates these onto the successor, so
	// tests set them to assert the copy (SetSelfGrants).
	selfAPIAccess   any
	selfGroupAccess any
	// ungrantableAPIID, when non-zero, is an apiId this account's signing
	// credential may not delegate: creating an api client whose apiAccess includes
	// it returns 403. Models the real Akamai rule that an api client cannot grant
	// access it does not itself hold — the "authenticates but cannot mint" case
	// (SetUngrantableAPIID).
	ungrantableAPIID int
}

func NewAkamaiServer() *AkamaiServer {
	s := &AkamaiServer{
		clients:                 make(map[string]map[string]any),
		expectedSecrets:         make(map[string]string),
		identityManagementAPIID: fakeIdentityManagementAPIID,
	}
	maps.Copy(s.expectedSecrets, fakeStandardCredentials)
	s.nextID.Store(fakeStartID)
	s.nextCredID.Store(fakeStartCredID)
	// Default self-grants: a minter that can reach one content API plus
	// Identity-Management, which is the realistic shape of an operator-provisioned
	// minter (it must hold every api its roles hand out).
	s.selfAPIAccess = map[string]any{
		"allAccessibleApis": false,
		"apis": []map[string]any{
			{jsonKeyAPIID: fakeContentAPIID, jsonKeyAPIName: "CCU APIs", jsonKeyAccessLevel: accessLevelRW},
			{jsonKeyAPIID: fakeIdentityManagementAPIID, jsonKeyAPIName: fakeIdentityManagementAPIName, jsonKeyAccessLevel: accessLevelRW},
		},
	}
	s.selfGroupAccess = map[string]any{"groups": []map[string]any{{"groupId": fakeSelfGroupID}}}
	s.Server = httptest.NewServer(s.handler())
	return s
}

// SetSelfGrants overrides the apiAccess / groupAccess GET /api-clients/self
// reports. Test-only: rotation copies these onto the successor, so a test can
// give the incumbent a distinctive grant and assert the successor received it.
func (s *AkamaiServer) SetSelfGrants(apiAccess, groupAccess any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.selfAPIAccess = apiAccess
	s.selfGroupAccess = groupAccess
}

// IdentityManagementAPIID returns the per-account apiId the fake reports for the
// Identity-Management API in the allowed-apis lookup. Test-only: rotation
// resolves this id at run time, so a test asserting the successor's grants needs
// to know which id to look for.
func (s *AkamaiServer) IdentityManagementAPIID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identityManagementAPIID
}

// SetUngrantableAPIID makes POST /api-clients reject any request whose apiAccess
// includes the given apiId with 403, while GET /api-clients/self keeps
// succeeding. Test-only: this is the shape of a minter that is healthy but
// cannot mint what a role asks for.
func (s *AkamaiServer) SetUngrantableAPIID(apiID int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ungrantableAPIID = apiID
}

// GrantsForClient returns the apiAccess and groupAccess recorded for a created
// API client. Test-only: lets a rotation test assert what the successor was
// actually granted.
func (s *AkamaiServer) GrantsForClient(clientID string) (apiAccess, groupAccess any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return nil, nil
	}
	return c["apiAccess"], c["groupAccess"]
}

// fakeStandardCredentials are the minter triples (client_token -> client_secret)
// used across the akamai plugin's test suite. Registering them by default makes
// every test exercise real EG1-HMAC-SHA256 signature validation end-to-end
// without each call site having to wire RegisterCredential. Tokens not listed
// here are still accepted (validation is skipped) for back-compat.
var fakeStandardCredentials = map[string]string{
	"ct-test":     "cs-test",
	"ct-other":    "cs-other",
	"ct-reseeded": "cs-reseeded",
	"ct-a":        "cs-a",
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
	s.clients[clientID] = map[string]any{
		jsonKeyClientID:   clientID,
		jsonKeyClientName: clientName,
		jsonKeyIsLocked:   false,
	}
}

// AddRawClientWithCreatedDate injects an API client with an arbitrary clientId,
// clientName and createdDate (RFC3339) directly into the fake. Test-only: used
// to plant an orphan with a controlled age for the fail-closed reconciler's
// confirmation hold.
func (s *AkamaiServer) AddRawClientWithCreatedDate(clientID, clientName, createdDate string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[clientID] = map[string]any{
		jsonKeyClientID:    clientID,
		jsonKeyClientName:  clientName,
		jsonKeyIsLocked:    false,
		jsonKeyCreatedDate: createdDate,
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

// SetFailHealthForTokenPrefix makes GET /api-clients/self return 500 for any
// request whose signing client_token starts with prefix (empty disables).
// Test-only: the rotate successor health-check builds a client AS the successor
// token, which the fake mints with the "akab-ct-" prefix, so failing that
// prefix exercises the successor-health-check-failed path while the minting
// client (a token with a different prefix) stays healthy.
func (s *AkamaiServer) SetFailHealthForTokenPrefix(prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failHealthPrefix = prefix
}

// RegisterCredential tells the fake the client_secret to expect for a given
// client_token so it can validate the EG1-HMAC-SHA256 signature on requests
// signed with that token. Tests register the same triple they configure as the
// plugin's minter. Tokens with no registered secret skip validation
// (back-compat for tests that don't exercise signing).
func (s *AkamaiServer) RegisterCredential(clientToken, clientSecret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expectedSecrets[clientToken] = clientSecret
}

func (s *AkamaiServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /identity-management/v3/users/{username}/allowed-apis", s.allowedAPIs)
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
		writeJSON(w, map[string]any{
			jsonKeyError:   injectedErrorValue,
			jsonKeyMessage: fmt.Sprintf("injected %d", status),
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
	return edgeGridAuthField(auth, "client_token")
}

// edgeGridAuthField extracts a single semicolon-delimited field value (e.g.
// "client_token", "signature") from an EdgeGrid Authorization header.
func edgeGridAuthField(auth, key string) string {
	prefix := key + "="
	for part := range strings.SplitSeq(auth, ";") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "EG1-HMAC-SHA256 ")
		if after, ok := strings.CutPrefix(part, prefix); ok {
			return after
		}
	}
	return ""
}

// edgeGridAuthData returns the authData prefix of an EdgeGrid Authorization
// header: everything up to and including the last ';' that precedes the
// "signature=" field. The plugin signs over this exact substring concatenated
// with the canonical request, so taking it verbatim from the header avoids any
// re-formatting drift in field order/separators.
func edgeGridAuthData(auth string) string {
	before, _, ok := strings.Cut(auth, "signature=")
	if !ok {
		return ""
	}
	return before
}

// akamaiHMACSHA256 computes HMAC-SHA256, matching the plugin's signing primitive.
func akamaiHMACSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// validateEdgeGridSignature recomputes the EG1-HMAC-SHA256 signature from the
// received request using the registered client_secret and compares it to the
// presented signature. It returns true when the signature matches (or when no
// secret is registered for the token, in which case validation is skipped). It
// restores r.Body so the downstream handler can re-read it.
func (s *AkamaiServer) validateEdgeGridSignature(r *http.Request, auth string) bool {
	clientToken := parseClientToken(auth)

	s.mu.Lock()
	secret, registered := s.expectedSecrets[clientToken]
	s.mu.Unlock()
	if !registered {
		return true // back-compat: tokens with no registered secret skip validation
	}

	timestamp := edgeGridAuthField(auth, "timestamp")
	presented := edgeGridAuthField(auth, "signature")
	authData := edgeGridAuthData(auth)

	// Read and restore the body for the downstream handler.
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))

	bodyHash := ""
	if len(body) > 0 && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
		hashInput := body
		if len(hashInput) > akamaiMaxBodyHashBytes {
			hashInput = hashInput[:akamaiMaxBodyHashBytes]
		}
		sum := sha256.Sum256(hashInput)
		bodyHash = base64.StdEncoding.EncodeToString(sum[:])
	}

	scheme := schemeHTTPS
	if r.URL.Scheme != "" {
		scheme = r.URL.Scheme
	}
	// Behind httptest the request's scheme is empty and the transport speaks
	// plain HTTP, matching the plugin which reads req.URL.Scheme ("http").
	if scheme == schemeHTTPS {
		scheme = "http"
	}

	// Canonical request: method\tscheme\thost\tpath+query\theaders\tbody_hash\t
	canonicalRequest := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t",
		r.Method, scheme, r.Host, r.URL.RequestURI(), "", bodyHash)

	signingKey := akamaiHMACSHA256([]byte(secret), []byte(timestamp))
	expected := base64.StdEncoding.EncodeToString(
		akamaiHMACSHA256(signingKey, []byte(authData+canonicalRequest)),
	)

	return hmac.Equal([]byte(expected), []byte(presented))
}

func (s *AkamaiServer) writeUnauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	writeJSON(w, map[string]any{
		jsonKeyType:   "https://problems.luna.akamaiapis.net/identity-management/unauthorized",
		jsonKeyTitle:  "Unauthorized",
		jsonKeyDetail: "Missing or invalid EdgeGrid authorization",
	})
}

func (s *AkamaiServer) checkEdgeGridAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "EG1-HMAC-SHA256") {
		s.writeUnauthorized(w)
		return false
	}
	if !s.validateEdgeGridSignature(r, auth) {
		s.writeUnauthorized(w)
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
		ClientName      string   `json:"clientName"`
		AuthorizedUsers []string `json:"authorizedUsers"`
		APIAccess       any      `json:"apiAccess"`
		GroupAccess     any      `json:"groupAccess"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{
			jsonKeyType:   "https://problems.luna.akamaiapis.net/identity-management/bad-request",
			jsonKeyTitle:  "Bad Request",
			jsonKeyDetail: "Invalid request body",
		})
		return
	}

	s.mu.Lock()
	forbidden := s.ungrantableAPIID
	s.mu.Unlock()
	if forbidden != 0 && apiAccessGrants(req.APIAccess, forbidden) {
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]any{
			jsonKeyType:   "https://problems.luna.akamaiapis.net/identity-management/forbidden",
			jsonKeyTitle:  titleForbidden,
			jsonKeyDetail: fmt.Sprintf("you may not grant access to apiId %d", forbidden),
		})
		return
	}

	clientID := fmt.Sprintf("akamai-client-%d", s.nextID.Add(1))

	client := map[string]any{
		jsonKeyClientID:    clientID,
		jsonKeyClientName:  req.ClientName,
		"authorizedUsers":  req.AuthorizedUsers,
		"apiAccess":        req.APIAccess,
		"groupAccess":      req.GroupAccess,
		jsonKeyIsLocked:    false,
		jsonKeyCreatedDate: fakeCreatedAt,
	}

	var credentials []map[string]any
	if createCred {
		credID := s.nextCredID.Add(1)
		credentials = append(credentials, map[string]any{
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

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, client)
}

// apiAccessGrants reports whether a create-api-client apiAccess body asks for the
// given apiId. The body is whatever the caller sent, so every level is checked
// defensively rather than assumed.
func apiAccessGrants(apiAccess any, apiID int) bool {
	access, ok := apiAccess.(map[string]any)
	if !ok {
		return false
	}
	apis, ok := access["apis"].([]any)
	if !ok {
		return false
	}
	for _, entry := range apis {
		api, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := api[jsonKeyAPIID].(float64); ok && int(id) == apiID {
			return true
		}
	}
	return false
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
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{
			jsonKeyType:   "https://problems.luna.akamaiapis.net/identity-management/not-found",
			jsonKeyTitle:  "Not Found",
			jsonKeyDetail: "API client not found",
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *AkamaiServer) listClients(w http.ResponseWriter, r *http.Request) {
	if !s.checkEdgeGridAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	clients := make([]map[string]any, 0, len(s.clients))
	for _, c := range s.clients {
		// List does not return credentials
		clients = append(clients, map[string]any{
			jsonKeyClientID:    c[jsonKeyClientID],
			jsonKeyClientName:  c[jsonKeyClientName],
			jsonKeyIsLocked:    c[jsonKeyIsLocked],
			jsonKeyCreatedDate: c[jsonKeyCreatedDate],
		})
	}
	s.mu.Unlock()

	writeJSON(w, clients)
}

// allowedAPIs returns the per-user allowed-apis list. The rotation flow reads
// this to resolve the per-account Identity-Management apiId before granting the
// successor READ-WRITE on it.
func (s *AkamaiServer) allowedAPIs(w http.ResponseWriter, r *http.Request) {
	if !s.checkEdgeGridAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	apiID := s.identityManagementAPIID
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	writeJSON(w, []map[string]any{
		{
			jsonKeyAPIID:   apiID,
			jsonKeyAPIName: fakeIdentityManagementAPIName,
			"accessLevels": []string{"READ-ONLY", accessLevelRW},
		},
	})
}

func (s *AkamaiServer) getSelf(w http.ResponseWriter, r *http.Request) {
	if !s.checkEdgeGridAuth(w, r) {
		return
	}
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	failPrefix := s.failHealthPrefix
	token := s.lastClientToken
	s.mu.Unlock()
	if failPrefix != "" && strings.HasPrefix(token, failPrefix) {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{
			jsonKeyType:   "https://problems.luna.akamaiapis.net/identity-management/server-error",
			jsonKeyTitle:  "Server Error",
			jsonKeyDetail: msgHealthCheckDisabledByKnob,
		})
		return
	}

	s.mu.Lock()
	apiAccess, groupAccess := s.selfAPIAccess, s.selfGroupAccess
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]any{
		jsonKeyClientID:    "minter-self-id",
		jsonKeyClientName:  "cloud-creds-minter",
		jsonKeyIsLocked:    false,
		jsonKeyCreatedDate: "2025-01-01T00:00:00Z",
		"apiAccess":        apiAccess,
		"groupAccess":      groupAccess,
	})
}
