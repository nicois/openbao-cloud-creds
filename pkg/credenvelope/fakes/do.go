package fakes

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
)

type DOServer struct {
	*httptest.Server
	mu     sync.Mutex
	tokens map[string]map[string]any
	// spacesKeys holds Spaces access keys, keyed by access_key. A SEPARATE store from
	// tokens because they are a different credential type with a different id space, a
	// different endpoint and — on real DigitalOcean — a different answer to whether a
	// PAT may manage them at all (token management is fenced, Spaces keys are not).
	spacesKeys         map[string]map[string]any
	nextID             atomic.Int64
	nextSpacesID       atomic.Int64
	nextStatus         int
	forbidCreate       bool
	forbidSpacesCreate bool
	fenceTokenMgmt     bool
	// forcedExtraScopes are added to every minted token's reported scopes, and withheldScopes
	// are removed from them: an API that grants something other than what was asked for. Knobs
	// rather than default behaviour because DigitalOcean is not observed doing either — token
	// management is fenced for our account (KI-009), so no recorded 200 exists to read — and a
	// fake that quietly diverged the two would make the driver's reporting untestable.
	//
	// Withholding is the direction that costs a caller something: a credential reported with a
	// permission it does not carry is refused by the upstream later, far from the role.
	forcedExtraScopes []string
	withheldScopes    []string
}

func NewDOServer() *DOServer {
	s := &DOServer{
		tokens:     make(map[string]map[string]any),
		spacesKeys: make(map[string]map[string]any),
	}
	s.nextID.Store(fakeStartID)
	s.nextSpacesID.Store(fakeStartCredID)
	s.Server = httptest.NewServer(s.handler())
	return s
}

// ProvisionedCount returns the number of tokens currently held by the fake.
func (s *DOServer) ProvisionedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

// AddRawToken injects a token with an arbitrary id and name directly into the
// fake, bypassing the create path. Test-only: used to plant foreign-named
// (non-cloud-creds-) entities that the reconciler must never delete.
func (s *DOServer) AddRawToken(id, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[id] = map[string]any{
		"id":        id,
		jsonKeyName: name,
	}
}

// AddRawTokenWithCreatedAt injects a token with an arbitrary id, name and
// created_at (RFC3339) directly into the fake. Test-only: used to plant an
// orphan with a controlled age so the fail-closed reconciler's confirmation
// hold can be exercised (delete-vs-skip by age).
func (s *DOServer) AddRawTokenWithCreatedAt(id, name, createdAt string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[id] = map[string]any{
		"id":             id,
		jsonKeyName:      name,
		jsonKeyCreatedAt: createdAt,
	}
}

// HasToken reports whether a token with the given id is still held by the fake.
func (s *DOServer) HasToken(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tokens[id]
	return ok
}

// ProvisionedSpacesKeyCount returns the number of Spaces access keys currently held
// by the fake. Counted separately from ProvisionedCount because the two credential
// types draw on separate upstream quotas (DO caps Spaces keys at 200 per account),
// so a per-class capacity assertion that summed them would pass for the wrong reason.
func (s *DOServer) ProvisionedSpacesKeyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.spacesKeys)
}

// AddRawSpacesKey injects a Spaces key with an arbitrary access key and name directly
// into the fake, bypassing the create path. Test-only: plants foreign-named keys the
// reconciler must never delete, and orphans it must.
func (s *DOServer) AddRawSpacesKey(accessKey, name string) {
	s.AddRawSpacesKeyWithCreatedAt(accessKey, name, fakeCreatedAt)
}

// AddRawSpacesKeyWithCreatedAt injects a Spaces key with a controlled created_at
// (RFC3339), so the reconciler's confirmation hold can be exercised by age.
func (s *DOServer) AddRawSpacesKeyWithCreatedAt(accessKey, name, createdAt string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.spacesKeys[accessKey] = map[string]any{
		jsonKeyName:      name,
		jsonKeyAccessKey: accessKey,
		jsonKeyGrants:    []any{},
		jsonKeyCreatedAt: createdAt,
	}
}

// HasSpacesKey reports whether a Spaces key with the given access key is still held
// by the fake. The access key is the identifier DO deletes by — there is no separate
// id — so it is what a lease has to remember in order to revoke.
func (s *DOServer) HasSpacesKey(accessKey string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.spacesKeys[accessKey]
	return ok
}

// SetForbidSpacesKeyCreate makes POST /v2/spaces/keys refuse with 403 until it is
// called again with false, while GET /v2/account keeps succeeding. Sticky and
// mint-only, for the same reason as SetForbidCreate.
//
// Deliberately a SEPARATE knob from SetForbidCreate rather than a shared one: on real
// DigitalOcean the two answers differ — token management is fenced for every PAT
// (KI-009) while `spaces_key:*` is grantable — so a single knob could not express the
// configuration that actually occurs, which is a minter able to mint one type and not
// the other.
func (s *DOServer) SetForbidSpacesKeyCreate(forbid bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forbidSpacesCreate = forbid
}

func (s *DOServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

// SetForbidCreate makes POST /v2/tokens refuse with 403 until it is called again
// with false, while GET /v2/account (the health check) keeps succeeding. Unlike
// SetNextStatus this is sticky and mint-specific, which is the shape the shared
// capability suite needs: a minter that authenticates but may not mint, across
// however many calls one configuration write makes.
func (s *DOServer) SetForbidCreate(forbid bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forbidCreate = forbid
}

// SetFenceTokenManagement models KI-009 as DigitalOcean actually presents it: the edge
// gateway refuses the whole /v2/tokens ROUTE for every PAT — create, list and delete
// alike — while every other endpoint on the same credential is served normally.
//
// Broader than SetForbidCreate, and kept separate from it because the two express
// different things. SetForbidCreate is a MINT privilege the capability suite needs; this
// is a route being closed regardless of privilege, which is the condition every real
// DigitalOcean account is in. It is what makes "one credential class cannot even be
// listed" testable — the case that decides whether orphan reclamation still works for the
// class that does.
func (s *DOServer) SetFenceTokenManagement(fenced bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fenceTokenMgmt = fenced
}

// SetForcedExtraScopes makes every minted token report permissions that were not requested.
func (s *DOServer) SetForcedExtraScopes(scopes []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forcedExtraScopes = scopes
}

// SetWithheldScopes makes every minted token report FEWER permissions than were requested, so a
// driver that publishes its own request rather than the response cannot pass.
func (s *DOServer) SetWithheldScopes(scopes []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.withheldScopes = scopes
}

// grantedScopes renders what the API decided to grant: what was asked for, plus anything forced,
// minus anything withheld.
func grantedScopes(requested, forced, withheld []string) []string {
	drop := make(map[string]bool, len(withheld))
	for _, s := range withheld {
		drop[s] = true
	}
	granted := make([]string, 0, len(requested)+len(forced))
	for _, s := range append(append([]string{}, requested...), forced...) {
		if !drop[s] {
			granted = append(granted, s)
		}
	}
	return granted
}

// fenced reports whether the /v2/tokens route is closed, and if so writes DO's exact
// edge-gateway refusal.
func (s *DOServer) fenced(w http.ResponseWriter) bool {
	s.mu.Lock()
	fenced := s.fenceTokenMgmt
	s.mu.Unlock()
	if !fenced {
		return false
	}
	// X-Response-From: Edge-Gateway is how the fence was IDENTIFIED against a real
	// account — the same PAT gets X-Response-From: service on endpoints that work — so the
	// fake reproduces it rather than only the status. A client that ever learns to
	// distinguish the two reads the same signal here.
	w.Header().Set("X-Response-From", "Edge-Gateway")
	w.WriteHeader(http.StatusForbidden)
	writeJSON(w, map[string]any{
		"id":           titleForbidden,
		jsonKeyMessage: msgOperationNotAllow,
	})
	return true
}

func (s *DOServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/account", s.getAccount)
	mux.HandleFunc("POST /v2/tokens", s.createToken)
	mux.HandleFunc("DELETE /v2/tokens/", s.deleteToken)
	mux.HandleFunc("GET /v2/tokens", s.listTokens)
	mux.HandleFunc("POST /v2/spaces/keys", s.createSpacesKey)
	mux.HandleFunc("DELETE /v2/spaces/keys/", s.deleteSpacesKey)
	mux.HandleFunc("GET /v2/spaces/keys", s.listSpacesKeys)
	return mux
}

func (s *DOServer) checkInjectedError(w http.ResponseWriter) bool {
	s.mu.Lock()
	status := s.nextStatus
	s.nextStatus = 0
	s.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		writeJSON(w, map[string]any{
			"id":           injectedErrorValue,
			jsonKeyMessage: fmt.Sprintf("injected %d", status),
		})
		return true
	}
	return false
}

func (s *DOServer) createToken(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}
	if s.fenced(w) {
		return
	}

	s.mu.Lock()
	forbidCreate := s.forbidCreate
	forced, withheld := s.forcedExtraScopes, s.withheldScopes
	s.mu.Unlock()
	if forbidCreate {
		w.WriteHeader(http.StatusForbidden)
		// Byte-for-byte what real DO returns to a PAT that is live but not
		// authorized for token management — recorded from a real account in
		// plugins/credential-do/testdata/cloud-real/POST_v2_tokens_403.json.
		// The capitalised "Forbidden" and the generic message are DO's, not a
		// convenience for the test: a fake that invents friendlier errors is a
		// fake whose error handling is untested.
		writeJSON(w, map[string]any{
			"id":           titleForbidden,
			jsonKeyMessage: msgOperationNotAllow,
		})
		return
	}

	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	id := fmt.Sprintf("tok-%d", s.nextID.Add(1))
	token := map[string]any{
		"id":               id,
		jsonKeyName:        req.Name,
		"scopes":           grantedScopes(req.Scopes, forced, withheld),
		jsonKeyAccessToken: fmt.Sprintf("dop_v1_fake_%s", id),
		jsonKeyCreatedAt:   fakeCreatedAt,
	}

	s.mu.Lock()
	s.tokens[id] = token
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"token": token})
}

func (s *DOServer) deleteToken(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}
	if s.fenced(w) {
		return
	}
	deleteByID(w, r, &s.mu, s.tokens, http.StatusNoContent)
}

func (s *DOServer) listTokens(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}
	if s.fenced(w) {
		return
	}

	s.mu.Lock()
	tokens := make([]map[string]any, 0, len(s.tokens))
	for _, t := range s.tokens {
		tokens = append(tokens, t)
	}
	s.mu.Unlock()

	// Deliberately NOT paginated, unlike the Spaces listing beside it. `/v2/tokens` is
	// absent from DigitalOcean's published spec (KI-009), so there is no documented
	// per_page, no documented envelope, and no way to check a guess — and the endpoint is
	// fenced at DO's edge gateway for every PAT, so this listing never runs against the real
	// API. Inventing pagination here would put a shape in the fake that nothing verifies,
	// which is the opposite of what a fake is for. Don't "fix" it for symmetry.
	writeJSON(w, map[string]any{"tokens": tokens})
}

// createSpacesKey mirrors POST /v2/spaces/keys: 201 with the full key object, and the
// secret_key present for the ONLY time in the key's life. The fake does not retain the
// secret at all — not even privately — so no later handler can serve it even by
// mistake, which is the property a plugin must be held to (it has to persist the secret
// in the lease at mint time; there is no recovering it afterwards).
func (s *DOServer) createSpacesKey(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	forbid := s.forbidSpacesCreate
	s.mu.Unlock()
	if forbid {
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]any{
			"id":           titleForbidden,
			jsonKeyMessage: msgOperationNotAllow,
		})
		return
	}

	var req struct {
		Name   string           `json:"name"`
		Grants []map[string]any `json:"grants"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	n := s.nextSpacesID.Add(1)
	// Fixed-width and upper-case, so a plugin that truncated or lower-cased the key is
	// caught here rather than in production. The exact width is this fake's choice and not
	// a documented DO format: the spec's only instance is the placeholder
	// DOACCESSKEYEXAMPLE, and no recording exists yet to pin the real shape.
	accessKey := fmt.Sprintf("DO00FAKEACCESS%06d", n)
	grants := req.Grants
	if grants == nil {
		grants = []map[string]any{}
	}

	key := map[string]any{
		jsonKeyName:      req.Name,
		jsonKeyAccessKey: accessKey,
		jsonKeyGrants:    grants,
		jsonKeyCreatedAt: fakeCreatedAt,
	}

	s.mu.Lock()
	s.spacesKeys[accessKey] = key
	s.mu.Unlock()

	// The secret is added to the RESPONSE only, never to the stored record.
	response := make(map[string]any, len(key)+1)
	maps.Copy(response, key)
	response[jsonKeySecretKey] = fmt.Sprintf("fake-spaces-secret-%d", n)

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"key": response})
}

func (s *DOServer) deleteSpacesKey(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}
	deleteByID(w, r, &s.mu, s.spacesKeys, http.StatusNoContent)
}

func (s *DOServer) listSpacesKeys(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	keys := make([]map[string]any, 0, len(s.spacesKeys))
	for _, k := range s.spacesKeys {
		keys = append(keys, k)
	}
	s.mu.Unlock()

	// Sorted before paging, and that is not cosmetic: paging over Go's randomised map
	// iteration would put the same key on two pages and another key on none, so a correctly
	// paging client would look broken. Access key is the sort field because it is the one
	// value guaranteed unique — created_at is a constant in this fake.
	sort.Slice(keys, func(i, j int) bool {
		left, _ := keys[i][jsonKeyAccessKey].(string)
		right, _ := keys[j][jsonKeyAccessKey].(string)
		return left < right
	})

	writeJSON(w, paginateDO(r, "keys", keys))
}

func (s *DOServer) getAccount(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}
	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]any{
		jsonKeyAccount: map[string]any{
			"uuid":   "fake-account-uuid",
			"status": "active",
		},
	})
}
