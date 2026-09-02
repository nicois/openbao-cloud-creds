package credentialakamai

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Local literals these rotation tests repeat, hoisted to consts so the
// package-wide goconst count stays below threshold. minterTokenKey ("token"),
// pathConfigKey, fieldMintersKey, pathMinterSetWrite and fieldExpiresAt /
// fieldAPIURL are already declared elsewhere in this (internal) package and are
// reused here.
const (
	rotatePath        = "minter-sets/default/rotate"
	rotationParamsKey = "rotation_params"
	idKey             = "id"
	testUsername      = "minter-svc-user"
	testHost          = "akab-test.luna.akamaiapis.net"
	defaultSetName    = "default"
	clientIDKey       = "client_id"
	usernameKey       = "username"
	minter1Token      = "ct-1:at-1:cs-1"
	minter2Token      = "ct-2:at-2:cs-2"
)

// newRotationBackend builds an Akamai backend via Factory wired to a fake
// Identity-Management server, with config written and the given minter-set
// written through the API. It returns the backend, the fake server, and the
// storage view.
func newRotationBackend(t *testing.T, minters []interface{}) (*backend, *fakes.AkamaiServer, logical.Storage) {
	t.Helper()
	srv := fakes.NewAkamaiServer()
	t.Cleanup(srv.Close)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	bk := b.(*backend)
	storage := config.StorageView

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]interface{}{
			fieldHost:   testHost,
			fieldAPIURL: srv.URL,
		},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathMinterSetWrite, Storage: storage,
		Data: map[string]interface{}{fieldMintersKey: minters},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write: err=%v resp=%v", err, resp)
	}
	return bk, srv, storage
}

// loadSetFromStorage reads the persisted default minter set straight from storage.
func loadSetFromStorage(t *testing.T, storage logical.Storage) cloudconfig.MinterSet {
	t.Helper()
	entry, err := storage.Get(t.Context(), pathMinterSetWrite)
	if err != nil {
		t.Fatalf("get set: %v", err)
	}
	if entry == nil {
		t.Fatalf("set %q not in storage", defaultSetName)
	}
	var set cloudconfig.MinterSet
	if err := json.Unmarshal(entry.Value, &set); err != nil {
		t.Fatalf("unmarshal set: %v", err)
	}
	return set
}

// neverExpiresMinter builds a never-expiring minter map for the minter-set API,
// carrying the username rotation param the rotation flow needs.
func neverExpiresMinter(id, token string) map[string]interface{} {
	return map[string]interface{}{
		idKey: id, minterTokenKey: token, neverExpiresKey: true,
		rotationParamsKey: map[string]interface{}{usernameKey: testUsername},
	}
}

// TestMinterRotation_HappyPath: rotating an active minter resolves the
// per-account Identity-Management apiId, mints a successor API client granted
// READ-WRITE on it, validates the successor, swaps it in (3 minters: 2 active +
// 1 retired), and the retired minter is never selected while the successor is.
func TestMinterRotation_HappyPath(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresMinter("minter-1", minter1Token),
		neverExpiresMinter("minter-2", minter2Token),
	})

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: "minter-1"},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate: err=%v resp=%v", err, resp)
	}
	successorID, _ := resp.Data["successor_id"].(string)
	if successorID == "" {
		t.Fatalf("response missing successor_id: %v", resp.Data)
	}
	if resp.Data["retired_minter_id"] != "minter-1" {
		t.Fatalf("retired_minter_id = %v, want minter-1", resp.Data["retired_minter_id"])
	}
	if _, ok := resp.Data["retired_at"].(time.Time); !ok {
		t.Fatalf("response missing retired_at time: %v", resp.Data)
	}

	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 3 {
		t.Fatalf("set has %d minters, want 3 (2 active + 1 retired)", len(set.Minters))
	}
	var retired, successor *cloudconfig.Minter
	for i := range set.Minters {
		m := &set.Minters[i]
		if m.ID == "minter-1" {
			retired = m
		}
		if m.ID == successorID {
			successor = m
		}
	}
	if retired == nil || !retired.Retired || retired.RetiredAt.IsZero() {
		t.Fatalf("minter-1 should be retired with RetiredAt set, got %+v", retired)
	}
	if successor == nil || successor.Retired {
		t.Fatalf("successor %q should be active, got %+v", successorID, successor)
	}
	// The successor must carry the upstream clientId (for the retired-sweep
	// delete) and the username (so it can itself be rotated later).
	successorClientID := successor.RotationParams[clientIDKey]
	if successorClientID == "" {
		t.Fatalf("successor missing client_id rotation param: %+v", successor.RotationParams)
	}
	if successor.RotationParams[usernameKey] != testUsername {
		t.Fatalf("successor missing username rotation param: %+v", successor.RotationParams)
	}
	// The successor's upstream API client exists in the fake.
	if !srv.HasClient(successorClientID) {
		t.Fatalf("successor upstream client %q not created", successorClientID)
	}

	// selectMinter must never return the retired minter (deterministic regardless
	// of map-iteration order).
	for range 10 {
		sel, err := bk.selectMinter(defaultSetName, "", mintercapacity.State{}, time.Now())
		if err != nil {
			t.Fatalf("selectMinter: %v", err)
		}
		if sel.minterID == "minter-1" {
			t.Fatal("retired minter-1 must never be selected")
		}
	}
	// Deterministic: the successor is present, active (not retired), and Selectable.
	bk.mu.RLock()
	ms, ok := bk.minterSets[defaultSetName][successorID]
	bk.mu.RUnlock()
	if !ok {
		t.Fatalf("successor %q not in the in-memory set", successorID)
	}
	if ms.minter.Retired {
		t.Fatal("successor must not be retired")
	}
	if !ms.sm.Selectable(time.Now()) {
		t.Fatal("successor must be selectable")
	}
}

// TestMinterRotation_RejectedBreaksValidation: a set of two expiring minters is
// valid (their expiries are far apart), but rotating minter-2 would yield a
// successor expiring far out, landing within 7d of minter-1's expiry — so the
// prospective set fails the >=7d-gap rule. Validation runs against a synthetic
// successor BEFORE any cloud call, so the rotate is rejected with no state
// change AND without ever creating an upstream API client.
func TestMinterRotation_RejectedBreaksValidation(t *testing.T) {
	// minter-1 expires 3 days BEFORE the successor lands; minter-2 expires 40d
	// out (far from minter-1, so the original set validates).
	nearSuccessor := time.Now().Add(minterSecretLifetime - 3*24*time.Hour).UTC().Format(time.RFC3339)
	later := time.Now().Add(40 * 24 * time.Hour).UTC().Format(time.RFC3339)
	expiringMinter := func(id, token, exp string) map[string]interface{} {
		return map[string]interface{}{
			idKey: id, minterTokenKey: token, fieldExpiresAt: exp,
			rotationParamsKey: map[string]interface{}{usernameKey: testUsername},
		}
	}
	bk, srv, storage := newRotationBackend(t, []interface{}{
		expiringMinter("minter-1", minter1Token, nearSuccessor),
		expiringMinter("minter-2", minter2Token, later),
	})
	beforeClients := srv.ProvisionedCount()

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: "minter-2"},
	})
	if err != nil {
		t.Fatalf("rotate err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected rejection error response, got %v", resp)
	}

	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 2 {
		t.Fatalf("set should be unchanged (2 minters), got %d", len(set.Minters))
	}
	for i := range set.Minters {
		if set.Minters[i].Retired {
			t.Fatalf("no minter should be retired after a rejected rotation: %+v", set.Minters[i])
		}
	}
	// Validation runs BEFORE any cloud call, so a rejected rotation must never
	// reach create-api-client at all: the upstream client count stays exactly at
	// baseline (stronger than "cleaned up back to baseline" — no create happened).
	if srv.ProvisionedCount() != beforeClients {
		t.Fatalf("rejected rotation must not create an api client at all; client count %d -> %d", beforeClients, srv.ProvisionedCount())
	}
}

// TestMinterRotation_RejectedSuccessorHealthCheckFails: the successor is minted
// but its health-check (authenticating AS the successor) fails; the successor's
// just-created upstream client must be cleaned up and the set left unchanged.
func TestMinterRotation_RejectedSuccessorHealthCheckFails(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresMinter("minter-1", minter1Token),
		neverExpiresMinter("minter-2", minter2Token),
	})
	beforeClients := srv.ProvisionedCount()

	// Make the successor's CheckHealth (GET /api-clients/self) fail. The fake
	// mints successor client tokens with the "akab-ct-" prefix, so failing that
	// prefix fails only the successor's health check, not the minting client.
	srv.SetFailHealthForTokenPrefix("akab-ct-")

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: "minter-1"},
	})
	if err != nil {
		t.Fatalf("rotate err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected health-check rejection, got %v", resp)
	}

	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 2 {
		t.Fatalf("set should be unchanged (2 minters), got %d", len(set.Minters))
	}
	for i := range set.Minters {
		if set.Minters[i].Retired {
			t.Fatalf("no minter should be retired after failed health check: %+v", set.Minters[i])
		}
	}
	// The cleanup deletes the just-created successor client, so the upstream
	// client count returns to baseline.
	if srv.ProvisionedCount() != beforeClients {
		t.Fatalf("successor client should have been cleaned up; client count %d -> %d", beforeClients, srv.ProvisionedCount())
	}
}

// TestRotateConfig_MinterRetireGraceRoundTrip writes minter_retire_grace and
// reads it back.
func TestRotateConfig_MinterRetireGraceRoundTrip(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresMinter("minter-1", minter1Token),
		neverExpiresMinter("minter-2", minter2Token),
	})

	if resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]interface{}{
			fieldHost:              testHost,
			fieldAPIURL:            srv.URL,
			fieldMinterRetireGrace: 86400,
		},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: pathConfigKey, Storage: storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config read: err=%v resp=%v", err, resp)
	}
	if got := resp.Data[fieldMinterRetireGrace]; got != 86400 {
		t.Fatalf("minter_retire_grace = %v, want 86400", got)
	}
}

// TestRetireSweep_DropsAfterGraceKeepsBeforeGrace: a minter retired 8d ago
// (past the 7d grace) is swept (upstream client deleted + dropped from set); a
// minter retired 1h ago is kept.
func TestRetireSweep_DropsAfterGraceKeepsBeforeGrace(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresMinter("active-1", minter1Token),
		neverExpiresMinter("old-expired", minter2Token),
		neverExpiresMinter("recent", "ct-3:at-3:cs-3"),
	})

	// Plant upstream API clients the sweep should DELETE, recording their
	// clientIds in the retired minters' rotation params.
	srv.AddRawClient("old-client", ownertag.CredentialName(ownerInstanceForTest(t, storage), "minter-old", "expired"))
	srv.AddRawClient("recent-client", ownertag.CredentialName(ownerInstanceForTest(t, storage), "minter", "recent"))
	if !srv.HasClient("old-client") || !srv.HasClient("recent-client") {
		t.Fatal("setup: planted clients missing")
	}

	// Mark two minters retired in storage with controlled RetiredAt + client_ids.
	set := loadSetFromStorage(t, storage)
	now := time.Now()
	for i := range set.Minters {
		switch set.Minters[i].ID {
		case "old-expired":
			set.Minters[i].Retired = true
			set.Minters[i].RetiredAt = now.Add(-8 * 24 * time.Hour)
			set.Minters[i].RotationParams = map[string]string{usernameKey: testUsername, clientIDKey: "old-client"}
		case "recent":
			set.Minters[i].Retired = true
			set.Minters[i].RetiredAt = now.Add(-1 * time.Hour)
			set.Minters[i].RotationParams = map[string]string{usernameKey: testUsername, clientIDKey: "recent-client"}
		}
	}
	entry, err := logical.StorageEntryJSON(pathMinterSetWrite, &set)
	if err != nil {
		t.Fatalf("encode set: %v", err)
	}
	if err := storage.Put(t.Context(), entry); err != nil {
		t.Fatalf("put set: %v", err)
	}
	bk.loadMinterSet(&set)

	if err := bk.sweepRetiredMinters(t.Context(), storage, now); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// old-expired: upstream client deleted + dropped from the set.
	if srv.HasClient("old-client") {
		t.Fatal("old-expired's upstream client should have been deleted")
	}
	// recent: untouched (within grace).
	if !srv.HasClient("recent-client") {
		t.Fatal("recent (within grace) must NOT be swept")
	}

	after := loadSetFromStorage(t, storage)
	ids := map[string]bool{}
	for i := range after.Minters {
		ids[after.Minters[i].ID] = true
	}
	if ids["old-expired"] {
		t.Fatal("old-expired should have been dropped from the set")
	}
	if !ids["recent"] {
		t.Fatal("recent should still be in the set")
	}
	if !ids["active-1"] {
		t.Fatal("active-1 should still be in the set")
	}
}

// ownerInstanceForTest resolves (and on first call mints) the mount's owner instance id
// from the same storage the backend reads it from, so a seeded orphan carries the prefix
// the reconciler will actually match (A19).
func ownerInstanceForTest(t *testing.T, storage logical.Storage) string {
	t.Helper()
	id, err := ownertag.InstanceID(t.Context(), storage)
	if err != nil {
		t.Fatalf("resolving the owner instance id: %v", err)
	}
	return id
}
