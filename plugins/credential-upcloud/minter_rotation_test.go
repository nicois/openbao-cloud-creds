package credentialupcloud

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Local literals these rotation tests repeat, hoisted to consts so the
// package-wide goconst count stays below threshold.
const (
	rotatePath       = "minter-sets/default/rotate"
	defaultSetName   = "default"
	successorIDKey   = "successor_id"
	retiredMinterKey = "retired_minter_id"
	keyTokenID       = "token_id"
)

// newRotationBackend builds an UpCloud backend via Factory wired to a fake
// UpCloud server, with config written and the given minter-set written through
// the API. It returns the backend, the fake server, and the storage view.
func newRotationBackend(t *testing.T, minters []interface{}) (*backend, *fakes.UpCloudServer, logical.Storage) {
	t.Helper()
	srv := fakes.NewUpCloudServer()
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
			fieldUsername: "testuser",
			fieldAPIURL:   srv.URL,
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
	entry, err := storage.Get(t.Context(), "minter-sets/"+defaultSetName)
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

func neverExpiresMinter(id, token string) map[string]interface{} {
	return map[string]interface{}{
		"id": id, minterTokenKey: token, "never_expires": true,
	}
}

// TestMinterRotation_HappyPath: rotating an active minter mints a mint-capable
// successor, validates it, swaps it in (3 minters: 2 active + 1 retired), and
// the retired minter is never selected while the successor is.
func TestMinterRotation_HappyPath(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresMinter("minter-1", "ucat_v1_one"),
		neverExpiresMinter("minter-2", "ucat_v1_two"),
	})
	beforeTokens := srv.ProvisionedCount()

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: "minter-1"},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate: err=%v resp=%v", err, resp)
	}
	successorID, _ := resp.Data[successorIDKey].(string)
	if successorID == "" {
		t.Fatalf("response missing successor_id: %v", resp.Data)
	}
	if resp.Data[retiredMinterKey] != "minter-1" {
		t.Fatalf("retired_minter_id = %v, want minter-1", resp.Data[retiredMinterKey])
	}
	if _, ok := resp.Data["retired_at"].(time.Time); !ok {
		t.Fatalf("response missing retired_at time: %v", resp.Data)
	}

	// Exactly one new upstream token was minted (the successor).
	if srv.ProvisionedCount() != beforeTokens+1 {
		t.Fatalf("expected one new upstream token, count %d -> %d", beforeTokens, srv.ProvisionedCount())
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
	tokenID := successor.RotationParams[keyTokenID]
	if tokenID == "" {
		t.Fatalf("successor missing token_id rotation param: %+v", successor.RotationParams)
	}
	// The successor's upstream token must itself be mint-capable.
	if !srv.CanCreateTokens(tokenID) {
		t.Fatalf("successor upstream token %q should have can_create_tokens=true", tokenID)
	}

	// selectMinter must never return the retired minter (deterministic regardless
	// of map-iteration order).
	for range 10 {
		sel, err := bk.selectMinter(defaultSetName, time.Now())
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
// successor expiring ~365d out (defaultMinterSecretLifetime), landing within 7d
// of minter-1's ~365d expiry — so the prospective set fails the >=7d-gap rule.
// Validation runs against a synthetic successor BEFORE any cloud call, so the
// rotate is rejected with no state change AND without ever creating an upstream
// token.
func TestMinterRotation_RejectedBreaksValidation(t *testing.T) {
	// minter-1 expires 3 days BEFORE the 365d successor lands; minter-2 expires
	// in 40d (far from minter-1, so the original set validates).
	nearSuccessor := time.Now().Add(defaultMinterSecretLifetime - 3*24*time.Hour).UTC().Format(time.RFC3339)
	later := time.Now().Add(40 * 24 * time.Hour).UTC().Format(time.RFC3339)
	expiringMinter := func(id, token, exp string) map[string]interface{} {
		return map[string]interface{}{
			"id": id, minterTokenKey: token, fieldExpiresAt: exp,
		}
	}
	bk, srv, storage := newRotationBackend(t, []interface{}{
		expiringMinter("minter-1", "ucat_v1_one", nearSuccessor),
		expiringMinter("minter-2", "ucat_v1_two", later),
	})
	beforeTokens := srv.ProvisionedCount()

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
	// reach the create-token API at all: the upstream token count stays exactly
	// at baseline (stronger than "cleaned up back to baseline" — no mint happened).
	if srv.ProvisionedCount() != beforeTokens {
		t.Fatalf("rejected rotation must not create any upstream token; count %d -> %d", beforeTokens, srv.ProvisionedCount())
	}
}

// TestMinterRotation_RejectedSuccessorHealthCheckFails: the successor is minted
// but its health-check fails; the successor must be cleaned up (DeleteToken) and
// the set left unchanged.
func TestMinterRotation_RejectedSuccessorHealthCheckFails(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresMinter("minter-1", "ucat_v1_one"),
		neverExpiresMinter("minter-2", "ucat_v1_two"),
	})
	beforeTokens := srv.ProvisionedCount()

	// The fake mints successor tokens with the "ucat_fake_" prefix; the minting
	// minters use "ucat_v1_". Failing the successor prefix rejects the successor
	// (which authenticates AS its own token) while the minting client stays
	// healthy.
	srv.SetFailHealthForTokenPrefix("ucat_fake_")

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
	// The cleanup DeleteToken undoes the just-minted successor token, so the
	// upstream count returns to baseline.
	if srv.ProvisionedCount() != beforeTokens {
		t.Fatalf("successor token should have been cleaned up; count %d -> %d", beforeTokens, srv.ProvisionedCount())
	}
}

// TestRotateConfig_MinterRetireGraceRoundTrip writes minter_retire_grace and
// reads it back.
func TestRotateConfig_MinterRetireGraceRoundTrip(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresMinter("minter-1", "ucat_v1_one"),
		neverExpiresMinter("minter-2", "ucat_v1_two"),
	})

	if resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]interface{}{
			fieldUsername:          "testuser",
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
// (past the 7d grace) is swept (upstream DeleteToken + dropped from set); a
// minter retired 1h ago is kept.
func TestRetireSweep_DropsAfterGraceKeepsBeforeGrace(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresMinter("active-1", "ucat_v1_active"),
		neverExpiresMinter("old-expired", "ucat_v1_old"),
		neverExpiresMinter("recent", "ucat_v1_recent"),
	})

	// Plant upstream tokens the sweep should DeleteToken, and record their token
	// ids in the retired minters' rotation params.
	srv.AddRawToken("old-token-id", ownertag.CredentialName(ownerInstanceForTest(t, storage), "minter-old", "expired"))
	srv.AddRawToken("recent-token-id", ownertag.CredentialName(ownerInstanceForTest(t, storage), "minter", "recent"))
	if !srv.HasToken("old-token-id") || !srv.HasToken("recent-token-id") {
		t.Fatal("setup: planted tokens missing")
	}

	// Mark two minters retired in storage with controlled RetiredAt + token ids.
	set := loadSetFromStorage(t, storage)
	now := time.Now()
	for i := range set.Minters {
		switch set.Minters[i].ID {
		case "old-expired":
			set.Minters[i].Retired = true
			set.Minters[i].RetiredAt = now.Add(-8 * 24 * time.Hour)
			set.Minters[i].RotationParams = map[string]string{keyTokenID: "old-token-id"}
		case "recent":
			set.Minters[i].Retired = true
			set.Minters[i].RetiredAt = now.Add(-1 * time.Hour)
			set.Minters[i].RotationParams = map[string]string{keyTokenID: "recent-token-id"}
		}
	}
	entry, err := logical.StorageEntryJSON("minter-sets/"+defaultSetName, &set)
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

	// old-expired: upstream removed + dropped from the set.
	if srv.HasToken("old-token-id") {
		t.Fatal("old-expired's upstream token should have been DeleteToken'd")
	}
	// recent: untouched (within grace).
	if !srv.HasToken("recent-token-id") {
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
