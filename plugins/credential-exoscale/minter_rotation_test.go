package credentialexoscale

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Local literals these rotation tests repeat, hoisted to consts so the
// package-wide goconst count stays below threshold. (pathConfigKey,
// fieldMintersKey, pathMinterSetWrite, fieldAPIURL, fieldExpiresAt and
// minterKeyKey are already defined elsewhere in this internal test package and
// are reused here.)
const (
	rotatePath       = "minter-sets/default/rotate"
	defaultSetName   = "default"
	successorIDKey   = "successor_id"
	retiredMinterKey = "retired_minter_id"
	testMinterRoleID = "11111111-1111-1111-1111-111111111111"
	successorKeyName = "cloud-creds-minter-"
	minter1ID        = "minter-1"
	minter2ID        = "minter-2"
	minter1Key       = "EXO_key_1"
	minter2Key       = "EXO_key_2"
)

// newRotationBackend builds an Exoscale backend via Factory wired to a fake
// Exoscale server, with config written and the given minter-set written through
// the API. It returns the backend, the fake server, and the storage view.
func newRotationBackend(t *testing.T, minters []interface{}) (*backend, *fakes.ExoscaleServer, logical.Storage) {
	t.Helper()
	srv := fakes.NewExoscaleServer()
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
		Data: map[string]interface{}{fieldAPIURL: srv.URL},
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

// neverExpiresRotatableMinter builds a never-expiring minter map carrying the
// rotation_params.role_id needed for a mint-capable successor.
func neverExpiresRotatableMinter(id, key string) map[string]interface{} {
	return map[string]interface{}{
		"id": id, minterKeyKey: key, "never_expires": true,
		rotationParamsKey: map[string]interface{}{fieldRoleID: testMinterRoleID},
	}
}

// rotationParamsKey is the per-minter rotation metadata map key used in test
// minter maps written through the API.
const rotationParamsKey = "rotation_params"

// TestMinterRotation_HappyPath: rotating an active minter mints a successor
// (with the minter's OWN role_id), validates it, swaps it in (3 minters: 2
// active + 1 retired), the retired minter is never selected, the successor is
// deterministically selectable, and the successor carries role_id forward + a
// key_id.
func TestMinterRotation_HappyPath(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresRotatableMinter(minter1ID, minter1Key),
		neverExpiresRotatableMinter(minter2ID, minter2Key),
	})
	beforeKeys := srv.ProvisionedCount()

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: minter1ID},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate: err=%v resp=%v", err, resp)
	}
	successorID, _ := resp.Data[successorIDKey].(string)
	if successorID == "" {
		t.Fatalf("response missing successor_id: %v", resp.Data)
	}
	if resp.Data[retiredMinterKey] != minter1ID {
		t.Fatalf("retired_minter_id = %v, want %s", resp.Data[retiredMinterKey], minter1ID)
	}
	if _, ok := resp.Data["retired_at"].(time.Time); !ok {
		t.Fatalf("response missing retired_at time: %v", resp.Data)
	}

	// Exactly one new upstream key was minted (the successor).
	if srv.ProvisionedCount() != beforeKeys+1 {
		t.Fatalf("expected one new upstream key, count %d -> %d", beforeKeys, srv.ProvisionedCount())
	}

	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 3 {
		t.Fatalf("set has %d minters, want 3 (2 active + 1 retired)", len(set.Minters))
	}
	var retired, successor *cloudconfig.Minter
	for i := range set.Minters {
		m := &set.Minters[i]
		if m.ID == minter1ID {
			retired = m
		}
		if m.ID == successorID {
			successor = m
		}
	}
	if retired == nil || !retired.Retired || retired.RetiredAt.IsZero() {
		t.Fatalf("%s should be retired with RetiredAt set, got %+v", minter1ID, retired)
	}
	if successor == nil || successor.Retired {
		t.Fatalf("successor %q should be active, got %+v", successorID, successor)
	}
	// Successor carries the minter's role_id forward (so it can mint further keys).
	if successor.RotationParams[fieldRoleID] != testMinterRoleID {
		t.Fatalf("successor missing role_id rotation param: %+v", successor.RotationParams)
	}
	// Successor records its own upstream key id (for the retired-sweep).
	keyID := successor.RotationParams[fieldKeyID]
	if keyID == "" {
		t.Fatalf("successor missing key_id rotation param: %+v", successor.RotationParams)
	}
	// The successor's upstream key must have been created with the minter's role_id.
	if got := srv.RoleIDForKey(keyID); got != testMinterRoleID {
		t.Fatalf("successor upstream key %q role-id = %q, want %q", keyID, got, testMinterRoleID)
	}

	// selectMinter must never return the retired minter (deterministic regardless
	// of map-iteration order).
	for range 10 {
		sel, err := bk.selectMinter(defaultSetName, time.Now())
		if err != nil {
			t.Fatalf("selectMinter: %v", err)
		}
		if sel.minterID == minter1ID {
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
// key.
func TestMinterRotation_RejectedBreaksValidation(t *testing.T) {
	// minter-1 expires 3 days BEFORE the 365d successor lands; minter-2 expires
	// in 40d (far from minter-1, so the original set validates).
	const daysBeforeSuccessor = 3
	const minter2ExpiryDays = 40
	nearSuccessor := time.Now().Add(defaultMinterSecretLifetime - daysBeforeSuccessor*24*time.Hour).UTC().Format(time.RFC3339)
	later := time.Now().Add(minter2ExpiryDays * 24 * time.Hour).UTC().Format(time.RFC3339)
	expiringMinter := func(id, key, exp string) map[string]interface{} {
		return map[string]interface{}{
			"id": id, minterKeyKey: key, fieldExpiresAt: exp,
			rotationParamsKey: map[string]interface{}{fieldRoleID: testMinterRoleID},
		}
	}
	bk, srv, storage := newRotationBackend(t, []interface{}{
		expiringMinter(minter1ID, minter1Key, nearSuccessor),
		expiringMinter(minter2ID, minter2Key, later),
	})
	beforeKeys := srv.ProvisionedCount()

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: minter2ID},
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
	// reach the create-api-key API at all: the upstream key count stays exactly
	// at baseline (stronger than "cleaned up back to baseline" — no mint happened).
	if srv.ProvisionedCount() != beforeKeys {
		t.Fatalf("rejected rotation must not create any upstream key; count %d -> %d", beforeKeys, srv.ProvisionedCount())
	}
}

// TestMinterRotation_RejectedSuccessorHealthCheckFails: the successor is minted
// but its health-check fails; the successor must be cleaned up (DeleteAPIKey)
// and the set left unchanged.
func TestMinterRotation_RejectedSuccessorHealthCheckFails(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresRotatableMinter(minter1ID, minter1Key),
		neverExpiresRotatableMinter(minter2ID, minter2Key),
	})
	beforeKeys := srv.ProvisionedCount()

	// The fake mints API keys as "EXOexo-key-<n>"; the minters seeded above use
	// "EXO_key_". Failing the minted prefix rejects the successor (which
	// authenticates AS its own key) while the minting client stays healthy.
	srv.SetFailHealthForKeyPrefix(capMintedPrefix)

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: minter1ID},
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
	// The cleanup DeleteAPIKey undoes the just-minted successor key, so the
	// upstream count returns to baseline.
	if srv.ProvisionedCount() != beforeKeys {
		t.Fatalf("successor key should have been cleaned up; count %d -> %d", beforeKeys, srv.ProvisionedCount())
	}
}

// TestMinterRotation_NoRoleIDRejected: a minter with no rotation_params.role_id
// cannot mint a mint-capable successor; rotation is rejected with no state
// change and no upstream key created.
func TestMinterRotation_NoRoleIDRejected(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		map[string]interface{}{"id": minter1ID, minterKeyKey: minter1Key, "never_expires": true},
		map[string]interface{}{"id": minter2ID, minterKeyKey: minter2Key, "never_expires": true},
	})
	beforeKeys := srv.ProvisionedCount()

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: minter1ID},
	})
	if err != nil {
		t.Fatalf("rotate err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected rejection for minter without role_id, got %v", resp)
	}
	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 2 {
		t.Fatalf("set should be unchanged (2 minters), got %d", len(set.Minters))
	}
	if srv.ProvisionedCount() != beforeKeys {
		t.Fatalf("no upstream key should have been created; count %d -> %d", beforeKeys, srv.ProvisionedCount())
	}
}

// TestRotateConfig_MinterRetireGraceRoundTrip writes minter_retire_grace and
// reads it back.
func TestRotateConfig_MinterRetireGraceRoundTrip(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresRotatableMinter(minter1ID, minter1Key),
		neverExpiresRotatableMinter(minter2ID, minter2Key),
	})

	const graceSeconds = 86400
	if resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]interface{}{
			fieldAPIURL:            srv.URL,
			fieldMinterRetireGrace: graceSeconds,
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
	if got := resp.Data[fieldMinterRetireGrace]; got != graceSeconds {
		t.Fatalf("minter_retire_grace = %v, want %d", got, graceSeconds)
	}
}

// TestRetireSweep_DropsAfterGraceKeepsBeforeGrace: a minter retired 8d ago
// (past the 7d grace) is swept (upstream DeleteAPIKey + dropped from set); a
// minter retired 1h ago is kept.
func TestRetireSweep_DropsAfterGraceKeepsBeforeGrace(t *testing.T) {
	const activeID = "active-1"
	const oldID = "old-expired"
	const recentID = "recent"
	const oldKeyID = "old-key-id"
	const recentKeyID = "recent-key-id"

	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresRotatableMinter(activeID, "EXO_active"),
		neverExpiresRotatableMinter(oldID, "EXO_old"),
		neverExpiresRotatableMinter(recentID, "EXO_recent"),
	})

	// Plant upstream keys the sweep should DeleteAPIKey, and record their key ids
	// in the retired minters' rotation params.
	srv.AddRawAPIKey(oldKeyID, successorKeyName+oldID)
	srv.AddRawAPIKey(recentKeyID, successorKeyName+recentID)
	if !srv.HasAPIKey(oldKeyID) || !srv.HasAPIKey(recentKeyID) {
		t.Fatal("setup: planted keys missing")
	}

	// Mark two minters retired in storage with controlled RetiredAt + key ids.
	set := loadSetFromStorage(t, storage)
	now := time.Now()
	const pastGraceDays = 8
	for i := range set.Minters {
		switch set.Minters[i].ID {
		case oldID:
			set.Minters[i].Retired = true
			set.Minters[i].RetiredAt = now.Add(-pastGraceDays * 24 * time.Hour)
			set.Minters[i].RotationParams = map[string]string{fieldRoleID: testMinterRoleID, fieldKeyID: oldKeyID}
		case recentID:
			set.Minters[i].Retired = true
			set.Minters[i].RetiredAt = now.Add(-1 * time.Hour)
			set.Minters[i].RotationParams = map[string]string{fieldRoleID: testMinterRoleID, fieldKeyID: recentKeyID}
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
	if srv.HasAPIKey(oldKeyID) {
		t.Fatal("old-expired's upstream key should have been DeleteAPIKey'd")
	}
	// recent: untouched (within grace).
	if !srv.HasAPIKey(recentKeyID) {
		t.Fatal("recent (within grace) must NOT be swept")
	}

	after := loadSetFromStorage(t, storage)
	ids := map[string]bool{}
	for i := range after.Minters {
		ids[after.Minters[i].ID] = true
	}
	if ids[oldID] {
		t.Fatal("old-expired should have been dropped from the set")
	}
	if !ids[recentID] {
		t.Fatal("recent should still be in the set")
	}
	if !ids[activeID] {
		t.Fatal("active-1 should still be in the set")
	}
}
