package credentialgcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Local literals these rotation tests repeat, hoisted to consts so the
// package-wide goconst count stays below threshold.
const (
	rotatePath          = "minter-sets/default/rotate"
	defaultSetName      = "default"
	successorIDKey      = "successor_id"
	retiredMinterKey    = "retired_minter_id"
	rotMinter1ID        = "minter-1"
	rotMinter2ID        = "minter-2"
	failHealthMarker    = "FAILHEALTH"
	successorJSONPrefix = "{\"rot\":"
	noStateChangeMsgFmt = "set should be unchanged (2 minters), got %d"
)

// fakeSAKeyStore is a shared in-memory model of one service account's JSON keys.
// Every fakeSAKeyClient built in a test points at the same store, so CreateKey /
// DeleteKey see a coherent per-SA key set.
type fakeSAKeyStore struct {
	mu          sync.Mutex
	keys        map[string]bool // key resource name -> present
	createCalls int
	deleteCalls int
	nextSeq     int
	// orgPolicyBlock makes CreateKey return the
	// iam.disableServiceAccountKeyCreation org-policy sentinel.
	orgPolicyBlock bool
	// failHealth makes CreateKey embed failHealthMarker in the successor key JSON,
	// so the injected impersonation client fails the successor health-check.
	failHealth bool
}

func newFakeSAKeyStore() *fakeSAKeyStore {
	return &fakeSAKeyStore{keys: map[string]bool{}}
}

func (s *fakeSAKeyStore) createCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createCalls
}

func (s *fakeSAKeyStore) keyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

func (s *fakeSAKeyStore) has(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys[name]
}

func (s *fakeSAKeyStore) addKey(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[name] = true
}

// fakeSAKeyClient is an in-memory SAKeyClient backed by a shared store.
type fakeSAKeyClient struct {
	store *fakeSAKeyStore
}

func (c *fakeSAKeyClient) CreateKey(_ context.Context) (newKeyJSON, keyName string, err error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.store.orgPolicyBlock {
		return "", "", errKeyCreationDisabled
	}
	c.store.createCalls++
	c.store.nextSeq++
	keyName = fmt.Sprintf("projects/-/serviceAccounts/sa/keys/rotkey%d", c.store.nextSeq)
	marker := ""
	if c.store.failHealth {
		marker = failHealthMarker
	}
	newKeyJSON = fmt.Sprintf("%s%d,\"marker\":%q}", successorJSONPrefix, c.store.nextSeq, marker)
	c.store.keys[keyName] = true
	return newKeyJSON, keyName, nil
}

func (c *fakeSAKeyClient) DeleteKey(_ context.Context, keyName string) error {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	c.store.deleteCalls++
	if !c.store.keys[keyName] {
		return errSAKeyNotFound
	}
	delete(c.store.keys, keyName)
	return nil
}

// newRotationBackend builds a GCP backend via Factory with a fake SA
// key-management client (rotation) and a fake impersonation client (health
// check) injected. The impersonation TestConnection fails for any minter whose
// SA JSON contains failHealthMarker, letting a test fail the successor's
// health-check deterministically.
func newRotationBackend(t *testing.T, store *fakeSAKeyStore, minters []interface{}) (*backend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	bk := b.(*backend)
	storage := config.StorageView

	SetSAKeyClientFactory(b, func(string) SAKeyClient {
		return &fakeSAKeyClient{store: store}
	})
	SetIAMClientFactory(b, func(credentialsJSON string) IAMCredentialsClient {
		creds := credentialsJSON
		return NewFakeIAMClient(nil, func(_ context.Context) error {
			if strings.Contains(creds, failHealthMarker) {
				return fmt.Errorf("PERMISSION_DENIED: health check disabled by test")
			}
			return nil
		})
	})

	if resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]interface{}{},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}

	if resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathMinterSetWrite, Storage: storage,
		Data: map[string]interface{}{fieldMintersKey: minters},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write: err=%v resp=%v", err, resp)
	}
	return bk, storage
}

// loadSetFromStorage reads the persisted default minter set straight from storage.
func loadSetFromStorage(t *testing.T, storage logical.Storage) cloudconfig.MinterSet {
	t.Helper()
	entry, err := storage.Get(context.Background(), "minter-sets/"+defaultSetName)
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

func neverExpiresMinter(id, credsJSON string) map[string]interface{} {
	return map[string]interface{}{
		"id": id, minterCredentialsJSONKey: credsJSON, "never_expires": true,
	}
}

// TestMinterRotation_HappyPath: rotating an active minter creates a successor SA
// key, validates it, swaps it in (3 minters: 2 active + 1 retired), and the
// retired minter is never selected while the successor is.
func TestMinterRotation_HappyPath(t *testing.T) {
	store := newFakeSAKeyStore()
	bk, storage := newRotationBackend(t, store, []interface{}{
		neverExpiresMinter(rotMinter1ID, "{\"k\":1}"),
		neverExpiresMinter(rotMinter2ID, "{\"k\":2}"),
	})

	resp, err := bk.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: rotMinter1ID},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate: err=%v resp=%v", err, resp)
	}
	successorID, _ := resp.Data[successorIDKey].(string)
	if successorID == "" {
		t.Fatalf("response missing successor_id: %v", resp.Data)
	}
	if resp.Data[retiredMinterKey] != rotMinter1ID {
		t.Fatalf("retired_minter_id = %v, want %s", resp.Data[retiredMinterKey], rotMinter1ID)
	}
	if _, ok := resp.Data["retired_at"].(time.Time); !ok {
		t.Fatalf("response missing retired_at time: %v", resp.Data)
	}

	// Exactly one new upstream SA key was created (the successor).
	if store.createCount() != 1 {
		t.Fatalf("expected exactly one CreateKey, got %d", store.createCount())
	}
	if store.keyCount() != 1 {
		t.Fatalf("SA should hold 1 created key after rotation, got %d", store.keyCount())
	}

	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 3 {
		t.Fatalf("set has %d minters, want 3 (2 active + 1 retired)", len(set.Minters))
	}
	var retired, successor *cloudconfig.Minter
	for i := range set.Minters {
		m := &set.Minters[i]
		if m.ID == rotMinter1ID {
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
	successorKeyName := successor.RotationParams[fieldKeyName]
	if successorKeyName == "" {
		t.Fatalf("successor missing key_name rotation param: %+v", successor.RotationParams)
	}
	if !store.has(successorKeyName) {
		t.Fatalf("successor upstream SA key %q should exist", successorKeyName)
	}

	// selectMinter must never return the retired minter (deterministic regardless
	// of map-iteration order).
	for range 10 {
		sel, err := bk.selectMinter(defaultSetName, time.Now())
		if err != nil {
			t.Fatalf("selectMinter: %v", err)
		}
		if sel.minterID == rotMinter1ID {
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

// TestMinterRotation_RejectedBreaksValidation: SA keys never expire, so a
// rotation successor inherits the rotated minter's expiry — the >=7d-gap rule is
// therefore not the natural break here. Instead we use the OTHER load-bearing
// rule: a set of two EXPIRING minters (no never_expires) is valid only with >=2
// non-retired expiring minters. We pre-retire minter-2, then rotate minter-1.
// The prospective set has minter-1 retired AND minter-2 already retired, leaving
// just the successor as the sole non-retired expiring minter (<2, no
// never_expires) -> INVALID. Crucially this is checked against a synthetic
// successor BEFORE any cloud call, so the rotate is rejected with no state change
// AND zero CreateKey calls (load-bearing: a rejected rotation must never create
// an upstream SA key).
func TestMinterRotation_RejectedBreaksValidation(t *testing.T) {
	exp1 := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	exp2 := time.Now().Add(50 * 24 * time.Hour).UTC().Format(time.RFC3339)
	expiringMinter := func(id, credsJSON, exp string) map[string]interface{} {
		return map[string]interface{}{
			"id": id, minterCredentialsJSONKey: credsJSON, fieldExpiresAt: exp,
		}
	}
	store := newFakeSAKeyStore()
	bk, storage := newRotationBackend(t, store, []interface{}{
		expiringMinter(rotMinter1ID, "{\"k\":1}", exp1),
		expiringMinter(rotMinter2ID, "{\"k\":2}", exp2),
	})

	// Pre-retire minter-2 in storage and reload the in-memory snapshot, so the
	// prospective set after rotating minter-1 has too few non-retired expiring
	// minters.
	set := loadSetFromStorage(t, storage)
	for i := range set.Minters {
		if set.Minters[i].ID == rotMinter2ID {
			set.Minters[i].Retired = true
			set.Minters[i].RetiredAt = time.Now().Add(-time.Hour)
		}
	}
	entry, err := logical.StorageEntryJSON("minter-sets/"+defaultSetName, &set)
	if err != nil {
		t.Fatalf("encode set: %v", err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatalf("put set: %v", err)
	}
	bk.loadMinterSet(&set)

	resp, err := bk.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: rotMinter1ID},
	})
	if err != nil {
		t.Fatalf("rotate err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected rejection error response, got %v", resp)
	}

	after := loadSetFromStorage(t, storage)
	for i := range after.Minters {
		if after.Minters[i].ID == rotMinter1ID && after.Minters[i].Retired {
			t.Fatalf("minter-1 should not be retired after a rejected rotation: %+v", after.Minters[i])
		}
	}
	if len(after.Minters) != 2 {
		t.Fatalf("set should still have 2 minters, got %d", len(after.Minters))
	}
	// Validation runs BEFORE any cloud call, so a rejected rotation must never
	// reach CreateKey at all: zero creates (stronger than "cleaned up").
	if store.createCount() != 0 {
		t.Fatalf("rejected rotation must not call CreateKey at all; got %d", store.createCount())
	}
}

// TestMinterRotation_RejectedSuccessorHealthCheckFails: the successor key is
// created but its impersonation health-check fails; the successor must be
// cleaned up (DeleteKey) and the set left unchanged.
func TestMinterRotation_RejectedSuccessorHealthCheckFails(t *testing.T) {
	store := newFakeSAKeyStore()
	store.failHealth = true
	bk, storage := newRotationBackend(t, store, []interface{}{
		neverExpiresMinter(rotMinter1ID, "{\"k\":1}"),
		neverExpiresMinter(rotMinter2ID, "{\"k\":2}"),
	})

	resp, err := bk.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: rotMinter1ID},
	})
	if err != nil {
		t.Fatalf("rotate err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected health-check rejection, got %v", resp)
	}

	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 2 {
		t.Fatalf(noStateChangeMsgFmt, len(set.Minters))
	}
	for i := range set.Minters {
		if set.Minters[i].Retired {
			t.Fatalf("no minter should be retired after failed health check: %+v", set.Minters[i])
		}
	}
	// The successor key was created then deleted by cleanup: one create, one
	// delete, no keys left.
	if store.createCount() != 1 {
		t.Fatalf("expected one CreateKey before health-check failure, got %d", store.createCount())
	}
	if store.keyCount() != 0 {
		t.Fatalf("successor key should have been cleaned up; key count = %d, want 0", store.keyCount())
	}
}

// TestMinterRotation_OrgPolicyBlocked: keys.create is blocked by the
// iam.disableServiceAccountKeyCreation org policy. The rotate must be rejected
// with the clear org-policy message and no state change.
func TestMinterRotation_OrgPolicyBlocked(t *testing.T) {
	store := newFakeSAKeyStore()
	store.orgPolicyBlock = true
	bk, storage := newRotationBackend(t, store, []interface{}{
		neverExpiresMinter(rotMinter1ID, "{\"k\":1}"),
		neverExpiresMinter(rotMinter2ID, "{\"k\":2}"),
	})

	resp, err := bk.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: rotMinter1ID},
	})
	if err != nil {
		t.Fatalf("rotate err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected org-policy rejection, got %v", resp)
	}
	msg := resp.Error().Error()
	if !strings.Contains(msg, orgPolicyKeyCreationDisabled) {
		t.Fatalf("rejection message should name the org policy constraint, got: %v", msg)
	}
	if !strings.Contains(msg, "org policy") {
		t.Fatalf("rejection message should mention org policy, got: %v", msg)
	}

	// No key created and the set is unchanged.
	if store.createCount() != 0 {
		t.Fatalf("org-policy block must not leave a created key; got %d creates", store.createCount())
	}
	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 2 {
		t.Fatalf(noStateChangeMsgFmt, len(set.Minters))
	}
	for i := range set.Minters {
		if set.Minters[i].Retired {
			t.Fatalf("no minter should be retired after org-policy rejection: %+v", set.Minters[i])
		}
	}
}

// TestRotateConfig_MinterRetireGraceRoundTrip writes minter_retire_grace and
// reads it back.
func TestRotateConfig_MinterRetireGraceRoundTrip(t *testing.T) {
	store := newFakeSAKeyStore()
	bk, storage := newRotationBackend(t, store, []interface{}{
		neverExpiresMinter(rotMinter1ID, "{\"k\":1}"),
		neverExpiresMinter(rotMinter2ID, "{\"k\":2}"),
	})

	if resp, err := bk.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]interface{}{fieldMinterRetireGrace: 86400},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}

	resp, err := bk.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: pathConfigKey, Storage: storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config read: err=%v resp=%v", err, resp)
	}
	if got := resp.Data[fieldMinterRetireGrace]; got != 86400 {
		t.Fatalf("minter_retire_grace = %v, want 86400", got)
	}
}

// TestRetireSweep_DropsAfterGraceKeepsBeforeGrace: a minter retired 8d ago (past
// the 7d grace) is swept (upstream DeleteKey + dropped from set); a minter
// retired 1h ago is kept.
func TestRetireSweep_DropsAfterGraceKeepsBeforeGrace(t *testing.T) {
	store := newFakeSAKeyStore()
	store.addKey("keys/old")
	store.addKey("keys/recent")
	bk, storage := newRotationBackend(t, store, []interface{}{
		neverExpiresMinter("active-1", "{\"k\":1}"),
		neverExpiresMinter("old-expired", "{\"k\":2}"),
		neverExpiresMinter("recent", "{\"k\":3}"),
	})

	set := loadSetFromStorage(t, storage)
	now := time.Now()
	for i := range set.Minters {
		switch set.Minters[i].ID {
		case "old-expired":
			set.Minters[i].Retired = true
			set.Minters[i].RetiredAt = now.Add(-8 * 24 * time.Hour)
			set.Minters[i].RotationParams = map[string]string{fieldKeyName: "keys/old"}
		case "recent":
			set.Minters[i].Retired = true
			set.Minters[i].RetiredAt = now.Add(-1 * time.Hour)
			set.Minters[i].RotationParams = map[string]string{fieldKeyName: "keys/recent"}
		}
	}
	entry, err := logical.StorageEntryJSON("minter-sets/"+defaultSetName, &set)
	if err != nil {
		t.Fatalf("encode set: %v", err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatalf("put set: %v", err)
	}
	bk.loadMinterSet(&set)

	if err := bk.sweepRetiredMinters(context.Background(), storage, now); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// old-expired: upstream key removed + dropped from the set.
	if store.has("keys/old") {
		t.Fatal("old-expired's upstream SA key should have been DeleteKey'd")
	}
	// recent: untouched (within grace).
	if !store.has("keys/recent") {
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
