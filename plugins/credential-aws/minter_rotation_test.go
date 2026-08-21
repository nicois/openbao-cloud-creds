package credentialaws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
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
	successorKeyPrefix  = "AKIAROT"
	noStateChangeMsgFmt = "set should be unchanged (2 minters), got %d"
)

// fakeIAMStore is a shared in-memory model of one IAM user's access keys. Every
// fakeIAMMinterClient built in a test points at the same store, so CreateAccessKey
// /DeleteAccessKey/ListAccessKeyIDs see a coherent per-user key set (the basis of
// the 2-key make-before-break guard).
type fakeIAMStore struct {
	mu          sync.Mutex
	keys        map[string]string // accessKeyID -> secret
	createCalls int
	nextSeq     int
}

func newFakeIAMStore(initial ...string) *fakeIAMStore {
	s := &fakeIAMStore{keys: map[string]string{}}
	for _, id := range initial {
		s.keys[id] = "secret-" + id
	}
	return s
}

func (s *fakeIAMStore) createCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createCalls
}

func (s *fakeIAMStore) keyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

func (s *fakeIAMStore) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.keys[id]
	return ok
}

// fakeIAMMinterClient is an in-memory IAMMinterClient backed by a shared store.
type fakeIAMMinterClient struct {
	store *fakeIAMStore
}

func (c *fakeIAMMinterClient) CreateAccessKey(_ context.Context) (accessKeyID, secretAccessKey string, err error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	c.store.createCalls++
	c.store.nextSeq++
	id := fmt.Sprintf("%s%d", successorKeyPrefix, c.store.nextSeq)
	secret := "secret-" + id
	c.store.keys[id] = secret
	return id, secret, nil
}

func (c *fakeIAMMinterClient) DeleteAccessKey(_ context.Context, accessKeyID string) error {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if _, ok := c.store.keys[accessKeyID]; !ok {
		return fmt.Errorf("iam DeleteAccessKey failed (%s): no such key", errNoSuchEntity)
	}
	delete(c.store.keys, accessKeyID)
	return nil
}

func (c *fakeIAMMinterClient) ListAccessKeyIDs(_ context.Context) ([]string, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	ids := make([]string, 0, len(c.store.keys))
	for id := range c.store.keys {
		ids = append(ids, id)
	}
	return ids, nil
}

// newRotationBackend builds an AWS backend via Factory with a fake STS client
// (issuance + successor health-check) and a fake IAM minter client backed by the
// given shared store, with config written and the minter-set written through the
// API. The injected STS GetCallerIdentity fails for any access key whose id
// contains failHealthMarker, letting a test fail the successor health-check
// deterministically (the successor's id is set by the test via the store).
func newRotationBackend(t *testing.T, store *fakeIAMStore, minters []interface{}) (*backend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	bk := b.(*backend)
	storage := config.StorageView

	SetSTSClientFactory(b, func(accessKeyID, _, _, _ string) STSClient {
		keyID := accessKeyID
		return NewFakeSTSClient(nil, func(_ context.Context, _ *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			if strings.Contains(keyID, failHealthMarker) {
				return nil, fmt.Errorf("AccessDenied: health check disabled by test")
			}
			return &sts.GetCallerIdentityOutput{}, nil
		})
	})
	SetIAMMinterClientFactory(b, func(_, _, _ string) IAMMinterClient {
		return &fakeIAMMinterClient{store: store}
	})

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]interface{}{configRegionKey: defaultRegion},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
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

func neverExpiresMinter(id, accessKeyID, secret string) map[string]interface{} {
	return map[string]interface{}{
		"id":                     id,
		minterAccessKeyIDKey:     accessKeyID,
		minterSecretAccessKeyKey: secret,
		"never_expires":          true,
	}
}

// TestMinterRotation_HappyPath: rotating an active minter creates a successor
// access key (1 key -> 2 keys), validates it, swaps it in (3 minters: 2 active +
// 1 retired), and the retired minter is never selected while the successor is.
func TestMinterRotation_HappyPath(t *testing.T) {
	store := newFakeIAMStore("AKIA1") // minter-1's only key: one free slot
	bk, storage := newRotationBackend(t, store, []interface{}{
		neverExpiresMinter(rotMinter1ID, "AKIA1", "secret1"),
		neverExpiresMinter(rotMinter2ID, "AKIA2", "secret2"),
	})

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
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

	// Exactly one new upstream access key was created (the successor), so the
	// user now holds 2 keys (old retired + successor active).
	if store.createCount() != 1 {
		t.Fatalf("expected exactly one CreateAccessKey, got %d", store.createCount())
	}
	if store.keyCount() != 2 {
		t.Fatalf("user should hold 2 access keys after rotation, got %d", store.keyCount())
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
	successorKeyID := successor.RotationParams[fieldAccessKeyID]
	if successorKeyID == "" {
		t.Fatalf("successor missing access_key_id rotation param: %+v", successor.RotationParams)
	}
	if !store.has(successorKeyID) {
		t.Fatalf("successor upstream access key %q should exist", successorKeyID)
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

// TestMinterRotation_RejectedBreaksValidation: AWS access keys never expire, so
// a rotation successor inherits the rotated minter's expiry — the >=7d-gap rule
// is therefore not the natural break here. Instead we use the OTHER load-bearing
// rule: a set of two EXPIRING minters (no never_expires) is valid only with >=2
// non-retired expiring minters. We pre-retire minter-2, then rotate minter-1.
// The prospective set has minter-1 retired AND minter-2 already retired, leaving
// just the successor as the sole non-retired expiring minter (<2, no
// never_expires) -> INVALID. Crucially this is checked against a synthetic
// successor BEFORE any IAM call, so the rotate is rejected with no state change
// AND zero CreateAccessKey calls (load-bearing: a rejected rotation must never
// consume one of the IAM user's scarce access-key slots).
func TestMinterRotation_RejectedBreaksValidation(t *testing.T) {
	exp1 := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	exp2 := time.Now().Add(50 * 24 * time.Hour).UTC().Format(time.RFC3339)
	expiringMinter := func(id, accessKeyID, secret, exp string) map[string]interface{} {
		return map[string]interface{}{
			"id":                     id,
			minterAccessKeyIDKey:     accessKeyID,
			minterSecretAccessKeyKey: secret,
			fieldExpiresAt:           exp,
		}
	}
	store := newFakeIAMStore("AKIA1")
	bk, storage := newRotationBackend(t, store, []interface{}{
		expiringMinter(rotMinter1ID, "AKIA1", "secret1", exp1),
		expiringMinter(rotMinter2ID, "AKIA2", "secret2", exp2),
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
	if err := storage.Put(t.Context(), entry); err != nil {
		t.Fatalf("put set: %v", err)
	}
	bk.loadMinterSet(&set)

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
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
	// minter-1 must NOT have been retired by the rejected rotation (minter-2 was
	// pre-retired by the test setup, so exactly one retired minter remains).
	for i := range after.Minters {
		if after.Minters[i].ID == rotMinter1ID && after.Minters[i].Retired {
			t.Fatalf("minter-1 should not be retired after a rejected rotation: %+v", after.Minters[i])
		}
	}
	if len(after.Minters) != 2 {
		t.Fatalf("set should still have 2 minters, got %d", len(after.Minters))
	}
	// Validation runs BEFORE any cloud call, so a rejected rotation must never
	// reach CreateAccessKey at all: zero creates (stronger than "cleaned up").
	if store.createCount() != 0 {
		t.Fatalf("rejected rotation must not call CreateAccessKey at all; got %d", store.createCount())
	}
}

// TestMinterRotation_RejectedSuccessorHealthCheckFails: the successor key is
// created but its STS health-check fails; the successor must be cleaned up
// (DeleteAccessKey) and the set left unchanged.
func TestMinterRotation_RejectedSuccessorHealthCheckFails(t *testing.T) {
	// Seed the store so the next created key id contains failHealthMarker: the
	// fake STS GetCallerIdentity then rejects the successor while the minting
	// minters (AKIA1/AKIA2) stay healthy.
	store := newFakeIAMStore("AKIA1")
	store.nextSeq = 0
	// Override the successor key naming to embed the fail marker by pre-setting a
	// prefix the fake create uses: we instead make the fake create a marked id.
	bk, storage := newRotationBackendFailHealth(t, store, []interface{}{
		neverExpiresMinter(rotMinter1ID, "AKIA1", "secret1"),
		neverExpiresMinter(rotMinter2ID, "AKIA2", "secret2"),
	})

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
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
	// The cleanup DeleteAccessKey undoes the just-created successor key, so the
	// user is back to its single original key.
	if store.keyCount() != 1 {
		t.Fatalf("successor key should have been cleaned up; key count = %d, want 1", store.keyCount())
	}
}

// newRotationBackendFailHealth is like newRotationBackend but the fake IAM
// CreateAccessKey returns key ids containing failHealthMarker, so the injected
// STS GetCallerIdentity fails the successor's health check.
func newRotationBackendFailHealth(t *testing.T, store *fakeIAMStore, minters []interface{}) (*backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	bk := b.(*backend)
	storage := config.StorageView

	SetSTSClientFactory(b, func(accessKeyID, _, _, _ string) STSClient {
		keyID := accessKeyID
		return NewFakeSTSClient(nil, func(_ context.Context, _ *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			if strings.Contains(keyID, failHealthMarker) {
				return nil, fmt.Errorf("AccessDenied: health check disabled by test")
			}
			return &sts.GetCallerIdentityOutput{}, nil
		})
	})
	SetIAMMinterClientFactory(b, func(_, _, _ string) IAMMinterClient {
		return &failHealthIAMClient{store: store}
	})

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]interface{}{configRegionKey: defaultRegion},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}
	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathMinterSetWrite, Storage: storage,
		Data: map[string]interface{}{fieldMintersKey: minters},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write: err=%v resp=%v", err, resp)
	}
	return bk, storage
}

// failHealthIAMClient mints successor keys whose id contains failHealthMarker.
type failHealthIAMClient struct {
	store *fakeIAMStore
}

func (c *failHealthIAMClient) CreateAccessKey(_ context.Context) (accessKeyID, secretAccessKey string, err error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	c.store.createCalls++
	c.store.nextSeq++
	id := fmt.Sprintf("%s%s%d", successorKeyPrefix, failHealthMarker, c.store.nextSeq)
	secret := "secret-" + id
	c.store.keys[id] = secret
	return id, secret, nil
}

func (c *failHealthIAMClient) DeleteAccessKey(_ context.Context, accessKeyID string) error {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if _, ok := c.store.keys[accessKeyID]; !ok {
		return fmt.Errorf("iam DeleteAccessKey failed (%s): no such key", errNoSuchEntity)
	}
	delete(c.store.keys, accessKeyID)
	return nil
}

func (c *failHealthIAMClient) ListAccessKeyIDs(_ context.Context) ([]string, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	ids := make([]string, 0, len(c.store.keys))
	for id := range c.store.keys {
		ids = append(ids, id)
	}
	return ids, nil
}

// TestRotateConfig_MinterRetireGraceRoundTrip writes minter_retire_grace and
// reads it back.
func TestRotateConfig_MinterRetireGraceRoundTrip(t *testing.T) {
	store := newFakeIAMStore("AKIA1")
	bk, storage := newRotationBackend(t, store, []interface{}{
		neverExpiresMinter(rotMinter1ID, "AKIA1", "secret1"),
		neverExpiresMinter(rotMinter2ID, "AKIA2", "secret2"),
	})

	if resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]interface{}{
			configRegionKey:        defaultRegion,
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

// TestRetireSweep_DropsAfterGraceKeepsBeforeGrace: a minter retired 8d ago (past
// the 7d grace) is swept (upstream DeleteAccessKey + dropped from set); a minter
// retired 1h ago is kept.
func TestRetireSweep_DropsAfterGraceKeepsBeforeGrace(t *testing.T) {
	// Seed the store with the upstream keys the sweep should delete.
	store := newFakeIAMStore("AKIA-active", "AKIA-old", "AKIA-recent")
	bk, storage := newRotationBackend(t, store, []interface{}{
		neverExpiresMinter("active-1", "AKIA-active", "secretA"),
		neverExpiresMinter("old-expired", "AKIA-old", "secretO"),
		neverExpiresMinter("recent", "AKIA-recent", "secretR"),
	})

	set := loadSetFromStorage(t, storage)
	now := time.Now()
	for i := range set.Minters {
		switch set.Minters[i].ID {
		case "old-expired":
			set.Minters[i].Retired = true
			set.Minters[i].RetiredAt = now.Add(-8 * 24 * time.Hour)
			set.Minters[i].RotationParams = map[string]string{fieldAccessKeyID: "AKIA-old"}
		case "recent":
			set.Minters[i].Retired = true
			set.Minters[i].RetiredAt = now.Add(-1 * time.Hour)
			set.Minters[i].RotationParams = map[string]string{fieldAccessKeyID: "AKIA-recent"}
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

	// old-expired: upstream key removed + dropped from the set.
	if store.has("AKIA-old") {
		t.Fatal("old-expired's upstream access key should have been DeleteAccessKey'd")
	}
	// recent: untouched (within grace).
	if !store.has("AKIA-recent") {
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

// TestMinterRotation_TwoKeyGuard: a minter IAM user already holding the IAM cap
// of 2 access keys cannot be rotated — the make-before-break create has no free
// slot. The rotate is rejected with the clear message, no CreateAccessKey call,
// and no state change.
func TestMinterRotation_TwoKeyGuard(t *testing.T) {
	// The user already holds 2 keys (e.g. a successor minted by an earlier
	// rotation still in its retirement grace).
	store := newFakeIAMStore("AKIA1", "AKIA1b")
	bk, storage := newRotationBackend(t, store, []interface{}{
		neverExpiresMinter(rotMinter1ID, "AKIA1", "secret1"),
		neverExpiresMinter(rotMinter2ID, "AKIA2", "secret2"),
	})

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: rotMinter1ID},
	})
	if err != nil {
		t.Fatalf("rotate err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected 2-key-guard rejection, got %v", resp)
	}
	if !strings.Contains(resp.Error().Error(), "2 access keys") {
		t.Fatalf("rejection message should mention the 2-key guard, got: %v", resp.Error())
	}

	// No new key was created and the set is unchanged.
	if store.createCount() != 0 {
		t.Fatalf("2-key guard must reject before CreateAccessKey; got %d creates", store.createCount())
	}
	if store.keyCount() != 2 {
		t.Fatalf("key count should be unchanged at 2, got %d", store.keyCount())
	}
	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 2 {
		t.Fatalf(noStateChangeMsgFmt, len(set.Minters))
	}
	for i := range set.Minters {
		if set.Minters[i].Retired {
			t.Fatalf("no minter should be retired after 2-key-guard rejection: %+v", set.Minters[i])
		}
	}
}
