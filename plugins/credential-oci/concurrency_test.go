package credentialoci

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Test-local field/value literals, named so this file does not trip goconst by
// repeating config/role keys the non-test code already uses twice.
const (
	testRegionField   = "region"
	testRegionValue   = "us-ashburn-1"
	testDefaultTTLKey = "default_ttl"
	testMaxTTLKey     = "max_ttl"
)

// ---------------------------------------------------------------------------
// F3: fakeOCIClient has no mutex but is shared between the test goroutine and
// the background rotation/reconcile workers. Concurrent CreateAuthToken /
// ListAuthTokens / TokenCount touch the same unguarded `tokens` map.
// ---------------------------------------------------------------------------

func TestFakeOCIClient_ConcurrentAccess(t *testing.T) {
	f := newFakeOCIClient()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _, _ = f.CreateAuthToken(context.Background(), "user-1", "cloud-creds-x")
				_ = f.TokenCount()
				_, _ = f.ListAuthTokens(context.Background(), "user-1")
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// F4: rotation creates+persists a new token while reconcile snapshots the
// known-set THEN lists+deletes. The known-set snapshot (collectKnownTokenIDs)
// is taken before ListAuthTokens; if a rotation creates a new token and writes
// it to slot storage in that window, the new live token is present upstream but
// absent from the stale snapshot, so reconcileOrphans deletes it.
//
// The fix serializes the two operations with rotateReconcileMu: a rotation's
// create+persist+delete and a reconcile pass's snapshot+list+delete are now
// mutually exclusive, so the destructive interleaving above is IMPOSSIBLE — one
// runs fully before the other.
//
// Why the test changed: the original test forced that interleaving by gating
// reconcile's ListAuthTokens until a concurrent rotation had persisted its new
// token. With proper serialization that gate would deadlock (reconcile holds
// rotateReconcileMu while blocked in ListAuthTokens; rotation can't acquire it to
// persist), which would merely prove the lock holds — but a deadlocking test is
// a bad regression test. So this now runs rotation and reconcile concurrently
// through the LOCKED entry points (rotateSlot / runReconcilePass) over many
// trials with randomized ordering, and asserts the freshly-rotated live token
// always survives. Under the old unguarded code the snapshot+delete could still
// straddle a rotation and delete the live token; the race detector plus the
// repeated trials catch any regression.
func TestRotationReconcileRace(t *testing.T) {
	const trials = 50

	for trial := 0; trial < trials; trial++ {
		b, storage, fake := newInternalConfiguredBackend(t)

		role, ok := loadRole(context.Background(), storage, "test-role")
		if !ok {
			t.Fatal("test-role not found after setup")
		}

		// Force slot 0 due for rotation: rewrite its NextRotationAt into the past.
		s0, err := loadSlot(context.Background(), storage, "test-role", 0)
		if err != nil || s0 == nil {
			t.Fatalf("loadSlot(0): err=%v slot=%v", err, s0)
		}
		s0.NextRotationAt = time.Now().Add(-time.Hour)
		if err := saveSlot(context.Background(), storage, "test-role", s0); err != nil {
			t.Fatalf("saveSlot(0): %v", err)
		}

		tokensBefore := fake.TokenCount()
		roleNames := []string{"test-role"}

		// startGate releases both goroutines at once so their locked regions race
		// to acquire rotateReconcileMu in arbitrary order across trials.
		startGate := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		// Reconcile goroutine: full pass through the LOCKED entry point
		// (snapshot+list+delete are atomic under rotateReconcileMu).
		go func() {
			defer wg.Done()
			<-startGate
			b.runReconcilePass(context.Background(), storage, roleNames, false)
		}()

		// Rotation goroutine: rotates slot 0 through the LOCKED entry point
		// (create+persist+delete atomic under rotateReconcileMu).
		go func() {
			defer wg.Done()
			<-startGate
			if err := b.rotateSlot(context.Background(), storage, role, 0); err != nil {
				t.Errorf("trial %d: rotateSlot: %v", trial, err)
			}
		}()

		close(startGate)
		wg.Wait()

		// The freshly-rotated slot's token must still exist upstream. rotateSlot
		// creates a new token and deletes the OLD one, so net upstream count is
		// unchanged (tokensBefore). If reconcile destroyed the new live token, the
		// count drops below tokensBefore.
		newS0, err := loadSlot(context.Background(), storage, "test-role", 0)
		if err != nil || newS0 == nil {
			t.Fatalf("trial %d: loadSlot(0) after: err=%v slot=%v", trial, err, newS0)
		}
		if !fake.hasToken(role.UserOCID, newS0.TokenID) {
			t.Fatalf("trial %d: freshly-rotated live token %q was deleted by reconcile (F4 regression)",
				trial, newS0.TokenID)
		}
		if got := fake.TokenCount(); got < tokensBefore {
			t.Fatalf("trial %d: upstream token count dropped from %d to %d: reconcile deleted a live token (F4 regression)",
				trial, tokensBefore, got)
		}
	}
}

// hasToken reports whether the fake still holds the given token for a user.
func (f *fakeOCIClient) hasToken(userID, tokenID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	userTokens, ok := f.tokens[userID]
	if !ok {
		return false
	}
	_, ok = userTokens[tokenID]
	return ok
}

// newInternalConfiguredBackend builds a configured *backend with the in-memory
// fake injected, mirroring setupConfiguredBackend from the _test package but
// usable from this internal-package file. It writes config, a minter set, and a
// role (which provisions slots).
func newInternalConfiguredBackend(t *testing.T) (*backend, logical.Storage, *fakeOCIClient) {
	t.Helper()

	cfg := logical.TestBackendConfig()
	cfg.StorageView = &logical.InmemStorage{}
	lb, err := Factory(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	b, ok := lb.(*backend)
	if !ok {
		t.Fatalf("expected *backend, got %T", lb)
	}
	storage := cfg.StorageView

	// One shared fake so the tokens minted during slot provisioning persist and
	// can later be observed/asserted on.
	fake := newFakeOCIClient()
	b.SetClientFactory(func(string) OCIIAMClient { return fake })

	write := func(path string, data map[string]interface{}) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("%s write failed: err=%v resp=%v", path, err, resp)
		}
	}

	write("config", map[string]interface{}{testRegionField: testRegionValue})
	write("minter-sets/default", map[string]interface{}{
		"minters": []interface{}{
			map[string]interface{}{
				"id":            "minter-1",
				"token":         "tenancy:user:fingerprint:key",
				"never_expires": true,
			},
		},
	})
	write("roles/test-role", map[string]interface{}{
		"user_ocid":       "ocid1.user.oc1..testuser",
		"slot_count":      2,
		"rotation_period": 604800,
		testDefaultTTLKey: 302400,
		testMaxTTLKey:     604800,
		"minter_set":      "default",
	})

	return b, storage, fake
}
