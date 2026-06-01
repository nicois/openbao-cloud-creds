package credentialoci

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	minterTokenKey = "token"
	mintersKey     = "minters"
)

// TestSelectMinterForSet_SkipsCooldownMinter verifies that a minter driven into
// a 429 cool-down is not chosen by selectMinterForSet while a healthy sibling
// exists. OCI is phased-rotation, so selection happens in the rotation /
// reconcile path (selectMinterForSet), not a JIT read path.
func TestSelectMinterForSet_SkipsCooldownMinter(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	bk := b.(*backend)
	// Route per-set minter clients through an in-memory fake.
	bk.SetClientFactory(func(string) OCIIAMClient { return NewTestFakeClient() })
	storage := config.StorageView

	// config: operational settings only (no minters)
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{testRegionField: testRegionValue},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// minter set with TWO minters so there's a sibling to fall to
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]interface{}{
			mintersKey: []interface{}{
				map[string]interface{}{"id": "minter-1", minterTokenKey: "tenancy:user1:fp:key", "never_expires": true},
				map[string]interface{}{"id": "minter-2", minterTokenKey: "tenancy:user2:fp:key", "never_expires": true},
			},
		},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Drive minter-1 into 429 cool-down via its state machine.
	bk.mu.RLock()
	ms1 := bk.minterSets["default"]["minter-1"]
	bk.mu.RUnlock()
	if ms1 == nil {
		t.Fatal("minter-1 state not loaded")
	}
	ms1.sm.RecordError(http.StatusTooManyRequests, time.Now())

	// selectMinterForSet should skip cooling-down minter-1 and choose minter-2
	minterID, client, err := bk.selectMinterForSet("default")
	if err != nil {
		t.Fatalf("selectMinterForSet: %v", err)
	}
	if client == nil {
		t.Fatal("expected a client for the healthy sibling")
	}
	if minterID == "minter-1" {
		t.Fatal("expected cooling-down minter-1 to be skipped, sibling minter-2 chosen")
	}
	if minterID != "minter-2" {
		t.Fatalf("expected minter-2 to be selected, got %s", minterID)
	}
}
