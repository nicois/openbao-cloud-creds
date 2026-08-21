package credentialaws

import (
	"net/http"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	minterAccessKeyIDKey     = "access_key_id"
	minterSecretAccessKeyKey = "secret_access_key"
	configRegionKey          = "region"
)

func TestSelectMinter_SkipsCooldownMinter(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	bk := b.(*backend)
	storage := config.StorageView

	// config: operational settings only
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{configRegionKey: "us-east-1"},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// minter set with TWO minters so there's a sibling to fall to
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "minter-1", minterAccessKeyIDKey: "AKIA1", minterSecretAccessKeyKey: "secret1", "never_expires": true},
				map[string]interface{}{"id": "minter-2", minterAccessKeyIDKey: "AKIA2", minterSecretAccessKeyKey: "secret2", "never_expires": true},
			},
		},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Drive minter-1 into 429 cool-down
	bk.recordMinterError("default", "minter-1", http.StatusTooManyRequests, nil, time.Now())

	// selectMinter should skip cooling-down minter-1 and choose minter-2
	sel, err := bk.selectMinter("default", time.Now())
	if err != nil {
		t.Fatalf("selectMinter: %v", err)
	}
	if sel.minterID == "minter-1" {
		t.Fatal("expected cooling-down minter-1 to be skipped, sibling minter-2 chosen")
	}
	if sel.minterID != "minter-2" {
		t.Fatalf("expected minter-2 to be selected, got %s", sel.minterID)
	}
}
