package credentialdo

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const minterTokenKey = "token"

func TestSelectMinter_SkipsCooldownMinter(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	// Setup backend
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	bk := b.(*backend)
	storage := config.StorageView

	// config: operational settings
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{"do_api_url": srv.URL},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// minter set with TWO minters so there's a sibling to fall to
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "minter-1", minterTokenKey: "dop_v1_test1", "never_expires": true},
				map[string]interface{}{"id": "minter-2", minterTokenKey: "dop_v1_test2", "never_expires": true},
			},
		},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Drive minter-1 into 429 cool-down
	bk.recordMinterError("default", "minter-1", http.StatusTooManyRequests, time.Now())

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
