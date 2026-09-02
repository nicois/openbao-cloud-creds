package credentialdo

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestSelectMinter_SkipsRetired(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	bk := b.(*backend)
	storage := config.StorageView

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{"do_api_url": srv.URL},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config: %v %v", err, resp)
	}
	// two never_expires minters, then mark minter-1 retired in-memory
	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-1", minterTokenKey: "dop_v1_a", "never_expires": true},
			map[string]interface{}{"id": "minter-2", minterTokenKey: "dop_v1_b", "never_expires": true},
		}},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set: %v %v", err, resp)
	}

	bk.mu.Lock()
	bk.minterSets["default"]["minter-1"].minter.Retired = true
	bk.mu.Unlock()

	for i := 0; i < 10; i++ {
		sel, err := bk.selectMinter("default", "", mintercapacity.State{}, time.Now())
		if err != nil {
			t.Fatalf("selectMinter: %v", err)
		}
		if sel.minterID == "minter-1" {
			t.Fatal("retired minter-1 must never be selected")
		}
	}
}
