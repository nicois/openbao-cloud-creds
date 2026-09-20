package credentialgcp

import (
	"net/http"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const minterCredentialsJSONKey = "credentials_json"

func TestSelectMinter_SkipsCooldownMinter(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	bk := b.(*backend)
	// Inject a fake IAM client so selection does not build a real GCP client.
	bk.iamClientFn = func(string) IAMCredentialsClient { return nil }
	storage := config.StorageView

	// config: operational settings only
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]any{},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// minter set with TWO minters so there's a sibling to fall to
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]any{
			"minters": []any{
				map[string]any{"id": "minter-1", minterCredentialsJSONKey: "{\"k\":1}", "never_expires": true},
				map[string]any{"id": "minter-2", minterCredentialsJSONKey: "{\"k\":2}", "never_expires": true},
			},
		},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// Drive minter-1 into 429 cool-down
	bk.recordMinterError("default", "minter-1", http.StatusTooManyRequests, nil, time.Now())

	// selectMinter should skip cooling-down minter-1 and choose minter-2
	sel, err := bk.selectMinter("default", "", mintercapacity.State{}, time.Now())
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
