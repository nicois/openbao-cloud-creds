package credentialazure

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestOwnedIDsIncludesMinterCredentials is the regression guard for A1, at the
// level where the defect actually lived: the plugin's registry, not the shared
// reconciler.
//
// A rotation successor is deliberately named with the owner prefix, so the
// lister selects it as a reconciler candidate. It is not a lease, so the tracking
// entries never mention it. If the registry omits minter-recorded upstream ids,
// the reconciler classifies the set's own mint-capable credential as an orphan
// and deletes it — leaving the mount unable to issue, rotate or revoke.
//
// A retired minter counts too: it stays ours for the whole retirement grace.
func TestOwnedIDsIncludesMinterCredentials(t *testing.T) {
	storage := &logical.InmemStorage{}
	ctx := t.Context()

	set := cloudconfig.MinterSet{Name: "primary", Minters: []cloudconfig.Minter{
		{ID: "successor", NeverExpires: true, RotationParams: map[string]string{fieldKeyID: "upstream-successor"}},
		{ID: "retired-one", NeverExpires: true, Retired: true, RetiredAt: time.Now(),
			RotationParams: map[string]string{fieldKeyID: "upstream-retired"}},
	}}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal set: %v", err)
	}
	if err := storage.Put(ctx, &logical.StorageEntry{Key: "minter-sets/primary", Value: raw}); err != nil {
		t.Fatalf("put set: %v", err)
	}

	owned, err := (&leaseRegistry{storage: storage}).OwnedIDs(ctx)
	if err != nil {
		t.Fatalf("OwnedIDs: %v", err)
	}
	for _, id := range []string{"upstream-successor", "upstream-retired"} {
		if _, ok := owned[id]; !ok {
			t.Errorf("OwnedIDs omits minter credential %q, so the reconciler would delete it as an "+
				"orphan (A1). Owned set: %v", id, owned)
		}
	}
}
