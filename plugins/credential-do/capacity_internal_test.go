package credentialdo

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/minteraffinity"
	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Per-minter credential capacity: several clouds cap how many credentials one account may hold, so a
// set is how the ceiling is raised — (limit x minters) rather than (limit). These tests cover the two
// halves an operator depends on: a full minter is passed OVER, and a set with no room left says so in
// a way that names the fix.

// fillTracking writes n tracking records attributed to a minter, as issuance does.
func fillTracking(t *testing.T, storage logical.Storage, minterID string, n int) {
	t.Helper()
	for i := range n {
		entry, err := logical.StorageEntryJSON(
			fmt.Sprintf("%s%s-%d", activeTrackingPrefix, minterID, i),
			map[string]interface{}{fieldRole: "test-role", "minter": minterID})
		if err != nil {
			t.Fatalf("encoding a tracking record failed: %v", err)
		}
		if err := storage.Put(t.Context(), entry); err != nil {
			t.Fatalf("writing a tracking record failed: %v", err)
		}
	}
}

// twoMinterBackend returns a backend configured with a two-minter set.
func twoMinterBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	cfg := logical.TestBackendConfig()
	cfg.StorageView = &logical.InmemStorage{}
	b, err := Factory(t.Context(), cfg)
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	storage := cfg.StorageView
	write := func(path string, data map[string]interface{}) {
		t.Helper()
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("write %s failed: err=%v resp=%v", path, err, resp)
		}
	}
	// No api_url: nothing here reaches upstream, and the capability probe is off by omission of a
	// bound role at set-write time.
	write("minter-sets/default", map[string]interface{}{
		"minters": []interface{}{
			map[string]interface{}{"id": "minter-1", minterTokenKey: "dop_v1_a", "never_expires": true},
			map[string]interface{}{"id": "minter-2", minterTokenKey: "dop_v1_b", "never_expires": true},
		},
	})
	return b.(*backend), storage
}

// TestAFullMinterIsPassedOverNotFailedOn is the failover the feature exists for.
func TestAFullMinterIsPassedOverNotFailedOn(t *testing.T) {
	bk, storage := twoMinterBackend(t)
	const limit = 8
	fillTracking(t, storage, "minter-1", limit)

	capacity, err := mintercapacity.Snapshot(t.Context(), storage, activeTrackingPrefix, limit)
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}

	// Pin the affinity key to one that prefers the FULL minter, so the test proves failover rather
	// than accidentally choosing the empty one.
	key := keyPreferring(t, "minter-1")
	sel, err := bk.selectMinter("default", key, capacity, time.Now())
	if err != nil {
		t.Fatalf("selection failed although one minter had room: %v (usage %s)", err, capacity.Describe())
	}
	if sel.minterID != "minter-2" {
		t.Errorf("selected %q, want minter-2: minter-1 holds %d/%d and must be passed over",
			sel.minterID, capacity.Used["minter-1"], limit)
	}
}

// TestASetWithNoRoomSaysSoAndNamesTheFix: when every minter is full, the client must get an error that
// is distinguishable from an unhealthy set — nothing is wrong with the credentials, and rotating one
// would not help.
func TestASetWithNoRoomSaysSoAndNamesTheFix(t *testing.T) {
	bk, storage := twoMinterBackend(t)
	const limit = 4
	fillTracking(t, storage, "minter-1", limit)
	fillTracking(t, storage, "minter-2", limit)

	capacity, err := mintercapacity.Snapshot(t.Context(), storage, activeTrackingPrefix, limit)
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	_, err = bk.selectMinter("default", "", capacity, time.Now())
	if err == nil {
		t.Fatal("selection succeeded although every minter was at its limit")
	}

	resp := credenvelope.ResponseFor(err)
	code, _ := credenvelope.CodeOf(resp.Data["error"].(string))
	if code != credenvelope.ErrPoolExhausted {
		t.Errorf("a full set reported %q, want %q: the client's action is to retry later or ask for "+
			"capacity, which is what pool_exhausted means — not upstream_auth_failed, which says "+
			"the credentials are broken", code, credenvelope.ErrPoolExhausted)
	}
	message := resp.Data["error"].(string)
	for _, want := range []string{"add a minter", "minter-1=4/4"} {
		if !strings.Contains(message, want) {
			t.Errorf("the refusal does not contain %q, so it does not name the fix or the usage: %s",
				want, message)
		}
	}
}

// TestAnUnenforcedLimitLeavesSelectionAlone: every cloud whose cap is undocumented runs with no limit,
// so the default must not change behaviour — or nine plugins would start refusing issuance.
func TestAnUnenforcedLimitLeavesSelectionAlone(t *testing.T) {
	bk, storage := twoMinterBackend(t)
	fillTracking(t, storage, "minter-1", 500)
	fillTracking(t, storage, "minter-2", 500)

	capacity, err := mintercapacity.Snapshot(t.Context(), storage, activeTrackingPrefix, 0)
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if _, err := bk.selectMinter("default", "", capacity, time.Now()); err != nil {
		t.Errorf("selection failed with a thousand credentials outstanding and NO limit configured: "+
			"%v. An unset limit must mean unenforced", err)
	}
}

// TestCapacityAndHealthAreDifferentFaults: a full minter and a cooling-down minter are both skipped,
// but the resulting error when nothing is selectable must say which happened, since the fixes differ.
func TestCapacityAndHealthAreDifferentFaults(t *testing.T) {
	bk, storage := twoMinterBackend(t)
	const limit = 2
	fillTracking(t, storage, "minter-1", limit)
	fillTracking(t, storage, "minter-2", limit)
	// And make one of them unhealthy as well, so both conditions are true at once.
	bk.recordMinterError("default", "minter-1", http.StatusTooManyRequests, nil, time.Now())

	capacity, err := mintercapacity.Snapshot(t.Context(), storage, activeTrackingPrefix, limit)
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	_, err = bk.selectMinter("default", "", capacity, time.Now())
	if err == nil {
		t.Fatal("selection succeeded with every minter full")
	}
	// Capacity is reported, because it is the condition an operator can act on directly: a cooldown
	// clears itself, a full set does not.
	if !strings.Contains(err.Error(), "as many credentials as its account allows") {
		t.Errorf("with every minter full AND one throttled, the error did not mention capacity: %v", err)
	}
}

// keyPreferring finds an affinity key whose first preference is the named minter, so a test can force
// the interesting path rather than depending on which one the hash happens to pick.
func keyPreferring(t *testing.T, minterID string) string {
	t.Helper()
	ids := []string{"minter-1", "minter-2"}
	for i := range 200 {
		key := fmt.Sprintf("probe-%d", i)
		if minteraffinity.Order(key, ids)[0] == minterID {
			return key
		}
	}
	t.Fatalf("no key out of 200 preferred %q", minterID)
	return ""
}
