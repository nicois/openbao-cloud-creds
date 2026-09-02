package mintercapacity_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const prefix = "active-tokens/"

// track writes a tracking record shaped like the ones the plugins write.
func track(t *testing.T, storage logical.Storage, id, minterID string) {
	t.Helper()
	entry, err := logical.StorageEntryJSON(prefix+id, map[string]interface{}{
		"role": "reader", mintercapacity.FieldMinter: minterID, "created": "2026-09-03T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("encoding a tracking record failed: %v", err)
	}
	if err := storage.Put(t.Context(), entry); err != nil {
		t.Fatalf("writing a tracking record failed: %v", err)
	}
}

func TestUsageIsCountedPerMinter(t *testing.T) {
	storage := &logical.InmemStorage{}
	track(t, storage, "c1", "minter-1")
	track(t, storage, "c2", "minter-1")
	track(t, storage, "c3", "minter-2")

	state, err := mintercapacity.Snapshot(t.Context(), storage, prefix, 8)
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if state.Used["minter-1"] != 2 || state.Used["minter-2"] != 1 {
		t.Errorf("usage is %v, want minter-1=2 minter-2=1", state.Used)
	}
	if !state.HasRoom("minter-1") || !state.HasRoom("minter-3") {
		t.Error("a minter well under the cap was reported full")
	}
}

// TestAFullMinterHasNoRoom is what selection acts on.
func TestAFullMinterHasNoRoom(t *testing.T) {
	storage := &logical.InmemStorage{}
	const limit = 3
	for i := range limit {
		track(t, storage, fmt.Sprintf("c%d", i), "minter-1")
	}
	state, err := mintercapacity.Snapshot(t.Context(), storage, prefix, limit)
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if state.HasRoom("minter-1") {
		t.Errorf("a minter at %d/%d was reported as having room, so issuance would be attempted "+
			"and refused upstream instead of failing over", state.Used["minter-1"], limit)
	}
	if !state.HasRoom("minter-2") {
		t.Error("an unused minter was reported full, so failover would not happen")
	}
}

// TestAnUnconfiguredLimitChangesNothing: most clouds' caps are unknown, so the default must leave
// selection exactly as it was — and must not even pay for the count.
func TestAnUnconfiguredLimitChangesNothing(t *testing.T) {
	storage := &logical.InmemStorage{}
	for i := range 50 {
		track(t, storage, fmt.Sprintf("c%d", i), "minter-1")
	}
	state, err := mintercapacity.Snapshot(t.Context(), storage, prefix, 0)
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if state.Enforced() {
		t.Error("a zero limit reported itself as enforced")
	}
	if !state.HasRoom("minter-1") {
		t.Error("an unenforced state refused a minter; a cloud whose cap is unknown would stop " +
			"issuing entirely")
	}
	if state.Nearing("minter-1") {
		t.Error("an unenforced state warned about nearing a limit it does not have")
	}
	if len(state.Used) != 0 {
		t.Errorf("an unenforced snapshot counted %d records; it should not read storage at all",
			len(state.Used))
	}
}

// TestTheWarningArrivesBeforeTheCeiling is the operator-facing half. The remedy for a full set is
// adding a minter, which takes human time, so a warning that coincides with the ceiling is useless.
func TestTheWarningArrivesBeforeTheCeiling(t *testing.T) {
	storage := &logical.InmemStorage{}
	const limit = 8
	for i := range limit {
		state, err := mintercapacity.Snapshot(t.Context(), storage, prefix, limit)
		if err != nil {
			t.Fatalf("Snapshot failed: %v", err)
		}
		used := state.Used["minter-1"]
		switch {
		case used < 6 && state.Nearing("minter-1"):
			t.Errorf("warned at %d/%d, which is too early to be useful", used, limit)
		case used >= 7 && !state.Nearing("minter-1"):
			t.Errorf("did not warn at %d/%d, which is too late for anyone to add a minter before "+
				"the ceiling", used, limit)
		}
		track(t, storage, fmt.Sprintf("c%d", i), "minter-1")
	}
}

// TestACapOfOneStillWarns: the fraction rounds to zero for a cap of one, and a warning threshold of
// zero would fire with nothing outstanding.
func TestACapOfOneStillWarns(t *testing.T) {
	storage := &logical.InmemStorage{}
	state, err := mintercapacity.Snapshot(t.Context(), storage, prefix, 1)
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if state.Nearing("minter-1") {
		t.Error("warned about a minter with nothing outstanding")
	}
	track(t, storage, "c1", "minter-1")
	state, _ = mintercapacity.Snapshot(t.Context(), storage, prefix, 1)
	if !state.Nearing("minter-1") || state.HasRoom("minter-1") {
		t.Errorf("a cap of one was not reported as full and warning at 1/1: %v", state.Describe())
	}
}

// TestAnUnreadableRecordIsCountedNotIgnored pins the direction of an accounting failure. A record we
// cannot parse is still a credential that exists; ignoring it would make a minter look emptier than
// it is, which is how the cap gets exceeded.
func TestAnUnreadableRecordIsCountedNotIgnored(t *testing.T) {
	storage := &logical.InmemStorage{}
	track(t, storage, "good", "minter-1")
	if err := storage.Put(t.Context(), &logical.StorageEntry{
		Key: prefix + "corrupt", Value: []byte("not json"),
	}); err != nil {
		t.Fatalf("planting a corrupt record failed: %v", err)
	}

	state, err := mintercapacity.Snapshot(t.Context(), storage, prefix, 8)
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	total := 0
	for _, n := range state.Used {
		total += n
	}
	if total != 2 {
		t.Errorf("counted %d credentials from 2 records (%v); an unreadable one must still count, "+
			"or a minter looks emptier than it is", total, state.Used)
	}
	if state.Used["minter-1"] != 1 {
		t.Errorf("the unreadable record was attributed to minter-1 (%v); it belongs to no known "+
			"minter", state.Used)
	}
}

// TestDescribeNamesCountsAndTheCap: this string goes into the error a client sees when every minter
// is full, and into the operator's log. It must say enough to act on and nothing more.
func TestDescribeNamesCountsAndTheCap(t *testing.T) {
	storage := &logical.InmemStorage{}
	track(t, storage, "c1", "minter-1")
	state, _ := mintercapacity.Snapshot(t.Context(), storage, prefix, 8)

	got := state.Describe()
	for _, want := range []string{"minter-1", "1", "8"} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe() = %q, missing %q", got, want)
		}
	}
	if unenforced := (mintercapacity.State{}).Describe(); !strings.Contains(unenforced, "no per-minter") {
		t.Errorf("an unenforced Describe() = %q, which does not say the limit is unset", unenforced)
	}
}

// TestARecordWithNoMinterIsAttributedToNobody: older records, or a plugin that forgot the field,
// must not be silently credited to a real minter.
func TestARecordWithNoMinterIsAttributedToNobody(t *testing.T) {
	storage := &logical.InmemStorage{}
	raw, err := json.Marshal(map[string]interface{}{"role": "reader"})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := storage.Put(t.Context(), &logical.StorageEntry{Key: prefix + "old", Value: raw}); err != nil {
		t.Fatalf("planting failed: %v", err)
	}
	state, _ := mintercapacity.Snapshot(t.Context(), storage, prefix, 8)
	if state.Used["minter-1"] != 0 {
		t.Errorf("a record naming no minter was credited to minter-1: %v", state.Used)
	}
	if state.Used[""] != 1 {
		t.Errorf("a record naming no minter was not counted at all: %v", state.Used)
	}
}
