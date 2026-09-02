package minteraffinity_test

import (
	"fmt"
	"sort"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/minteraffinity"
)

// The two properties this package claims — "balanced, best-effort" and "semi-stable" — are
// quantitative, so they are asserted quantitatively rather than described. A hash function that
// merely compiles satisfies neither.

func minters(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("minter-%d", i+1)
	}
	return ids
}

func keys(n int) []string {
	out := make([]string, n)
	for i := range out {
		// Shaped like a real key: an OpenBao token accessor is a UUID-ish opaque string, and a
		// hash with weak avalanche does noticeably worse on inputs that share a long prefix.
		out[i] = fmt.Sprintf("hvs.CAESIF-worker-accessor-%08d", i)
	}
	return out
}

// TestTheSameKeyAlwaysGetsTheSameShard is affinity itself. Without it the feature is round-robin
// with extra steps.
func TestTheSameKeyAlwaysGetsTheSameShard(t *testing.T) {
	ids := minters(5)
	for _, key := range keys(50) {
		first := minteraffinity.Order(key, ids)
		for range 5 {
			again := minteraffinity.Order(key, ids)
			if first[0] != again[0] {
				t.Fatalf("key %q chose %q then %q", key, first[0], again[0])
			}
		}
	}
}

// TestTheFallbackOrderIsAlsoStable: affinity is a preference, not a constraint, so a client whose
// shard is unhealthy falls to the next. That fallback has to be as stable as the primary —
// otherwise a client with one sick minter is back to random selection, which is the behaviour
// this replaces.
func TestTheFallbackOrderIsAlsoStable(t *testing.T) {
	ids := minters(6)
	for _, key := range keys(20) {
		want := minteraffinity.Order(key, ids)
		// Input order must not matter either: the plugin builds the id slice from a map.
		shuffled := append([]string(nil), ids...)
		sort.Sort(sort.Reverse(sort.StringSlice(shuffled)))
		got := minteraffinity.Order(key, shuffled)
		for i := range want {
			if want[i] != got[i] {
				t.Fatalf("key %q: order depends on the input order: %v vs %v", key, want, got)
			}
		}
	}
}

// TestTheOrderIsATotalPermutation: every minter must appear exactly once, or a client would have
// fewer fallbacks than the set has members — silently losing redundancy in the name of affinity.
func TestTheOrderIsATotalPermutation(t *testing.T) {
	ids := minters(7)
	for _, key := range append(keys(20), "") {
		got := minteraffinity.Order(key, ids)
		if len(got) != len(ids) {
			t.Fatalf("key %q produced %d entries for %d minters", key, len(got), len(ids))
		}
		seen := map[string]int{}
		for _, id := range got {
			seen[id]++
		}
		for _, id := range ids {
			if seen[id] != 1 {
				t.Errorf("key %q: minter %q appears %d times, want once", key, id, seen[id])
			}
		}
	}
}

// TestTheDistributionIsBalanced puts a number on "balanced". Ten thousand keys over five minters
// should give each about a fifth; anything outside a few percent means the hash is lumpy, and a
// lumpy hash defeats the purpose — one account would exhaust its budget while another idled.
func TestTheDistributionIsBalanced(t *testing.T) {
	const (
		keyCount     = 10000
		minterCount  = 5
		tolerancePct = 3.0
	)
	ids := minters(minterCount)
	counts := map[string]int{}
	for _, key := range keys(keyCount) {
		counts[minteraffinity.Order(key, ids)[0]]++
	}

	expected := float64(keyCount) / float64(minterCount)
	for _, id := range ids {
		deviation := (float64(counts[id]) - expected) / expected * 100
		if deviation > tolerancePct || deviation < -tolerancePct {
			t.Errorf("minter %q took %d of %d keys (%.1f%% off an even share); the shards are "+
				"lumpy, so one upstream budget is exhausted while another idles",
				id, counts[id], keyCount, deviation)
		}
	}
	t.Logf("distribution over %d minters: %v", minterCount, counts)
}

// TestAddingAMinterMovesAboutOneNthOfClients is the "semi-stable" claim, and the reason for
// rendezvous hashing rather than `hash % N`.
//
// Growing a set from 4 to 5 should move about 1/5 of clients — the ones that belong on the new
// minter — and leave the rest where they are. Modulo would move roughly 4/5 of them, migrating
// almost every worker's budget at once for what should be a routine capacity change.
func TestAddingAMinterMovesAboutOneNthOfClients(t *testing.T) {
	const keyCount = 10000
	before, after := minters(4), minters(5)

	moved := 0
	for _, key := range keys(keyCount) {
		if minteraffinity.Order(key, before)[0] != minteraffinity.Order(key, after)[0] {
			moved++
		}
	}

	movedPct := float64(moved) / float64(keyCount) * 100
	const ideal = 20.0 // 1/5
	if movedPct < ideal-3 || movedPct > ideal+3 {
		t.Errorf("adding a 5th minter moved %.1f%% of clients, want about %.0f%%. Much more than "+
			"that means the mapping is not consistent and every capacity change migrates the "+
			"whole fleet", movedPct, ideal)
	}
	t.Logf("growing 4 -> 5 minters moved %.1f%% of clients", movedPct)
}

// TestRemovingAMinterOnlyMovesItsOwnClients is the other half: retiring a minter must not disturb
// clients that were not on it. Rotation retires minters routinely, so a reshuffle on removal would
// make every rotation a fleet-wide budget migration.
func TestRemovingAMinterOnlyMovesItsOwnClients(t *testing.T) {
	const keyCount = 10000
	full := minters(5)
	reduced := full[:4] // minter-5 retired

	movedButShouldNotHave := 0
	for _, key := range keys(keyCount) {
		was := minteraffinity.Order(key, full)[0]
		now := minteraffinity.Order(key, reduced)[0]
		if was != "minter-5" && was != now {
			movedButShouldNotHave++
		}
	}
	if movedButShouldNotHave != 0 {
		t.Errorf("%d clients moved although their minter was not the one removed; a retirement "+
			"must not migrate anybody else", movedButShouldNotHave)
	}
}

// TestNoKeyIsRandomisedRatherThanFixed: with no affinity information the order must NOT be a
// constant, or every keyless caller piles onto one minter — worse than the map-iteration
// randomness this replaces.
func TestNoKeyIsRandomisedRatherThanFixed(t *testing.T) {
	ids := minters(6)
	firsts := map[string]int{}
	for range 600 {
		firsts[minteraffinity.Order("", ids)[0]]++
	}
	if len(firsts) < len(ids) {
		t.Errorf("an empty key reached only %d of %d minters in 600 draws: %v. Keyless callers "+
			"would concentrate rather than spread", len(firsts), len(ids), firsts)
	}
}

// TestKeyPrefersTheMostSpecificIdentity pins the ordering that decides whether this feature works
// at all. An identity entity is shared by every client of one auth role — a hundred workers on one
// AppRole is ONE entity — so keying on it would hash the whole fleet to a single minter.
func TestKeyPrefersTheMostSpecificIdentity(t *testing.T) {
	cases := []struct {
		name                             string
		explicit, accessor, entity, want string
	}{
		{"explicit beats everything", "task-7", "accessor-1", "entity-1", "task-7"},
		{"the token accessor beats the entity", "", "accessor-1", "entity-1", "accessor-1"},
		{"the entity is the last resort", "", "", "entity-1", "entity-1"},
		{"nothing means no affinity", "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := minteraffinity.Key(tc.explicit, tc.accessor, tc.entity); got != tc.want {
				t.Errorf("Key(%q,%q,%q) = %q, want %q", tc.explicit, tc.accessor, tc.entity, got, tc.want)
			}
		})
	}
}

// TestASingleMinterIsUnaffected: a set of one must behave exactly as before, whatever the key.
func TestASingleMinterIsUnaffected(t *testing.T) {
	for _, key := range append(keys(5), "") {
		got := minteraffinity.Order(key, []string{"only"})
		if len(got) != 1 || got[0] != "only" {
			t.Errorf("key %q over one minter gave %v", key, got)
		}
	}
}

// TestAnEmptySetDoesNotPanic: the caller checks for an unloaded set, but a nil slice reaching here
// must not be the thing that fails.
func TestAnEmptySetDoesNotPanic(t *testing.T) {
	for _, key := range []string{"k", ""} {
		if got := minteraffinity.Order(key, nil); len(got) != 0 {
			t.Errorf("key %q over no minters gave %v", key, got)
		}
	}
}

// TestOrderKeysMatchesOrder: the map convenience must not be a second implementation.
func TestOrderKeysMatchesOrder(t *testing.T) {
	states := map[string]int{"minter-1": 1, "minter-2": 2, "minter-3": 3, "minter-4": 4}
	ids := []string{"minter-1", "minter-2", "minter-3", "minter-4"}
	for _, key := range keys(20) {
		fromMap := minteraffinity.OrderKeys(key, states)
		fromSlice := minteraffinity.Order(key, ids)
		for i := range fromSlice {
			if fromMap[i] != fromSlice[i] {
				t.Fatalf("key %q: OrderKeys gave %v, Order gave %v", key, fromMap, fromSlice)
			}
		}
	}
}
