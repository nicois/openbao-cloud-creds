package cloudconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// minterSetPrefix is the storage prefix every plugin persists its minter sets
// under.
const minterSetPrefix = "minter-sets/"

// MinterUpstreamIDs returns every upstream credential ID this mount owns by way
// of a minter, read from the given RotationParams keys across every minter in
// every set — **including retired ones**, which are still ours for the whole
// retirement grace.
//
// This exists because the reconciler's owned-set was incomplete, and that
// incompleteness deleted live credentials (A1 in docs/audit-2026-08-22.md). A
// rotation successor is deliberately named with the owner prefix, so the
// reconciler's filter selects it; but it is not a lease, so lease tracking has
// never heard of it. The minter entries are the only place that knowledge lives.
//
// "Owned" is therefore the right question, and "does a lease reference it" was
// the wrong one. A name-prefix exemption would have been the cheaper fix and the
// wrong one: it makes deletion safety depend on a naming convention that upstream
// state can violate, where this makes it depend on what we recorded.
//
// **Fail-closed.** A storage or parse error is returned rather than skipped: an
// incomplete owned-set is exactly the condition under which the reconciler must
// delete nothing, and its caller already aborts the pass on error.
func MinterUpstreamIDs(ctx context.Context, storage logical.Storage, keys ...string) (map[string]struct{}, error) {
	owned := make(map[string]struct{})
	if storage == nil || len(keys) == 0 {
		return owned, nil
	}

	names, err := storage.List(ctx, minterSetPrefix)
	if err != nil {
		return nil, fmt.Errorf("listing minter sets to build the owned-set: %w", err)
	}
	for _, name := range names {
		entry, err := storage.Get(ctx, minterSetPrefix+name)
		if err != nil {
			return nil, fmt.Errorf("reading minter set %q to build the owned-set: %w", name, err)
		}
		if entry == nil {
			continue
		}
		var set MinterSet
		if err := json.Unmarshal(entry.Value, &set); err != nil {
			return nil, fmt.Errorf("parsing minter set %q to build the owned-set: %w", name, err)
		}
		for i := range set.Minters {
			for _, key := range keys {
				if id := set.Minters[i].RotationParams[key]; id != "" {
					owned[id] = struct{}{}
				}
			}
		}
	}
	return owned, nil
}

// MergeOwned folds extra IDs into an owned-set in place, so a plugin's registry
// can combine its lease-tracked IDs with its minter-owned IDs without each
// re-implementing the loop.
func MergeOwned(into, from map[string]struct{}) map[string]struct{} {
	if into == nil {
		into = make(map[string]struct{}, len(from))
	}
	for id := range from {
		into[id] = struct{}{}
	}
	return into
}

// ValidateIntervals rejects a non-positive operational interval at write time,
// returning the first offender's field name.
//
// This is the half of the A2 fix that belongs to the operator: worker.Register
// clamps defensively so a bad value cannot kill the process, but a clamp is a
// silent recovery, and someone who typed 0 should be told. Both halves exist
// because the audit's cross-cutting finding was guards applied at one site and
// not generalised.
func ValidateIntervals(intervals map[string]time.Duration) error {
	names := make([]string, 0, len(intervals))
	for name := range intervals {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic message when several are wrong
	for _, name := range names {
		if intervals[name] <= 0 {
			return fmt.Errorf("%s must be a positive duration, got %s: a zero or negative interval "+
				"is not runnable", name, intervals[name])
		}
	}
	return nil
}

// PreserveLifecycle carries per-minter lifecycle state from the stored set onto an
// incoming one, matched by minter ID, and stamps CreatedAt only on genuinely new
// minters.
//
// A minter-set write reconstructs each minter from the request and persists the set
// wholesale. Since the request body carries no `retired` / `retired_at` — they are
// plugin bookkeeping, not operator input — any write during the 7-day retirement
// grace silently un-retired a rotated-out minter: it re-entered issuance from a
// credential scheduled for deletion, AND the retired-sweep (keyed off RetiredAt)
// never fired again, so the old mint-capable upstream credential lived forever. The
// same write re-stamped CreatedAt on every minter, resetting the age gauge on
// minters that were years old (A13 in docs/audit-2026-08-22.md).
//
// Un-retiring is deliberately impossible here. If an operator genuinely wants a
// retired minter back, that is an explicit action, not a side effect of editing a
// set.
func PreserveLifecycle(incoming []Minter, stored *MinterSet, now time.Time) []Minter {
	byID := map[string]Minter{}
	if stored != nil {
		for i := range stored.Minters {
			byID[stored.Minters[i].ID] = stored.Minters[i]
		}
	}
	out := make([]Minter, 0, len(incoming))
	for i := range incoming {
		minter := incoming[i]
		if previous, existed := byID[minter.ID]; existed {
			minter.CreatedAt = previous.CreatedAt
			minter.Retired = previous.Retired
			minter.RetiredAt = previous.RetiredAt
			if len(minter.RotationParams) == 0 {
				minter.RotationParams = previous.RotationParams
			}
		} else if minter.CreatedAt.IsZero() {
			minter.CreatedAt = now
		}
		out = append(out, minter)
	}
	return out
}

// ValidateMinterIDs rejects a set whose minter ids are empty or duplicated.
//
// Neither was checked. A duplicate id satisfied the (>=2 expiring, >=7d gap) rule
// while `states[m.ID] = ...` collapsed the pair to one on load — producing exactly
// the single-expiring-minter configuration RSK-005 exists to forbid — and an absent
// id yielded the literal minter id "<nil>" via fmt.Sprintf("%v", nil).
func ValidateMinterIDs(minters []Minter) error {
	seen := make(map[string]struct{}, len(minters))
	for i := range minters {
		id := minters[i].ID
		if id == "" || id == "<nil>" {
			return fmt.Errorf("minter %d has no id; every minter needs a stable id", i)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("minter id %q appears more than once: ids are the key minters are "+
				"stored and selected by, so duplicates silently collapse to one", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}
