// Package mintercapacity tracks how many live credentials each minter has outstanding, so a set can
// be used to scale past a per-account cap on credential count.
//
// # The problem
//
// Several clouds cap how many credentials one account may hold at once — OCI allows two auth tokens
// per user, which is why that cloud uses phased rotation instead of JIT at all. A cap that is merely
// low rather than crippling is a different matter: JIT works, but issuance fails once the cap is
// reached, and it fails for whoever happens to ask next rather than for whoever is holding the
// credentials.
//
// A minter set already provides the answer, since each minter's cap is its own: spread issuance
// across minters and the ceiling is (cap x minters). What is needed is for selection to KNOW which
// minters have room, so it can pass over a full one instead of failing on it — and for an operator
// to be told before the ceiling is reached rather than after.
//
// # Where the count comes from, and what it misses
//
// From the mount's own tracking records — the `active-*/` entries written at mint and deleted at
// revoke — rather than from the cloud. That is deliberate: an upstream listing would be authoritative
// but costs an API call per issuance, against the very quota being conserved.
//
// The count is therefore what THIS MOUNT believes it holds, and it undercounts in two ways worth
// stating. It cannot see credentials created by anything else in the same account, and it cannot see
// orphans whose tracking record was lost (the create-then-track window). Both mean the real ceiling
// may arrive earlier than predicted, which is why the cloud's own refusal must still be handled — the
// count avoids wasted calls and enables the warning; it is not a substitute for the upstream's answer.
//
// # Why the count is cheap
//
// It is a storage list plus a read per entry, which sounds expensive until you notice what bounds it:
// the number of live credentials cannot exceed (cap x minters), because that is the whole point of
// the cap. Where no cap is configured the count is not taken at all.
package mintercapacity

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// FieldMinter is the key under which a tracking record names the minter that issued it. Every plugin
// writes the same name; a plugin that spelled it differently would silently report zero usage for
// every minter, which reads as "plenty of room" — the wrong direction to fail in.
const FieldMinter = "minter"

// State is a snapshot of per-minter usage against a cap.
//
// A zero Limit means UNENFORCED, not "no capacity": most clouds' caps are unknown, so the default
// must be to leave selection alone rather than to refuse everything.
type State struct {
	// Limit is the per-minter cap on live credentials. Zero disables every check here.
	Limit int
	// Used counts live credentials per minter id. Absent means zero.
	Used map[string]int
	// WarnAt is the usage level at which Nearing starts reporting true. Derived by Snapshot.
	WarnAt int
}

// Enforced reports whether a cap is configured at all.
func (s State) Enforced() bool { return s.Limit > 0 }

// HasRoom reports whether a minter may mint another credential. Always true when unenforced.
func (s State) HasRoom(minterID string) bool {
	if !s.Enforced() {
		return true
	}
	return s.Used[minterID] < s.Limit
}

// Nearing reports whether a minter is close enough to its cap to be worth telling an operator about.
// The point of the warning is that the remedy — adding a minter — takes human time, so it has to
// arrive before the ceiling rather than with it.
func (s State) Nearing(minterID string) bool {
	if !s.Enforced() {
		return false
	}
	return s.Used[minterID] >= s.WarnAt
}

// Describe renders usage for a log line or an error message: minter ids and counts, sorted, with the
// cap. It names no credential, only counts.
func (s State) Describe() string {
	if !s.Enforced() {
		return "no per-minter credential limit is configured"
	}
	ids := make([]string, 0, len(s.Used))
	for id := range s.Used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%s=%d/%d", id, s.Used[id], s.Limit))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("no credentials outstanding (limit %d each)", s.Limit)
	}
	return strings.Join(parts, " ")
}

// warnFraction is how much of a minter's cap must be used before Nearing reports true. Four fifths:
// far enough along to be real, early enough that adding a minter is still a considered action rather
// than an incident.
const warnFraction = 0.8

// Snapshot counts live credentials per minter from the mount's tracking records.
//
// prefix is the storage prefix a plugin writes those records under — NOT uniform across clouds
// (`active-tokens/`, `active-users/`, `active-clients/`), so it is a parameter rather than a constant.
//
// A zero limit short-circuits: no listing, no reads, an unenforced State. That keeps the cost at zero
// for the clouds whose cap nobody knows.
func Snapshot(ctx context.Context, storage logical.Storage, prefix string, limit int) (State, error) {
	state := State{Limit: limit, Used: map[string]int{}}
	if limit <= 0 {
		return state, nil
	}
	state.WarnAt = max(int(float64(limit)*warnFraction),
		// A cap of one has no room for a gentle warning; the first credential is the last.
		1)

	ids, err := storage.List(ctx, prefix)
	if err != nil {
		return state, fmt.Errorf("listing %s to count outstanding credentials: %w", prefix, err)
	}
	for _, id := range ids {
		entry, err := storage.Get(ctx, prefix+id)
		if err != nil {
			return state, fmt.Errorf("reading %s%s: %w", prefix, id, err)
		}
		if entry == nil {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal(entry.Value, &record); err != nil {
			// A record we cannot read is still a credential that exists. Counting it against an
			// unknown minter would be wrong, but ignoring it entirely would overstate room, so it
			// is counted under the empty id — visible in Describe, and it makes no minter look
			// emptier than it is.
			state.Used[""]++
			continue
		}
		minterID, _ := record[FieldMinter].(string)
		state.Used[minterID]++
	}
	return state, nil
}
