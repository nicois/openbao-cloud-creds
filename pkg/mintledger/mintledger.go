// Package mintledger records when this mount minted an upstream credential, for
// clouds whose list API does not report a creation time.
//
// The reconciler will not delete an entity whose age it cannot confirm: without a
// timestamp it cannot tell a genuine orphan from a credential issued moments ago and
// not yet tracked. That guard is right, and on Exoscale and Vultr it meant NOTHING
// was ever reclaimable — their list APIs return no creation time, the worker
// configures a 1h hold, and the manual endpoint floors any requested hold at 5
// minutes, so every entity was skipped forever while `/reconcile` reported
// `orphans_found: 0`. Both are hard-revoke clouds whose credentials have no upstream
// expiry, so a leak there is permanent (A5 in docs/audit-2026-08-22.md).
//
// The ledger supplies the missing fact from our own records rather than weakening
// the guard. Two properties make it work:
//
//   - It is written at MINT time and is NOT deleted on revoke. The leak this exists
//     to clean up is precisely the case where the upstream delete failed but the
//     tracking entry went away — so a ledger that followed the tracking entry would
//     be empty exactly when it is needed.
//   - An entity absent from the ledger stays unconfirmable, and therefore survives.
//     Anything this mount did not mint — an operator's own key, another mount's
//     credential — is still protected by the age guard it was always protected by.
//
// Entries are pruned by age, not by revocation, so the keyspace stays bounded
// without reintroducing the hole.
package mintledger

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Prefix is the storage prefix for ledger entries.
const Prefix = "mint-ledger/"

// Retention is how long an entry is kept. It must comfortably exceed the longest
// confirmation hold any caller configures (1h worker, 5m manual floor) plus the
// reconcile cadence, or an orphan could age out of the ledger before a pass looks
// at it — which would silently restore the unreclaimable state.
const Retention = 30 * 24 * time.Hour

// Record notes that this mount minted the given upstream credential id.
//
// A failure is returned rather than swallowed: the caller decides, and the honest
// consequence of an unrecorded mint is a credential that cannot later be reclaimed
// automatically, which an operator should be able to see in a log.
func Record(ctx context.Context, storage logical.Storage, id string, at time.Time) error {
	if storage == nil || id == "" {
		return nil
	}
	return storage.Put(ctx, &logical.StorageEntry{
		Key:   Prefix + url.PathEscape(id),
		Value: []byte(strconv.FormatInt(at.UTC().Unix(), 10)),
	})
}

// CreatedAt reports when this mount minted the given id, or the zero time when the
// ledger has never heard of it — which the reconciler reads as "age unconfirmable"
// and therefore as "do not delete".
func CreatedAt(ctx context.Context, storage logical.Storage, id string) time.Time {
	if storage == nil || id == "" {
		return time.Time{}
	}
	entry, err := storage.Get(ctx, Prefix+url.PathEscape(id))
	if err != nil || entry == nil {
		return time.Time{}
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(string(entry.Value)), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(seconds, 0).UTC()
}

// Prune deletes entries older than Retention and returns how many it removed, so a
// caller can log it. A read failure on one entry does not abort the sweep: pruning
// is housekeeping, and the fail-closed direction here is to keep an entry (which
// only ever protects a credential), not to abort.
func Prune(ctx context.Context, storage logical.Storage, now time.Time) (int, error) {
	if storage == nil {
		return 0, nil
	}
	keys, err := storage.List(ctx, Prefix)
	if err != nil {
		return 0, fmt.Errorf("listing the mint ledger: %w", err)
	}
	pruned := 0
	for _, key := range keys {
		entry, err := storage.Get(ctx, Prefix+key)
		if err != nil || entry == nil {
			continue
		}
		seconds, convErr := strconv.ParseInt(strings.TrimSpace(string(entry.Value)), 10, 64)
		if convErr != nil {
			continue
		}
		if now.Sub(time.Unix(seconds, 0)) <= Retention {
			continue
		}
		if delErr := storage.Delete(ctx, Prefix+key); delErr == nil {
			pruned++
		}
	}
	return pruned, nil
}
