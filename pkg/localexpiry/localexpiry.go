// Package localexpiry prunes local tracking-storage entries whose recorded
// expiry has passed. It is used by no-revoke plugins (AWS/GCP/OVH) whose
// upstream credentials expire on their own, so reconciliation is purely a
// local-storage cleanup — distinct from pkg/reconciler, which deletes orphaned
// UPSTREAM entities.
package localexpiry

import (
	"context"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Result reports a prune pass.
type Result struct {
	Scanned int      // entries listed under the prefix
	Expired []string // keys (relative to prefix) whose expires_at is past `now`
	Deleted int      // entries actually deleted (0 when dryRun)
}

// Options configures a PruneExpired pass.
type Options struct {
	Prefix string       // storage key prefix to scan, e.g. "active-tokens/"
	Now    time.Time    // entries with expires_at before this are expired
	DryRun bool         // when true, report expired entries without deleting
	Logger hclog.Logger // optional; delete failures are logged here
}

// PruneExpired lists entries under opts.Prefix, reads each entry's stored
// "expires_at" (RFC3339), and deletes those already past opts.Now. A missing or
// malformed expires_at, or an unreadable entry, is skipped (not an error).
// opts.DryRun reports what would be deleted without deleting. A delete failure
// is logged and counted as not-deleted; it does not abort the pass.
func PruneExpired(ctx context.Context, storage logical.Storage, opts Options) (Result, error) {
	keys, err := storage.List(ctx, opts.Prefix)
	if err != nil {
		return Result{}, err
	}
	res := Result{Scanned: len(keys)}
	for _, key := range keys {
		if !isExpired(ctx, storage, opts.Prefix+key, opts.Now) {
			continue
		}
		res.Expired = append(res.Expired, key)
		if opts.DryRun {
			continue
		}
		if err := storage.Delete(ctx, opts.Prefix+key); err != nil {
			if opts.Logger != nil {
				opts.Logger.Warn("localexpiry: failed to delete expired entry", "key", key, "error", err)
			}
			continue
		}
		res.Deleted++
	}
	return res, nil
}

// isExpired reports whether the entry at fullKey records an "expires_at"
// (RFC3339) that is strictly before now. An unreadable/absent entry, a missing
// or empty timestamp, or an unparseable timestamp all report false (skip).
func isExpired(ctx context.Context, storage logical.Storage, fullKey string, now time.Time) bool {
	entry, err := storage.Get(ctx, fullKey)
	if err != nil || entry == nil {
		return false
	}
	var data map[string]any
	if err := entry.DecodeJSON(&data); err != nil {
		return false
	}
	expiresStr, ok := data["expires_at"].(string)
	if !ok || expiresStr == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil {
		return false
	}
	return now.After(expiresAt)
}
