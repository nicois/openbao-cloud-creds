package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// cachePrefix is the storage prefix for remembered probe verdicts.
const cachePrefix = "capability-cache/"

// DefaultCacheTTL is how long a successful probe stands in for a fresh one.
//
// It is a trade, and worth stating plainly in both directions. Without a cache a
// single minter-set write costs up to (active minters x bound roles) real mints,
// every write, so an idempotent `terraform apply` or a CI loop re-mints the whole
// fan-out each time — and on OVH, which has no revoke API at all, each of those
// probes leaves a live one-hour token behind (A29). With one, a probe verdict can
// be up to this old: an operator who revokes a minter's grant upstream and then
// writes a role can have the role accepted on the strength of a probe from earlier.
//
// An hour is chosen because upstream grants change on a human timescale while
// configuration writes arrive in bursts, and because the consequence of a stale
// PASS is bounded — issuance then fails loudly at read time with the upstream's own
// refusal, which is exactly the state the probe exists to make rarer, not a state
// it is the last line of defence against. Set capability_cache_ttl=0 to disable.
const DefaultCacheTTL = time.Hour

// Cache remembers which (minter, mint shape) pairs have recently been proved, so a
// repeated configuration write does not re-mint the entire fan-out.
//
// Only SUCCESSES are cached. A failure is never remembered: an operator who has
// just fixed a grant upstream must be able to retry immediately and see it work.
type Cache struct {
	// Storage is the mount's storage. Nil disables the cache.
	Storage logical.Storage
	// TTL is how long a verdict stands. Zero disables the cache.
	TTL time.Duration
	// Now is the clock, for tests. Defaults to time.Now.
	Now func() time.Time
}

// cacheEntry is what a remembered verdict looks like on disk. It holds no
// credential material: a fingerprint and a timestamp.
type cacheEntry struct {
	Fingerprint string `json:"fingerprint"`
	VerifiedAt  int64  `json:"verified_at"`
}

// fresh reports whether this exact probe was proved recently enough to skip. A nil
// receiver, absent storage or zero TTL all mean "no", so the probe runs — the safe
// direction, and the one a disabled cache must take.
func (c *Cache) fresh(ctx context.Context, check Check) bool {
	if !c.usable() || check.MinterJSON == nil {
		return false
	}
	entry, err := c.Storage.Get(ctx, c.key(check))
	if err != nil || entry == nil {
		return false
	}
	var stored cacheEntry
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		return false
	}
	// A changed credential behind the same minter id must re-prove itself: the id
	// is an operator's label, and rewriting a minter set with a new secret under an
	// old label is the ordinary way a credential is replaced.
	if stored.Fingerprint != c.fingerprint(check) {
		return false
	}
	age := c.now().Sub(time.Unix(stored.VerifiedAt, 0))
	return age >= 0 && age <= c.TTL
}

// store remembers a successful probe. A write failure is ignored deliberately:
// the only consequence is that the next write re-probes, which is what would have
// happened anyway.
func (c *Cache) store(ctx context.Context, check Check) {
	if !c.usable() || check.MinterJSON == nil {
		return
	}
	value, err := json.Marshal(cacheEntry{
		Fingerprint: c.fingerprint(check),
		VerifiedAt:  c.now().Unix(),
	})
	if err != nil {
		return
	}
	_ = c.Storage.Put(ctx, &logical.StorageEntry{Key: c.key(check), Value: value})
}

func (c *Cache) usable() bool {
	return c != nil && c.Storage != nil && c.TTL > 0
}

// key is a digest of the dedup key, so an arbitrary mint shape cannot produce an
// invalid storage path.
func (c *Cache) key(check Check) string {
	sum := sha256.Sum256([]byte(check.Key))
	return cachePrefix + hex.EncodeToString(sum[:])
}

// fingerprint digests the minter's stored form, so that replacing the credential
// behind a minter id invalidates the verdict recorded for it.
//
// Plain SHA-256 rather than a keyed MAC, deliberately: this entry lives in the same
// mount storage as the minter set itself, which holds the credential in the clear.
// A digest is therefore no exposure at all here — anyone who can read it can
// already read the secret — and a keyed version would only add a key to manage.
// The value is never returned by an endpoint, logged, or used as a label.
func (c *Cache) fingerprint(check Check) string {
	sum := sha256.Sum256(check.MinterJSON)
	return hex.EncodeToString(sum[:])
}

func (c *Cache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// PruneCache deletes verdicts older than ttl, and every verdict when ttl is zero
// (the cache having been turned off, its entries are now dead weight). Callers run
// it from the same housekeeping sweep that prunes the mint ledger.
func PruneCache(ctx context.Context, storage logical.Storage, now time.Time, ttl time.Duration) (int, error) {
	if storage == nil {
		return 0, nil
	}
	keys, err := storage.List(ctx, cachePrefix)
	if err != nil {
		return 0, fmt.Errorf("listing the capability cache: %w", err)
	}
	pruned := 0
	for _, key := range keys {
		if ttl > 0 && !expired(ctx, storage, cachePrefix+key, now, ttl) {
			continue
		}
		if err := storage.Delete(ctx, cachePrefix+key); err == nil {
			pruned++
		}
	}
	return pruned, nil
}

// expired reads one entry and reports whether it has aged out. An unreadable or
// unparseable entry counts as expired: it can never satisfy a probe anyway, so
// deleting it is both safe and tidy.
func expired(ctx context.Context, storage logical.Storage, key string, now time.Time, ttl time.Duration) bool {
	entry, err := storage.Get(ctx, key)
	if err != nil || entry == nil {
		return true
	}
	var stored cacheEntry
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		return true
	}
	return now.Sub(time.Unix(stored.VerifiedAt, 0)) > ttl
}

// SweepCache prunes expired verdicts and reports the outcome. It exists so the
// ten housekeeping workers that call it are one line each rather than ten copies
// of the same logging block, which is how the copies drift.
func SweepCache(ctx context.Context, storage logical.Storage, cloud string, logger hclog.Logger, ttl time.Duration) {
	pruned, err := PruneCache(ctx, storage, time.Now(), ttl)
	if logger == nil {
		return
	}
	switch {
	case err != nil:
		logger.Warn("could not prune the capability cache", "cloud", cloud, "error", err)
	case pruned > 0:
		logger.Info("pruned capability-cache entries", "cloud", cloud, "pruned", pruned)
	}
}
