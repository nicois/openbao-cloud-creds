package capability

import (
	"strings"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The default must be one value, not two that drift: cloudconfig cannot import
// this package (it would be a cycle), so it declares its own constant and this
// asserts they agree.
func TestDefaultCacheTTLAgreesWithCloudConfig(t *testing.T) {
	if DefaultCacheTTL != cloudconfig.DefaultCapabilityCacheTTL {
		t.Fatalf("capability.DefaultCacheTTL (%s) and cloudconfig.DefaultCapabilityCacheTTL (%s) "+
			"have drifted apart", DefaultCacheTTL, cloudconfig.DefaultCapabilityCacheTTL)
	}
}

func testCheck(minterJSON string) Check {
	return Check{Key: "minter-1|shape", Minter: "minter-1", MinterJSON: []byte(minterJSON)}
}

func TestCacheOnlyRepeatsWhatIsStillTrue(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	newCache := func(storage logical.Storage, ttl time.Duration, at time.Time) *Cache {
		return &Cache{Storage: storage, TTL: ttl, Now: func() time.Time { return at }}
	}

	t.Run("a stored verdict is reused within the TTL", func(t *testing.T) {
		storage := &logical.InmemStorage{}
		check := testCheck(`{"id":"minter-1","token":"secret"}`)
		newCache(storage, time.Hour, now).store(t.Context(), check)
		if !newCache(storage, time.Hour, now.Add(30*time.Minute)).fresh(t.Context(), check) {
			t.Error("a probe proved 30 minutes ago was re-run inside a one-hour TTL, so a repeated " +
				"configuration write still re-mints the whole fan-out")
		}
	})

	t.Run("a verdict expires", func(t *testing.T) {
		storage := &logical.InmemStorage{}
		check := testCheck(`{"id":"minter-1","token":"secret"}`)
		newCache(storage, time.Hour, now).store(t.Context(), check)
		if newCache(storage, time.Hour, now.Add(2*time.Hour)).fresh(t.Context(), check) {
			t.Error("a verdict older than the TTL was still trusted")
		}
	})

	t.Run("replacing the credential behind a minter id invalidates it", func(t *testing.T) {
		storage := &logical.InmemStorage{}
		newCache(storage, time.Hour, now).store(t.Context(), testCheck(`{"id":"minter-1","token":"old"}`))
		replaced := testCheck(`{"id":"minter-1","token":"new"}`)
		if newCache(storage, time.Hour, now).fresh(t.Context(), replaced) {
			t.Error("a NEW credential under the same minter id was taken as already proved. That is " +
				"the ordinary way a minter is rotated by hand, and it must re-prove itself")
		}
	})

	t.Run("a zero TTL disables the cache entirely", func(t *testing.T) {
		storage := &logical.InmemStorage{}
		check := testCheck(`{"id":"minter-1","token":"secret"}`)
		newCache(storage, 0, now).store(t.Context(), check)
		if newCache(storage, 0, now).fresh(t.Context(), check) {
			t.Error("capability_cache_ttl=0 must mean every write re-probes")
		}
	})

	t.Run("the stored entry contains no credential material", func(t *testing.T) {
		storage := &logical.InmemStorage{}
		check := testCheck(`{"id":"minter-1","token":"super-secret-token"}`)
		cache := newCache(storage, time.Hour, now)
		cache.store(t.Context(), check)
		entry, err := storage.Get(t.Context(), cache.key(check))
		if err != nil || entry == nil {
			t.Fatalf("nothing was stored: err=%v", err)
		}
		if got := string(entry.Value); strings.Contains(got, "super-secret-token") {
			t.Fatalf("the cache entry quotes the minter's secret: %s", got)
		}
	})
}

func TestPruneCacheClearsEverythingWhenDisabled(t *testing.T) {
	storage := &logical.InmemStorage{}
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	cache := &Cache{Storage: storage, TTL: time.Hour, Now: func() time.Time { return now }}
	cache.store(t.Context(), testCheck(`{"id":"minter-1"}`))

	pruned, err := PruneCache(t.Context(), storage, now, 0)
	if err != nil {
		t.Fatalf("prune failed: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("turning the cache off must clear its entries rather than leave them to be "+
			"trusted later; pruned %d", pruned)
	}
}
