package credentialdo

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Scale benchmarks for the rotated Spaces type, which is the only lifecycle here designed for a
// mount holding hundreds of thousands of roles — one per droplet, each with its own bucket.
//
// What these measure, and what they deliberately do not:
//
//   - The READ path, which is what every client touches and what carries the fleet's whole load.
//     It re-serves a stored key: no upstream call, no minter selection, and since the lock became
//     per-role, no exclusive lock either. Parameterised by role count to show it is O(1) in N.
//   - The SWEEP, which walks every role on every pass. That is O(N) today and the reason a
//     retirement index is worth building: at 200k roles a pass loads 200k records to service the
//     ~2% that have anything retiring.
//   - The persisted SIZE of a role's record, which is the number that transfers to production.
//     Heap here is dominated by InmemStorage, which is not what a deployment uses, so the honest
//     memory figure is bytes-per-record times N against the real storage backend, plus whatever
//     OpenBao core spends on leases — neither of which lives in this process.
//
// Nothing per-role is held in the plugin's heap today: minterSets is keyed by set and minter, so
// the backend's own footprint is flat in role count. BenchmarkRotatedRead_Memory pins that, and it
// is the benchmark that will change the day an in-memory credential cache lands.
//
// Roles and their key records are seeded DIRECTLY into storage rather than written through the
// API, because a role write fires the capability probe: at these counts that would be hundreds of
// thousands of upstream mint-and-delete round trips, measuring the fake instead of the plugin.

const benchMinterID = "bench-minter"

// seedRotatedRoles writes n rotated roles and the key record each one already serves, as a
// rotation would have left them: current key not yet due, nothing retiring.
func seedRotatedRoles(tb testing.TB, storage logical.Storage, n, retiringEvery int) {
	tb.Helper()
	now := time.Now()
	for i := range n {
		name := fmt.Sprintf("droplet-%07d", i)
		role := &doRole{
			Name:           name,
			DefaultTTL:     15 * time.Minute,
			MaxTTL:         time.Hour,
			MinterSet:      "default",
			CredentialType: credentialTypeSpacesKeyRotated,
			Grants:         []spacesGrant{{Bucket: "bucket-" + name, Permission: "read"}},
			Region:         "nyc3",
			RotationPeriod: 90 * 24 * time.Hour,
			RotationJitter: 24 * time.Hour,
			OverlapTTL:     48 * time.Hour,
		}
		entry, err := logical.StorageEntryJSON("roles/"+name, role)
		if err != nil {
			tb.Fatalf("encoding role %q: %v", name, err)
		}
		if err := storage.Put(tb.Context(), entry); err != nil {
			tb.Fatalf("writing role %q: %v", name, err)
		}

		state := &sharedSpacesState{Current: &sharedSpacesKey{
			AccessKey: "DO00BENCH" + name,
			SecretKey: "secret-secret-secret-secret-secret-" + name,
			Grants:    role.Grants,
			MintedAt:  now,
			RotateAt:  now.Add(89 * 24 * time.Hour),
			MinterSet: "default",
			MinterID:  benchMinterID,
		}}
		// A slice of roles carry something retiring, which is what the sweep actually has work
		// for. The caller chooses the fraction; the lifecycle's own is overlap_ttl/rotation_period,
		// one role in 45 for a 48-hour overlap against 90 days.
		if retiringEvery > 0 && i%retiringEvery == 0 {
			state.Retiring = []retiringSpacesKey{{
				AccessKey: "DO00OLD" + name,
				MinterSet: "default",
				MinterID:  benchMinterID,
				RetiredAt: now.Add(-time.Hour),
				DeleteAt:  now.Add(47 * time.Hour),
			}}
		}
		if err := saveSharedSpacesState(tb.Context(), storage, name, state); err != nil {
			tb.Fatalf("writing the key record for %q: %v", name, err)
		}
	}
}

// benchBackend is a backend with a minter set and no roles, ready for direct seeding.
func benchBackend(tb testing.TB) (*backend, logical.Storage) {
	tb.Helper()
	cfg := logical.TestBackendConfig()
	cfg.StorageView = &logical.InmemStorage{}
	b, err := Factory(tb.Context(), cfg)
	if err != nil {
		tb.Fatalf("factory failed: %v", err)
	}
	storage := cfg.StorageView
	for path, data := range map[string]map[string]any{
		"config": {fieldDOAPIURLKey: "http://127.0.0.1:1", fieldVerifyCapability: false},
		"minter-sets/default": {fieldMintersKey: []any{map[string]any{
			"id": benchMinterID, minterTokenKey: "dop_v1_bench", neverExpiresKey: true,
		}}},
	} {
		resp, err := b.HandleRequest(tb.Context(), &logical.Request{
			Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			tb.Fatalf("write %s failed: err=%v resp=%v", path, err, resp)
		}
	}
	return b.(*backend), storage
}

// BenchmarkRotatedRead is the fleet's whole load: one client re-reading the key it already has.
// Reported per role count so the slope — there should not be one — is visible.
func BenchmarkRotatedRead(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("roles=%d", n), func(b *testing.B) {
			backend, storage := benchBackend(b)
			seedRotatedRoles(b, storage, n, 100)
			b.ReportAllocs()
			b.ResetTimer()

			var i int
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					i++
					name := fmt.Sprintf("droplet-%07d", i%n)
					resp, err := backend.HandleRequest(b.Context(), &logical.Request{
						Operation: logical.ReadOperation, Path: "creds/" + name, Storage: storage,
					})
					if err != nil || resp == nil || resp.IsError() {
						b.Fatalf("read %s failed: err=%v resp=%v", name, err, resp)
					}
				}
			})
		})
	}
}

// BenchmarkRotatedSweep is one lifecycle pass. It walks EVERY role, so this is the O(N) cost a
// retirement index would remove: only the roles with something retiring have work to do.
func BenchmarkRotatedSweep(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("roles=%d", n), func(b *testing.B) {
			backend, storage := benchBackend(b)
			seedRotatedRoles(b, storage, n, 100)
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				if err := backend.sweepRetiredSpacesKeys(b.Context(), storage, time.Now()); err != nil {
					b.Fatalf("sweep failed: %v", err)
				}
			}
			b.ReportMetric(float64(n), "roles")
		})
	}
}

// BenchmarkRotatedRead_Memory reports what a role costs, split into the part that transfers to a
// deployment and the part that does not.
//
// bytes/record is the persisted size, which is what N of them cost the real storage backend.
// heap-per-role is this process, and is dominated by InmemStorage holding every record — so it
// measures the harness, not the plugin. It is here to pin the property that matters: the
// backend's OWN structures are flat in role count, so the day that stops being true is visible.
func BenchmarkRotatedRead_Memory(b *testing.B) {
	const n = 100_000
	backend, storage := benchBackend(b)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	seedRotatedRoles(b, storage, n, 100)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	entry, err := storage.Get(b.Context(), sharedSpacesStateKey("droplet-0000000"))
	if err != nil || entry == nil {
		b.Fatalf("seeded record missing: err=%v", err)
	}
	roleEntry, err := storage.Get(b.Context(), "roles/droplet-0000000")
	if err != nil || roleEntry == nil {
		b.Fatalf("seeded role missing: err=%v", err)
	}

	b.ReportMetric(float64(len(entry.Value)), "bytes/key-record")
	b.ReportMetric(float64(len(roleEntry.Value)), "bytes/role-record")
	b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/n, "heap-B/role(harness)")
	b.ReportMetric(float64(len(backend.minterSets)), "minter-set-entries")

	// The read path, once, so the benchmark fails rather than reports if seeding was wrong.
	resp, err := backend.HandleRequest(b.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/droplet-0000000", Storage: storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		b.Fatalf("read of a seeded role failed: err=%v resp=%v", err, resp)
	}
}
