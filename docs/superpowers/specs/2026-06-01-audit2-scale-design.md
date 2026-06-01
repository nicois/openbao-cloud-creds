# Audit-2 Effort 3: Scale (#1, #3) — Design Spec

**Status:** Approved (2026-06-01)
**Scope:** The two findings the auditor flagged as the real blockers to production at the stated 100k scale: #1 (per-node metrics never persist — the cross-node design is unimplemented) and #3 (reconciler `IsKnown` is O(N²)). Grouped because both are scale-correctness fixes touching shared `pkg/` substrate + per-plugin wiring.

Both re-verified against the code at HEAD `fe0f352` during brainstorming (file:line below). Each fix is TDD; logic centralized in `pkg/`, applied mechanically at per-plugin sites.

## #1 — Storage-backed metrics + real per-node ID

**Bug (verified, re-scoped):** Every plugin builds its access tracker with `metrics.NewInMemoryStore()` and a hardcoded nodeID `"local"` (e.g. `credential-do/backend.go:73-74`, identical across all 10). There is no `logical.Storage`-backed `MetricsStore`. So the flush worker (`workers.go:30-31`, `cfg.FlushInterval`, default 15m) writes to an in-process map — lost on reload, never shared across nodes — directly contradicting `decisions.md` ("per-node-tagged keyspace flushed every 15m, merged across nodes").

**Re-scoping (verified):** `MergeEntity`/`ListStaleEntities` are consumed **only** by the read-only `/metrics` query endpoints (`pkg/metricspath/metricspath.go:57,82`). Nothing deletes based on them today. So #1 is currently an **observability data-loss** bug (the documented cross-node design is unimplemented); the auditor's "a reclamation job trusting `staleness_seconds` could delete an in-use entity" is a *latent future* risk that this fix forecloses by making the substrate real and correct.

**The `MetricsStore` interface is already storage-shaped** (`pkg/metrics/access.go:27-31`):
```go
type MetricsStore interface {
    Put(ctx context.Context, key string, value []byte) error
    Get(ctx context.Context, key string) ([]byte, error)
    List(ctx context.Context, prefix string) ([]string, error)
}
```
`InMemoryStore` already satisfies it; `Flush`/`MergeEntity`/`ListStaleEntities` are written against the interface, so a second implementation drops in with no consumer changes.

**Fix:**

1. **`pkg/metrics`: add `StorageBackedStore`** implementing `MetricsStore` over `logical.Storage`:
   - `Put(ctx, key, value)` → `storage.Put(ctx, &logical.StorageEntry{Key: key, Value: value})`.
   - `Get(ctx, key)` → `storage.Get(ctx, key)`; a nil entry returns the SAME `fmt.Errorf("key not found: %s", key)` error `InMemoryStore.Get` returns (consumers like `MergeEntity` call `Get` only on keys `List` returned, but the parity keeps the contract identical).
   - **`List(ctx, prefix)` MUST recurse and return full keys.** This is the one real trap: OpenBao's `logical.Storage.List` returns *hierarchical, relative immediate children* (a nested level appears as `"subdir/"`), NOT the flat full-key prefix match `InMemoryStore.List` returns. `MergeEntity`/`ListStaleEntities` both pass `List` results straight to `Get` and do `strings.HasSuffix(key, "/"+nodeID)` / `SplitN(TrimPrefix(key,"metrics/"),"/",3)` — they require full keys. So `StorageBackedStore.List` walks: for each child, if it ends in `/` recurse into `prefix+child`, else emit `prefix+child`. The keyspace is exactly `metrics/<esc-entity>/<esc-role>/<esc-node>` — 3 escaped levels (`url.PathEscape` strips embedded slashes), so recursion is bounded and shallow.
   - `InMemoryStore` stays unchanged (tests + the documented contract reference).

2. **Real nodeID — node-local, restart-stable (per brainstorming decision):** resolve at backend construction as `os.Getenv("OPENBAO_CLOUD_CREDS_NODE_ID")` → `os.Hostname()` → `"unknown-node"`. A small shared helper `metrics.ResolveNodeID() string` (so all 10 plugins resolve identically and it is unit-testable). **Not** a `PluginConfig` field: `PluginConfig` is persisted to `logical.Storage`, which raft replicates across all nodes — a persisted override would make every node read back one shared ID and collapse the per-node keyspace (the exact collision the node-local requirement exists to prevent). The env var is per-process (node-local) and survives restarts.

3. **Wire all 10 backends:** replace
   ```go
   store := metrics.NewInMemoryStore()
   b.accessTracker = metrics.NewAccessTracker("local", store)
   ```
   with
   ```go
   store := metrics.NewStorageBackedStore(conf.StorageView)
   b.accessTracker = metrics.NewAccessTracker(metrics.ResolveNodeID(), store)
   ```
   `conf.StorageView` is already available in every Factory (DO uses it at `backend.go:76-78`). Plugins that build the tracker before that line just reorder to use it.

**Touch:** `pkg/metrics/access.go` (+ `StorageBackedStore`, `ResolveNodeID`, tests), each plugin's `backend.go` tracker-construction site (10 plugins).

## #3 — Reconciler O(N²) → O(N), fail-closed

**Bug (verified):** `reconciler.Run` calls `r.registry.IsKnown(entity.ID)` per listed entity (`reconciler.go:87`), and each `IsKnown` does a fresh full `storage.List` + linear scan (`credential-do/reconciler_integration.go:50-61`, byte-identical in akamai/azure/exoscale/upcloud/vultr — only the active-prefix and not-found handling differ). N entities → N raft-backed Lists of ~N keys = O(N²). At 100k creds the pass cannot complete within cadence; orphan cleanup starves. **Secondary safety bug:** `IsKnown` returns `false` when `storage.List` errors — *fail-open*: unreachable storage makes every upstream entity look like an orphan, eligible for deletion.

**Fix (per brainstorming decision — change the shared interface):**

1. **`pkg/reconciler`: `Registry` interface** changes from
   ```go
   type Registry interface { IsKnown(id string) bool }
   ```
   to
   ```go
   type Registry interface { KnownIDs(ctx context.Context) (map[string]struct{}, error) }
   ```
   `Run` calls it **once** at the top, then membership-checks in-memory:
   ```go
   known, err := r.registry.KnownIDs(ctx)
   if err != nil {
       return nil, err   // fail-CLOSED: cannot enumerate known leases → delete nothing
   }
   ...
   for _, entity := range entities {
       if _, ok := known[entity.ID]; ok {
           continue
       }
       ...
   }
   ```
   This both makes the pass O(N) (one List + N map lookups) and flips the registry path to **fail-closed** — aligning it with `Run`'s existing fail-closed posture (it already skips orphans whose age it cannot confirm). A `KnownIDs` error aborting the pass is correct: deleting based on an incomplete known-set is the dangerous outcome.

2. **6 plugins** (DO, akamai, azure, exoscale, upcloud, vultr): `leaseRegistry.IsKnown` → `KnownIDs`:
   ```go
   func (r *leaseRegistry) KnownIDs(ctx context.Context) (map[string]struct{}, error) {
       entries, err := r.storage.List(ctx, "<active-prefix>/")
       if err != nil {
           return nil, err
       }
       known := make(map[string]struct{}, len(entries))
       for _, e := range entries {
           known[e] = struct{}{}
       }
       return known, nil
   }
   ```
   (active-prefix per plugin: DO/azure/exoscale/upcloud `active-tokens/`, akamai `active-clients/`, vultr `active-users/`.) The stored `ctx`/`r.ctx` field is dropped in favor of the passed `ctx` (the registry no longer needs to capture one at construction). Update the two construction sites per plugin (`workers.go` reconcileWorker + `path_reconcile.go`) — they no longer pass `ctx`.

   **Untouched:** AWS/GCP/OVH (no-revoke — no reconciler/registry) and OCI (phased rotation — no JIT lease registry). Confirmed: only the 6 hard-revoke plugins define a `leaseRegistry`.

**Touch:** `pkg/reconciler/reconciler.go` (interface + `Run` + tests), each of the 6 plugins' `reconciler_integration.go` + the 2 construction sites each.

## Testing

- **#1 `StorageBackedStore`:** unit tests against OpenBao's in-memory `logical.Storage` (`&logical.InmemStorage{}`): Put→Get round-trip; **`List` returns full recursive keys** for a 3-level `metrics/e/r/node` keyspace (the load-bearing contract test — fails for a naive non-recursing delegate); Get-missing returns the `"key not found"` error matching `InMemoryStore`. A `ResolveNodeID` test: env set → env wins; env empty → hostname; (hostname-empty fallback asserted via the documented `"unknown-node"` constant, since hostname can't be forced empty in-process — assert the env and precedence paths, document the final fallback).
- **#1 consumer parity:** existing `pkg/metrics/access_test.go` (written on `InMemoryStore`) stays green unchanged — proves `Flush`/`MergeEntity`/`ListStaleEntities` are store-agnostic. Add one test running the SAME merge/stale scenario through `StorageBackedStore` to prove the recursive `List` satisfies the consumers end-to-end.
- **#3 reconciler:** a counting-fake `Registry` proving `Run` calls `KnownIDs` **exactly once** regardless of entity count; a fake whose `KnownIDs` returns an error proving `Run` returns that error with **zero deletes** (fail-closed). Existing reconciler tests adapted from `IsKnown` to `KnownIDs`.
- **#3 per-plugin:** a `leaseRegistry` test (DO representative, lighter for the rest): seed `active-*/<id>` keys → `KnownIDs` returns the set; a storage stub returning a List error → `KnownIDs` propagates it (non-nil error, nil map).
- **Full gate:** 20 modules `go build` / `go test -race` / golangci-lint v2.12.2 (the v2 binary at `/home/claude-aiven-2/code/qualcheck/bin/golangci-lint`) 0 issues / `make smoke-test` 10/10; no new `//nolint`.

## Risk

- **#1 `List` recursion** is the one real correctness trap (hierarchical vs flat keys) — guarded by the explicit full-key-contract test and the end-to-end consumer-parity test. The `metrics/` keyspace being raft-replicated is *correct* — it is meant to merge cross-node; the per-node key suffix prevents collision, and `ResolveNodeID` keeps that suffix node-local.
- **#3 interface change** touches a shared interface + 6 impls + their construction sites — mechanical; existing reconciler tests (adapted) + the per-plugin tests are the guard. The fail-open→fail-closed flip is a deliberate safety **improvement** consistent with the reconciler's existing fail-closed age guard; it cannot cause a spurious delete (worst case: a pass aborts and retries next cadence).
- No envelope/error-contract change; no `api_version` bump; no new error code.

## Success criteria

1. `pkg/metrics.StorageBackedStore` exists, implements `MetricsStore` over `logical.Storage` with a **recursive full-key `List`**, unit-tested incl. the recursion contract; `ResolveNodeID` resolves env→hostname→`"unknown-node"`.
2. All 10 plugins construct the access tracker with `NewStorageBackedStore(conf.StorageView)` + `ResolveNodeID()`; no plugin uses `NewInMemoryStore()`/`"local"` in production code. Metrics survive reload and are written under a node-local key.
3. `pkg/reconciler.Registry` is `KnownIDs(ctx) (map[string]struct{}, error)`; `Run` calls it once and is O(N); a `KnownIDs` error aborts the pass with zero deletes (fail-closed). All 6 hard-revoke plugins implement it; their construction sites updated.
4. Reconciler is provably O(N) (one `KnownIDs` call per pass, verified by a counting fake) and fail-closed (error → zero deletes).
5. Whole workspace `go build` / `go test -race` / `make lint` / `make smoke-test` green; all 20 modules 0 lint; no new `//nolint`.

## Out of scope

- A storage-backed reclamation/GC job that actually deletes by `staleness_seconds` (the latent risk #1 forecloses — but building the reclaimer is a separate feature, not this fix; this effort only makes the substrate real and correct).
- Reconciler delete-throttling beyond the existing `MaxDeletesPerPass` cap (deferred with audit #8's reconciler-throttle part).
- The other audit-2 efforts (#9 minter lifecycle) and the deferred #7 (real-cloud integration tests).
- Migration of any pre-existing in-memory metrics (there are none persisted — nothing to migrate).
