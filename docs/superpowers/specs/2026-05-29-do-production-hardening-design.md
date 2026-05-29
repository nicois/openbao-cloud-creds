# credential-do Production Hardening — Design Spec

**Status:** Approved (2026-05-29)
**Scope:** Background workers, real reconciler integration, metrics flush, stale query, Prometheus emission

## Goal

Bring the DO reference implementation from "works in tests with fakes" to "production-ready with observability." After this work, the plugin self-heals from upstream failures, actively reclaims orphaned tokens, flushes access metrics to durable storage, and emits Prometheus-compatible telemetry.

## Architecture

A new `pkg/worker/` package provides a generic lifecycle manager for background goroutines. The DO plugin registers three workers with it:

1. **Health-check** — probes auth_failing minters, transitions them back to healthy
2. **Metrics flush** — persists in-memory access data to plugin storage
3. **Reconciler** — lists upstream DO tokens, deletes orphans matching the owner-tag prefix

All workers share a single `context.Context` from the plugin lifecycle. The manager handles start, stop, restart-on-config-change, and clean shutdown.

## Component 1: Worker Manager (`pkg/worker/`)

### Interface

```go
type WorkerFunc func(ctx context.Context) error

type WorkerManager struct { ... }

func New() *WorkerManager
func (wm *WorkerManager) Register(name string, interval time.Duration, opts WorkerOpts, fn WorkerFunc)
func (wm *WorkerManager) Start(ctx context.Context)
func (wm *WorkerManager) Stop()
func (wm *WorkerManager) Running() bool
```

### WorkerOpts

```go
type WorkerOpts struct {
    InitialDelay time.Duration // delay before first tick (e.g., reconciler bootstrap_delay)
}
```

### Behavior

- `Register` adds a worker definition. Must be called before `Start`.
- `Start` launches one goroutine per registered worker. Each goroutine sleeps `InitialDelay` (if set), then ticks at `interval`.
- `Stop` cancels the shared context and waits for all goroutines to return.
- On config rewrite: the plugin calls `Stop()`, re-registers with new intervals, calls `Start()`.
- A worker that returns an error: the error is logged, the worker sleeps until the next tick. No crash-the-world.

### Testing

Unit tests use a fake clock (passed via opts or interface) to advance time without real sleeps.

## Component 2: Health-Check Worker

**Interval:** 5 minutes (configurable via config)
**Initial delay:** None

### Per-tick logic

1. Iterate all minters where `sm.NeedsHealthCheck(now)` returns true
2. For each: call `GET /v2/account` using that minter's token
3. On 200: `sm.RecordSuccess(now)` → minter transitions to healthy
4. On error: no-op (stays in auth_failing, retried next tick)
5. Emit Prometheus gauge metrics for all minters (state, expires_in, last_success_ago, consecutive_failures)

### DO client addition

```go
func (c *doClient) CheckHealth(ctx context.Context) (int, error)
```

Calls `GET /v2/account` with the minter's token. Returns HTTP status code. Cheaper than minting a token and doesn't consume token quota.

### State machine addition

`pkg/recovery/state.go` gets:
```go
func (sm *StateMachine) ConsecutiveFailures() int
```

Tracks failures since last success. Reset to 0 on `RecordSuccess`.

## Component 3: Metrics Flush Worker

**Interval:** `flush_interval` from config (default 15min)
**Initial delay:** None

### Per-tick logic

1. Call `b.accessTracker.Flush(ctx, time.Now())`
2. Flush writes in-memory entries to plugin storage under `metrics/<entity_id>/<role>/<node_id>`

### Interface change (breaking)

The `MetricsStore` interface gains `context.Context` on all methods:

```go
type MetricsStore interface {
    Put(ctx context.Context, key string, value []byte) error
    Get(ctx context.Context, key string) ([]byte, error)
    List(ctx context.Context, prefix string) ([]string, error)
}
```

All callers (`InMemoryStore`, `AccessTracker`, tests) updated accordingly.

### Storage adapter

A new `StorageAdapter` in `plugins/credential-do/` wraps `logical.Storage` to satisfy `MetricsStore`:

```go
type storageAdapter struct {
    storage logical.Storage
}

func (s *storageAdapter) Put(ctx context.Context, key string, value []byte) error {
    return s.storage.Put(ctx, &logical.StorageEntry{Key: key, Value: value})
}
// Get, List similarly
```

Created in `Factory` and passed to `NewAccessTracker`.

## Component 4: Reconciler Integration

**Interval:** `reconcile_cadence` from config (default 6h)
**Initial delay:** `bootstrap_delay` from config (default 24h)

### Per-tick logic

1. Build a `doCloudLister` that calls `GET /v2/tokens`, filters to names matching `cloud-creds-*`
2. Build a `leaseRegistry` that checks plugin storage for known leases
3. Call `reconciler.Run(ctx, now)` with the constructed lister and registry
4. Log results, emit `cloud_creds_orphans_found` and `cloud_creds_auto_deleted_total` metrics

### DO client addition

```go
func (c *doClient) ListTokens(ctx context.Context) ([]tokenInfo, error)
```

Calls `GET /v2/tokens`, returns all tokens. The `doCloudLister` filters by prefix.

### doCloudLister (implements `reconciler.CloudLister`)

```go
type doCloudLister struct {
    client *doClient
    prefix string // "cloud-creds-"
}

func (l *doCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error)
func (l *doCloudLister) DeleteEntity(ctx context.Context, id string) error
```

### leaseRegistry (implements `reconciler.Registry`)

```go
type leaseRegistry struct {
    storage logical.Storage
}

func (r *leaseRegistry) IsKnown(id string) bool
```

Checks plugin storage for any active lease referencing this upstream token ID.

### Manual trigger endpoint

`POST reconcile` now calls the real `reconciler.Run()` instead of returning zeros. Accepts `mode=dry_run`. Returns the actual `Result` struct as JSON.

## Component 5: Metrics Stale Endpoint

### AccessTracker addition

```go
func (t *AccessTracker) ListStaleEntities(ctx context.Context, olderThan time.Duration, now time.Time) ([]string, error)
```

1. Lists all keys under `metrics/` prefix
2. Groups by entity_id, merges access data across nodes
3. Filters to entities where merged `last_access_at` is before `now - olderThan`
4. Returns entity IDs sorted by staleness (oldest first)

### Endpoint

`GET metrics/stale?older_than=7d` calls `ListStaleEntities` and returns the list via `logical.ListResponse`.

## Component 6: Prometheus Emission

### Metrics emitted

| Metric | Type | Labels | Source |
|--------|------|--------|--------|
| `cloud_creds_upstream_expires_in_seconds` | Gauge | cloud, cred_id | Health-check tick |
| `cloud_creds_upstream_state` | Gauge (0/1 per state) | cloud, cred_id, state | Health-check tick |
| `cloud_creds_upstream_last_success_seconds_ago` | Gauge | cloud, cred_id | Health-check tick |
| `cloud_creds_upstream_consecutive_failures` | Gauge | cloud, cred_id | Health-check tick |
| `cloud_creds_lease_issued_total` | Counter | cloud, role | pathCredsRead |
| `cloud_creds_lease_revoke_failures_total` | Counter | cloud, role | pathCredsRevoke |
| `cloud_creds_auto_deleted_total` | Counter | cloud, role, reason | Reconciler |
| `cloud_creds_orphans_found` | Gauge | cloud | Reconciler |
| `cloud_creds_reconcile_last_run_seconds_ago` | Gauge | cloud | Reconciler |
| `cloud_creds_reconcile_disabled` | Gauge | cloud, role | Config read |

### Implementation

A `telemetry.go` file in the plugin wraps the OpenBao metrics API (`metrics.SetGauge`, `metrics.IncrCounter` from `github.com/armon/go-metrics` which OpenBao uses internally). Labels use the `[]metrics.Label` pattern.

Health-check worker emits gauge metrics on each tick for all minters. Counters are incremented inline in request handlers.

## Testing

- **pkg/worker/**: Unit test with fake clock — verify workers tick at correct intervals, respect initial delay, shut down cleanly on Stop.
- **Health-check**: Integration test with DO fake — inject 401, verify minter stays auth_failing, then clear the injection, advance past health-check interval, verify recovery.
- **Metrics flush**: Test flush writes to plugin storage adapter, verify data round-trips through MergeEntity.
- **Reconciler integration**: Test with DO fake pre-seeded with orphan tokens — verify they appear in results and get deleted (or not, in dry-run).
- **Stale endpoint**: Seed metrics with old timestamps, verify stale query returns them.
- **Prometheus**: Verify metric values after issuance/revoke/health-check cycles (read from go-metrics InmemSink in tests).

## Files created/modified

### New files
- `pkg/worker/worker.go` — WorkerManager implementation
- `pkg/worker/worker_test.go`
- `plugins/credential-do/telemetry.go` — Prometheus metric wrappers
- `plugins/credential-do/reconciler_integration.go` — doCloudLister, leaseRegistry
- `plugins/credential-do/health_check.go` — health-check worker function
- `plugins/credential-do/workers.go` — worker registration and lifecycle

### Modified files
- `pkg/metrics/access.go` — Add context.Context to MetricsStore interface, add ListStaleEntities
- `pkg/metrics/access_test.go` — Update for context.Context parameter
- `pkg/recovery/state.go` — Add ConsecutiveFailures() getter
- `pkg/recovery/state_test.go` — Test consecutive failures counter
- `plugins/credential-do/backend.go` — Add WorkerManager field, lifecycle hooks
- `plugins/credential-do/path_config.go` — Start/restart workers on config write
- `plugins/credential-do/path_creds.go` — Emit lease_issued counter
- `plugins/credential-do/path_metrics.go` — Real stale endpoint implementation
- `plugins/credential-do/path_reconcile.go` — Wire up real reconciler
- `plugins/credential-do/do_client.go` — Add CheckHealth, ListTokens methods
- `pkg/credenvelope/fakes/do.go` — Add GET /v2/account endpoint, extend list with prefix filter
