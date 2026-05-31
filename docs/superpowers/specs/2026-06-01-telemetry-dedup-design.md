# Cross-Plugin Telemetry De-duplication (Audit #7) — Design Spec

**Status:** Approved (2026-06-01)
**Goal:** Extract the genuinely-duplicated telemetry emit helpers and metrics query endpoint out of the 10 plugins into two focused shared packages, after verifying which of the audit's duplication claims still hold.

## Scope

Audit item **#7 only**. This is the last open audit item.

## Verification of the audit's claims

Audit #7 (`docs/audit-2026-05-31.md`) claimed `telemetry.go`/`workers.go`/`health_check.go`/`path_metrics.go` are "near-identical ×10". Re-verified by normalized-hash clustering (strip package line + comments + blank lines; replace cloud-name string literals with a placeholder):

- **`telemetry.go`:** 3 clusters — 6 byte-identical, 3 byte-identical (no-revoke plugins omit `emitLeaseRevokeFailed`), OCI alone. The emit helpers (`emitGauge`, `emitCounter`, `emitLeaseIssued`, `emitLeaseRevokeFailed`, `emitOrphansFound`, `workerErrorHandler`) are identical modulo the cloud name. **STRONG de-dup candidate — extract (Extraction A).**
- **`path_metrics.go`:** **7 byte-identical**, plus a 2-cluster (exoscale) and akamai; the two outliers differ ONLY in where/how the `defaultStaleAfterSeconds` const is named — the two handlers (`pathMetricsEntity`, `pathMetricsStale`) and path definitions are identical across all 10. **BIGGEST single win — extract (Extraction B).**
- **`health_check.go`:** all 10 DISTINCT (no two share a normalized hash). The audit's "identical" claim is **STALE** — per-cloud health probing legitimately differs. **Not extracted.**
- **`workers.go`:** mostly per-plugin (one cluster of 3); worker registration varies. **Not extracted.**

So the work is the two extractions the audit's "Fix" sentence actually named ("move emit helpers … metrics query paths into pkg/ helpers"), and explicitly NOT health_check/workers.

## Key constraint (decisions.md)

Per-plugin module isolation is deliberate (process isolation). Preserve it: each plugin keeps its own module + `backend.go`. Only the duplicated helper *bodies* move to shared `pkg/` packages, with cloud identity passed as a parameter. No new coupling between plugin modules; the dependency arrow stays `plugins → pkg`, never reversed.

## Why two NEW packages (not pkg/metrics)

Verification found **`pkg/metrics` is currently pure** — stdlib imports only (the `AccessTracker` is storage/SDK-agnostic; it does NOT depend on `hashicorp/go-metrics` or the OpenBao SDK). Putting the emitter (needs `go-metrics`) and the path constructor (needs the SDK `framework`/`logical`) into `pkg/metrics` would drag both heavy deps into a clean package. So the audit's literal "move into pkg/metrics" is corrected: two new focused packages, each owning exactly one dependency, and `pkg/metrics` stays import-pure.

## Extraction A — `pkg/telemetry.Emitter`

New package `pkg/telemetry` (depends on `github.com/hashicorp/go-metrics`). A small value type carrying cloud identity; the label *keys* are fixed by the envelope contract (identical across all plugins), only the cloud *value* and namespace vary:

```go
package telemetry

import metrics "github.com/hashicorp/go-metrics"

// Emitter emits cloud-creds metrics for a single plugin, carrying that
// plugin's cloud identity and metric namespace.
type Emitter struct {
	Cloud     string // e.g. "do" — the value of the "cloud" label
	Namespace string // e.g. "cloud_creds" — leading metric-key segment
}

func (e Emitter) Gauge(name string, val float32, labels []metrics.Label) { ... }   // append cloud label, prepend namespace
func (e Emitter) Counter(name string, labels []metrics.Label)            { ... }
func (e Emitter) LeaseIssued(role string)                                { ... }
func (e Emitter) LeaseRevokeFailed(role string)                          { ... }
func (e Emitter) OrphansFound(count int)                                 { ... }
func (e Emitter) WorkerError(worker string, err error)                   { ... }   // the counter half of workerErrorHandler
```
The label keys (`"cloud"`, `"role"`, `"minter_set"`, `"worker"`, etc.) are constants inside `pkg/telemetry` — they are identical across all plugins by the envelope contract, so they belong with the shared emitter, not per-plugin.

Each plugin's `telemetry.go` after extraction:
- Defines a package-level emitter, e.g. `var emit = telemetry.Emitter{Cloud: cloudName, Namespace: metricNamespace}` (reusing the plugin's existing `cloudName`/`metricNamespace` consts).
- The old package-level `emitCounter`/`emitGauge`/`emitLeaseIssued`/`emitLeaseRevokeFailed`/`emitOrphansFound` become thin one-line wrappers over `emit.*`, OR call sites switch to `emit.*` directly (implementer's choice for least churn — but keep call sites readable).
- `workerErrorHandler` becomes: log via `b.Logger().Warn(...)` + `emit.WorkerError(name, err)`.
- `emitMinterMetrics` STAYS per-plugin (it reaches into `b.minterSets`/`b.mu`/`ms.sm` — plugin-coupled), but its gauge calls route through `emit.Gauge` so its body shrinks and no longer needs the local `emitGauge`.
- Per-plugin `field*`/label-key consts that become unused after extraction MUST be removed (the `unused` linter will flag them) — expected churn.

## Extraction B — `pkg/metricspath.Paths`

New package `pkg/metricspath` (depends on SDK `framework`/`logical` + `pkg/metrics` for `*AccessTracker`). The two handlers depend only on the plugin's lock-guarded `*metrics.AccessTracker`:

```go
package metricspath

// Paths returns the metrics/entity and metrics/stale framework paths, backed
// by the AccessTracker the supplied accessor returns (lock-guarded by the
// caller). staleDefaultSeconds is the "older_than" schema default.
func Paths(accessor func() *metrics.AccessTracker, staleDefaultSeconds int) []*framework.Path { ... }
```
- `accessor` is a closure the plugin supplies, e.g. `func() *metrics.AccessTracker { b.mu.RLock(); defer b.mu.RUnlock(); return b.accessTracker }`. This keeps the lock discipline in the plugin (where `b.mu` lives) while the handler logic is shared.
- The two handlers (`pathMetricsEntity`: MergeEntity → return merged fields or nil; `pathMetricsStale`: ListStaleEntities → ListResponse) move verbatim into `metricspath`, reading the tracker via the accessor and returning the "metrics not initialized" error when it is nil.
- Each plugin's `path_metrics.go` collapses to: `func (b *backend) metricsPaths() []*framework.Path { return metricspath.Paths(func() *metrics.AccessTracker { b.mu.RLock(); defer b.mu.RUnlock(); return b.accessTracker }, defaultStaleAfterSeconds) }`.
- The per-plugin `defaultStaleAfterSeconds` (or `defaultStaleOlderThanSeconds`) const stays per-plugin (passed in); the response-key strings and path patterns move into `metricspath`.

## Testing

- **`pkg/telemetry`:** unit-test `Emitter` using `go-metrics`' in-memory sink (`metrics.NewInmemSink`) to capture emitted samples; table-assert each method's metric key + labels + value for a given Cloud/Namespace.
- **`pkg/metricspath`:** test the two handlers with an in-memory `metrics.AccessTracker` (the existing `metrics.NewInMemoryStore`): `pathMetricsEntity` returns merged fields for a recorded entity and nil for an unknown one; `pathMetricsStale` returns the stale list; both return "metrics not initialized" when the accessor yields nil.
- **Per-plugin (×10):** behavior-preservation is the bar. Each plugin's EXISTING metrics/telemetry/resilience tests (e.g. `TestMetricsEntityEndpoint`) must pass UNCHANGED after delegating to the shared packages. That is the regression guard — do not edit those tests to make them pass; if they fail, the delegation diverged.

## Risk

- High churn (all 10 plugins), low individual risk — mechanical delegation guarded by unchanged per-plugin tests.
- Dead-const cleanup: removing now-unused per-plugin `field*` consts; `unused` linter is the check.
- `emitMinterMetrics` stays per-plugin but is rewired to `emit.Gauge` — behavior-preserving, test-guarded.
- Two new modules → wire into `go.work`, Makefile `LINT_DIRS`, and BOTH CI loops (lint + govulncheck). The recurring new-module checklist (the gap caught for `pkg/plugintest` and `pkg/localexpiry`).

## Success criteria

1. `pkg/telemetry.Emitter` + `pkg/metricspath.Paths` exist and are unit-tested; each owns only its necessary dependency (go-metrics / SDK); `pkg/metrics` remains import-pure (stdlib only — verify it gained no new imports).
2. All 10 plugins' telemetry emit helpers route through `pkg/telemetry`; all 10 `path_metrics.go` route through `pkg/metricspath`. No byte-duplicated emit/query handler bodies remain across plugins.
3. `health_check.go`, `workers.go`, and the `emitMinterMetrics` b.minterSets loop remain per-plugin (only the gauge calls inside `emitMinterMetrics` route through the shared Emitter).
4. Every plugin's existing test suite passes UNCHANGED.
5. Two new modules wired into go.work + Makefile + both CI loops; whole workspace `go build` / `go test -race` / `make lint` / `make smoke-test` green; all 20 modules 0 lint; no new `//nolint`.
6. Audit #7 marked `[RESOLVED 2026-06-01]`, recording that health_check.go/workers.go were verified-distinct (audit's "byte-identical" claim corrected) and deliberately not touched.

## Out of scope

health_check/workers convergence; any envelope or metric-name change; OCI reconcile (untouched); the deferred upstream-contribution work (precluded by the AI-authorship ban).

## New-module checklist (×2: pkg/telemetry, pkg/metricspath)

- `go.mod` per module (module paths `…/pkg/telemetry`, `…/pkg/metricspath`), added to `go.work`.
- Added to Makefile `LINT_DIRS` and the CI lint + govulncheck per-module loops in `.github/workflows/ci.yml`.
- `pkg/telemetry` requires `hashicorp/go-metrics`; `pkg/metricspath` requires the OpenBao SDK + `pkg/metrics` (require + replace per the existing per-module convention, resolved via go.work).
