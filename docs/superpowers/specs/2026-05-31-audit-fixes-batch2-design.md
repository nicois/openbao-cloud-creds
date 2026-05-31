# Audit Fixes (batch 2) — Design Spec

**Status:** Approved (2026-05-31)
**Scope:** The four small/independent audit items: #6 (worker error visibility + panic recovery), #8 (cloudconfig validator tests), #9 (targeted concurrency tests), #10 (CI gates). The two large refactors — #5 (reconciler convergence) and #7 (cross-plugin de-dup) — are deferred to a separate, dedicated effort.

These four are mutually independent; order doesn't matter for correctness.

## Fix #6 — worker error visibility + panic recovery (`pkg/worker` + 10 plugins)

**Bug (verified):** `pkg/worker/Manager.run()` does `_ = w.fn(ctx)` — every periodic worker's error is discarded (no log, no metric), and there is no `recover()`, so a worker goroutine panic crashes the whole plugin process. A persistently failing reconciler/flush is invisible.

**Fix:**
- Add a functional-option constructor to `pkg/worker` so the existing no-arg call sites can opt in without a breaking signature change:
  ```go
  type ErrorHandler func(worker string, err error)
  type Option func(*Manager)
  func WithErrorHandler(h ErrorHandler) Option
  func New(opts ...Option) *Manager   // New() still valid (no handler → errors still swallowed, but now also recovered)
  ```
- In `run()`, wrap each tick so a panic becomes an error and both real errors and recovered panics reach the handler:
  ```go
  func (m *Manager) invoke(ctx context.Context, w registration) (err error) {
      defer func() {
          if r := recover(); r != nil {
              err = fmt.Errorf("worker %q panicked: %v", w.name, r)
          }
      }()
      return w.fn(ctx)
  }
  // in run()'s ticker loop:
  if err := m.invoke(ctx, w); err != nil && m.errHandler != nil {
      m.errHandler(w.name, err)
  }
  ```
  (If `errHandler` is nil, a recovered panic is still contained — the worker keeps ticking — but not reported. Plugins will always set it.)
- Each plugin's `startWorkers` constructs the Manager with a handler closure that logs and counts:
  ```go
  wm := worker.New(worker.WithErrorHandler(func(name string, err error) {
      b.Logger().Warn("worker error", "worker", name, "error", err)
      metrics.IncrCounterWithLabels([]string{"cloud_creds", "worker_errors_total"}, 1,
          []metrics.Label{{Name: "cloud", Value: "<cloud>"}, {Name: "worker", Value: name}})
  }))
  ```
  Put the closure construction in each plugin's `telemetry.go` (e.g. `func (b *backend) workerErrorHandler() worker.ErrorHandler`) so `workers.go` just calls `worker.New(worker.WithErrorHandler(b.workerErrorHandler()))`. Uses the existing `github.com/hashicorp/go-metrics` import.

**Touch:** `pkg/worker/worker.go` (the logic), and each plugin's `workers.go` + `telemetry.go` (mechanical: build + pass the handler). 10 plugins.

**Tests:** in `pkg/worker/worker_test.go`: (a) a worker returning an error invokes the handler with the worker name + error; (b) a worker that panics is recovered, reported via the handler, and the manager keeps running (other workers still tick, Stop still drains). Existing race-regression test stays.

## Fix #8 — cloudconfig validator tests (`pkg/cloudconfig`, test-only)

**Gap (verified):** `pkg/cloudconfig` coverage 55.6%; `ValidateSetName`, `ValidateRole`, `DefaultConfig` at 0%. These are config-load gatekeepers (RSK-005).

**Fix:** table tests (new `pkg/cloudconfig/validation_test.go` or append to `config_test.go`):
- `ValidateSetName`: empty → error; `"default"`, `"set-1"`, `"a_b"` → ok; `"../evil"`, `"a/b"`, `"a b"`, `"a.b"` → error (per the `^[a-zA-Z0-9_-]+$` regex).
- `ValidateRole`: empty `Name` → error; `DefaultTTL <= 0` → error; `MaxTTL <= 0` → error; `DefaultTTL > MaxTTL` → error; a fully-valid role → nil.
- `DefaultConfig("do")`: assert `Cloud=="do"`, `FlushInterval==15*time.Minute`, `ReconcileCadence==6*time.Hour`, `BootstrapDelay==24*time.Hour`, `MaxDeletesPerPass==10`.

No production change.

## Fix #9 — targeted concurrency tests

**Gap (verified):** no test runs plugin/state-machine logic concurrently, so the `-race` CI is dormant against the real hot path.

**Fix (targeted, not ×10):**
- `pkg/recovery/state_test.go` — `TestStateMachine_ConcurrentAccess`: one `StateMachine`; 50 goroutines × N iterations each calling a mix of `RecordError(500, now)`, `RecordSuccess(now)`, `State()`, `ConsecutiveFailures()`, `NeedsHealthCheck(now)`; `WaitGroup` join. Pass = no race/panic. (Uses a fixed `now := time.Now()`.)
- `plugins/credential-do/concurrency_test.go` (new) — `TestConcurrent_IssueDuringWorkerActivity`: configure the backend (reuse `setupConfiguredBackend` with a DO fake); run a `WaitGroup` of goroutines: several issuing `creds/test-role`, plus one repeatedly invoking the `b.mu`-guarded paths a worker would (`b.healthCheckWorker(ctx)` and/or read-path issuance) for a fixed duration/iteration count; join. Pass = no race. This exercises the shared `b.mu` backend pattern (identical across all 10 plugins via the DO template), so DO is representative.

Both run under existing `go test -race`. No production change.

## Fix #10 — CI gates (`.github/workflows/ci.yml`)

**Gaps (verified):** the `golangci-lint-action@v7` step uses `args: --help` (installs then runs `--help` — dead; the real lint is the manual per-module loop). `coverage.out` is produced but never uploaded. No `govulncheck`.

**Fix:**
1. **Dead lint step:** change the action step to install-only (drop `args: --help`) — keep the existing per-module lint loop as the actual linter. (The action @v7 supports an install without running; if `args` is required, use a no-op that doesn't run a bogus command — simplest: remove the action step entirely and install golangci-lint in the loop step, OR keep the action purely for the binary install. Implementer picks the cleanest that leaves the per-module loop as the sole linter.)
2. **govulncheck (hard-fail):** new CI step/job: `go install golang.org/x/vuln/cmd/govulncheck@latest`, then run `govulncheck ./...` in EACH module (same loop as lint, since govulncheck doesn't span `go.work`). **Hard-fail** on findings. Resolve any reported (reachable) vulnerability by bumping the affected dependency (`go get -u <mod>` / bump the SDK in the relevant `go.mod`); if a finding has no fixed version available, report it for a decision (do not silently suppress). Run govulncheck locally during implementation first to surface and fix the baseline so the gate goes green.
3. **Coverage upload:** the existing test step already writes `coverage.out`; add `actions/upload-artifact@v4` to upload it. No external service, no hard threshold — visibility only.

## Out of scope (this batch)

#5 (reconciler convergence) and #7 (cross-plugin de-dup) — deferred to a dedicated refactor effort with its own design (the no-upstream-delete `pkg/reconciler` extension is a real design question).

## Testing / success criteria

1. `pkg/worker`: error-handler invoked on worker error AND on recovered panic; manager survives a panicking worker.
2. `pkg/cloudconfig`: the three validators + DefaultConfig have direct tests; coverage rises materially above 55.6%.
3. `pkg/recovery` + `credential-do`: concurrency tests pass under `-race`.
4. CI: lint loop is the sole linter (no dead `--help` step); `govulncheck` runs per-module and the pipeline is green (baseline vulns fixed by dep bumps, or reported); `coverage.out` uploaded as an artifact.
5. Whole workspace: `go test -race` green, `make lint` clean, `make smoke-test` green.
