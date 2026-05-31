# Audit Fixes (batch 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land four small, independent audit fixes: #6 worker error visibility + panic recovery, #8 cloudconfig validator tests, #9 targeted concurrency tests, #10 CI gates (fix dead lint step, add hard-fail govulncheck, upload coverage).

**Architecture:** #6 adds an optional error handler + panic recovery to the shared `pkg/worker.Manager`, with each plugin passing a log+metric closure. #8/#9 are test-only additions. #10 edits the CI workflow. The large refactors (#5, #7) are NOT in this batch.

**Tech Stack:** Go 1.26.1, OpenBao SDK v2.5.1, `github.com/hashicorp/go-metrics`, golangci-lint v2, GitHub Actions. Reference: `docs/superpowers/specs/2026-05-31-audit-fixes-batch2-design.md`, `docs/audit-2026-05-31.md`.

**Worktree note:** all work happens on the feature branch in the worktree. Subagents MUST `cd` to the worktree path at the start of every bash call and confirm `git branch --show-current` before committing — prior batches saw edits leak into the main checkout via cwd drift.

---

## Task 1: pkg/worker — error handler + panic recovery (#6, shared)

**Files:**
- Modify: `pkg/worker/worker.go`
- Modify: `pkg/worker/worker_test.go`

- [ ] **Step 1: Write failing tests**

Add to `pkg/worker/worker_test.go`:
```go
func TestWorker_ErrorHandlerInvokedOnError(t *testing.T) {
	var mu sync.Mutex
	var gotName string
	var gotErr error
	h := func(name string, err error) {
		mu.Lock()
		gotName, gotErr = name, err
		mu.Unlock()
	}
	m := worker.New(worker.WithErrorHandler(h))
	m.Register("failer", 5*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		return fmt.Errorf("boom")
	})
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	cancel()
	m.Wait()
	mu.Lock()
	defer mu.Unlock()
	if gotName != "failer" {
		t.Fatalf("expected handler called with worker name failer, got %q", gotName)
	}
	if gotErr == nil || gotErr.Error() != "boom" {
		t.Fatalf("expected boom error, got %v", gotErr)
	}
}

func TestWorker_PanicRecoveredAndReported(t *testing.T) {
	var mu sync.Mutex
	var calls int
	var lastErr error
	h := func(name string, err error) {
		mu.Lock()
		calls++
		lastErr = err
		mu.Unlock()
	}
	m := worker.New(worker.WithErrorHandler(h))
	m.Register("panicker", 5*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		panic("kaboom")
	})
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	time.Sleep(30 * time.Millisecond) // would crash the process if not recovered
	cancel()
	m.Wait()
	mu.Lock()
	defer mu.Unlock()
	if calls == 0 {
		t.Fatal("expected panic to be reported via handler")
	}
	if lastErr == nil || !strings.Contains(lastErr.Error(), "panicked") {
		t.Fatalf("expected panicked error, got %v", lastErr)
	}
}

func TestWorker_NilHandlerStillRecoversPanic(t *testing.T) {
	// No handler set: a panicking worker must not crash the manager; other
	// workers keep ticking and Wait() returns cleanly.
	var ticks int32
	m := worker.New() // no error handler
	m.Register("panicker", 5*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		panic("kaboom")
	})
	m.Register("counter", 5*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		atomic.AddInt32(&ticks, 1)
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	time.Sleep(40 * time.Millisecond)
	cancel()
	m.Wait()
	if atomic.LoadInt32(&ticks) == 0 {
		t.Fatal("counter worker should keep ticking despite sibling panic")
	}
}
```
Add imports to the test file as needed: `"fmt"`, `"strings"`, `"sync"`, `"sync/atomic"` (some may already be present — check).

- [ ] **Step 2: Run, confirm fail**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT> && go test ./pkg/worker/... -run 'TestWorker_ErrorHandler|TestWorker_Panic|TestWorker_NilHandler' 2>&1 | tail
```
Expected: compile failure — `worker.WithErrorHandler` undefined. (And without recovery, the panic test would crash the test binary — that's why the fix is needed.)

- [ ] **Step 3: Implement in pkg/worker/worker.go**

Add `"fmt"` to imports. Add the types/option, an `errHandler` field, the variadic `New`, and the `invoke` wrapper; route errors in `run`:
```go
// ErrorHandler is called when a worker tick returns an error or panics.
type ErrorHandler func(worker string, err error)

// Option configures a Manager.
type Option func(*Manager)

// WithErrorHandler sets the handler invoked on a worker error or recovered panic.
func WithErrorHandler(h ErrorHandler) Option {
	return func(m *Manager) { m.errHandler = h }
}
```
Add to the `Manager` struct: `errHandler ErrorHandler`. Change `New`:
```go
func New(opts ...Option) *Manager {
	m := &Manager{}
	for _, opt := range opts {
		opt(m)
	}
	return m
}
```
Add the recovering invoker and use it in `run`:
```go
func (m *Manager) invoke(ctx context.Context, w registration) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("worker %q panicked: %v", w.name, r)
		}
	}()
	return w.fn(ctx)
}
```
Replace the `case <-ticker.C: _ = w.fn(ctx)` body in `run` with:
```go
		case <-ticker.C:
			if err := m.invoke(ctx, w); err != nil && m.errHandler != nil {
				m.errHandler(w.name, err)
			}
```

- [ ] **Step 4: Run, confirm pass (with -race)**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT> && go test ./pkg/worker/... -race 2>&1 | tail
```
Expected: all worker tests pass (new + existing race-regression test).

- [ ] **Step 5: gofmt + lint + commit**

```bash
cd <WT>/pkg/worker && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...
cd <WT> && git add pkg/worker/ && git commit -m "feat(worker): error handler + panic recovery for periodic workers (audit #6)"
```

---

## Task 2: wire the worker error handler into all 10 plugins (#6)

Each plugin constructs `worker.New()` in its `workers.go` `startWorkers`. Change it to pass a log+metric handler, defined in the plugin's `telemetry.go`. Mechanical, per-plugin.

**Files (×10):**
- Modify: `plugins/credential-<cloud>/telemetry.go` (add `workerErrorHandler`)
- Modify: `plugins/credential-<cloud>/workers.go` (pass it to `worker.New`)

- [ ] **Step 1: Add the handler constructor to each plugin's telemetry.go**

For each cloud (do, upcloud, exoscale, aws, gcp, ovh, azure, vultr, akamai, oci), add to `telemetry.go` (the file already imports `github.com/hashicorp/go-metrics` and the backend has `b.Logger()`):
```go
// workerErrorHandler logs and counts background-worker errors and recovered panics.
func (b *backend) workerErrorHandler() worker.ErrorHandler {
	return func(name string, err error) {
		b.Logger().Warn("worker error", "worker", name, "error", err)
		metrics.IncrCounterWithLabels([]string{"cloud_creds", "worker_errors_total"}, 1,
			[]metrics.Label{
				{Name: "cloud", Value: "<cloud>"},
				{Name: "worker", Value: name},
			})
	}
}
```
Replace `<cloud>` with the plugin's cloud string (e.g. `"do"`, `"aws"`). Add the import `"github.com/nicois/openbao-cloud-creds/pkg/worker"` to telemetry.go (it may not be imported there yet).

- [ ] **Step 2: Pass the handler in each plugin's workers.go**

In `startWorkers`, change `wm := worker.New()` to:
```go
	wm := worker.New(worker.WithErrorHandler(b.workerErrorHandler()))
```

- [ ] **Step 3: Build + test each plugin**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT>
for p in do upcloud exoscale aws gcp ovh azure vultr akamai oci; do
  (cd plugins/credential-$p && gofmt -w . && go test ./... -race >/dev/null 2>&1 && echo "$p ok" || echo "$p FAIL")
done
```
Expected: all `ok`.

- [ ] **Step 4: Lint each touched plugin**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT>
export PATH="$(go env GOPATH)/bin:$PATH"
for p in do upcloud exoscale aws gcp ovh azure vultr akamai oci; do
  (cd plugins/credential-$p && golangci-lint run ./... >/dev/null 2>&1 && echo "$p lint ok" || echo "$p LINT FAIL")
done
```
Expected: all `lint ok`.

- [ ] **Step 5: Commit**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT>
git add plugins/
git commit -m "feat: wire worker error handler (log + worker_errors_total metric) into all plugins (audit #6)"
```

---

## Task 3: cloudconfig validator tests (#8)

**Files:**
- Create: `pkg/cloudconfig/validation_test.go`

- [ ] **Step 1: Write the tests**

`pkg/cloudconfig/validation_test.go`:
```go
package cloudconfig_test

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

func TestValidateSetName(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty", "", true},
		{"simple", "default", false},
		{"dashed", "set-1", false},
		{"underscored", "a_b", false},
		{"alnum", "Set123", false},
		{"slash", "a/b", true},
		{"traversal", "../evil", true},
		{"space", "a b", true},
		{"dot", "a.b", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cloudconfig.ValidateSetName(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
		})
	}
}

func TestValidateRole(t *testing.T) {
	valid := &cloudconfig.Role{Name: "r", Cloud: "do", DefaultTTL: 15 * time.Minute, MaxTTL: time.Hour}
	if err := cloudconfig.ValidateRole(valid); err != nil {
		t.Fatalf("valid role rejected: %v", err)
	}
	cases := []struct {
		name string
		r    *cloudconfig.Role
	}{
		{"empty name", &cloudconfig.Role{Name: "", DefaultTTL: time.Minute, MaxTTL: time.Hour}},
		{"zero default_ttl", &cloudconfig.Role{Name: "r", DefaultTTL: 0, MaxTTL: time.Hour}},
		{"zero max_ttl", &cloudconfig.Role{Name: "r", DefaultTTL: time.Minute, MaxTTL: 0}},
		{"default gt max", &cloudconfig.Role{Name: "r", DefaultTTL: 2 * time.Hour, MaxTTL: time.Hour}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := cloudconfig.ValidateRole(tc.r); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	c := cloudconfig.DefaultConfig("do")
	if c.Cloud != "do" {
		t.Fatalf("cloud: got %q", c.Cloud)
	}
	if c.FlushInterval != 15*time.Minute {
		t.Fatalf("flush: got %v", c.FlushInterval)
	}
	if c.ReconcileCadence != 6*time.Hour {
		t.Fatalf("reconcile: got %v", c.ReconcileCadence)
	}
	if c.BootstrapDelay != 24*time.Hour {
		t.Fatalf("bootstrap: got %v", c.BootstrapDelay)
	}
	if c.MaxDeletesPerPass != 10 {
		t.Fatalf("maxdeletes: got %d", c.MaxDeletesPerPass)
	}
}
```
NOTE: verify the actual field names/signatures by reading `pkg/cloudconfig/config.go`, `role.go`, `minter.go` first — `Role` field names (`Name`, `Cloud`, `DefaultTTL`, `MaxTTL`), `DefaultConfig` return fields, and `ValidateSetName`/`ValidateRole` signatures must match exactly. Adjust the test literals to the real struct.

- [ ] **Step 2: Run**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT> && go test ./pkg/cloudconfig/... -v 2>&1 | tail -25
```
Expected: all pass.

- [ ] **Step 3: Confirm coverage rose**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT> && go test ./pkg/cloudconfig/... -cover 2>&1 | tail -2
```
Expected: coverage materially above the prior 55.6% (the three 0%-covered functions are now exercised).

- [ ] **Step 4: gofmt + lint + commit**

```bash
cd <WT>/pkg/cloudconfig && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...
cd <WT> && git add pkg/cloudconfig/ && git commit -m "test(cloudconfig): cover ValidateSetName, ValidateRole, DefaultConfig (audit #8)"
```

---

## Task 4: targeted concurrency tests (#9)

**Files:**
- Modify: `pkg/recovery/state_test.go`
- Create: `plugins/credential-do/concurrency_test.go`

- [ ] **Step 1: Add the recovery state-machine concurrency test**

Add to `pkg/recovery/state_test.go` (check imports: needs `"sync"`, `"testing"`, `"time"`):
```go
func TestStateMachine_ConcurrentAccess(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold:   30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})
	now := time.Now()
	const goroutines = 50
	const iters = 200
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				switch (g + i) % 5 {
				case 0:
					sm.RecordError(500, now)
				case 1:
					sm.RecordSuccess(now)
				case 2:
					_ = sm.State()
				case 3:
					_ = sm.ConsecutiveFailures()
				case 4:
					_ = sm.NeedsHealthCheck(now)
				}
			}
		}(g)
	}
	wg.Wait()
	// Reaching here under -race with no panic is the assertion.
}
```

- [ ] **Step 2: Add the DO issue-during-worker-activity concurrency test**

First read `plugins/credential-do/path_creds_test.go` to confirm the configured-backend helper (`setupConfiguredBackend(t, srv.URL)`) and `fakes.NewDOServer()`. The test drives all contention through the EXPORTED `HandleRequest` surface — do NOT try to call unexported backend methods (`healthCheckWorker`/`emitMinterMetrics`) from the external `_test` package; they aren't reachable. Both goroutine groups hit `b.mu`-guarded state via `HandleRequest`: issuers via `creds/test-role`, the second group via the `metrics/entity/...` merge path (which takes the tracker lock). Create `plugins/credential-do/concurrency_test.go`:
```go
package credentialdo_test

import (
	"context"
	"sync"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestConcurrent_IssueDuringWorkerActivity(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL)

	ctx := context.Background()
	var wg sync.WaitGroup

	// Issuers: exercise the credential-issuance hot path under b.mu.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				resp, err := b.HandleRequest(ctx, &logical.Request{
					Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
				})
				// Don't fail on transient fake states; -race detects the race regardless.
				_, _ = resp, err
			}
		}()
	}

	// Concurrent metrics-merge reads: also take b.mu / the tracker lock.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				_, _ = b.HandleRequest(ctx, &logical.Request{
					Operation: logical.ReadOperation,
					Path:      "metrics/entity/default/minter-1",
					Storage:   storage,
				})
			}
		}()
	}
	wg.Wait()
}
```

- [ ] **Step 3: Run both under -race**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT>
go test ./pkg/recovery/... -run TestStateMachine_ConcurrentAccess -race -count=3 2>&1 | tail -3
go test ./plugins/credential-do/... -run TestConcurrent_IssueDuringWorkerActivity -race -count=3 2>&1 | tail -3
```
Expected: PASS, no `DATA RACE`. If a real race surfaces in production code, STOP and report it (that's a finding, not a test bug — do not paper over it).

- [ ] **Step 4: gofmt + lint + commit**

```bash
cd <WT> && gofmt -w pkg/recovery/ plugins/credential-do/
export PATH="$(go env GOPATH)/bin:$PATH"
(cd <WT>/pkg/recovery && golangci-lint run ./...) && (cd <WT>/plugins/credential-do && golangci-lint run ./...)
cd <WT> && git add pkg/recovery/ plugins/credential-do/
git commit -m "test: concurrency stress for recovery state machine and DO hot path (audit #9)"
```

---

## Task 5: CI gates — fix dead lint step, govulncheck, coverage upload (#10)

**Files:**
- Modify: `.github/workflows/ci.yml`
- Possibly modify: various `go.mod` (if govulncheck surfaces fixable vulns)

- [ ] **Step 1: Run govulncheck locally first to surface the baseline**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT>
go install golang.org/x/vuln/cmd/govulncheck@latest
export PATH="$(go env GOPATH)/bin:$PATH"
for d in pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/worker pkg/plugintest \
         plugins/credential-do plugins/credential-aws plugins/credential-azure plugins/credential-gcp \
         plugins/credential-ovh plugins/credential-upcloud plugins/credential-exoscale plugins/credential-vultr \
         plugins/credential-akamai plugins/credential-oci; do
  echo "=== $d ==="; (cd $d && govulncheck ./... 2>&1 | tail -20)
done
```
Record every reported vulnerability (govulncheck reports only *reachable* vulns).

- [ ] **Step 2: Resolve findings by bumping deps**

For each reported vuln, in the affected module: `go get -u <module>@<fixed-version>` (or `go get <module>@latest`), then `go mod tidy`, re-run `govulncheck ./...` in that module to confirm it clears, and re-run that module's tests (`go test ./... -race`). If a finding has NO fixed version available, STOP and report it (per the "bump to fix, report unfixable" decision) — do not suppress. Commit the dep bumps:
```bash
cd <WT> && git add <changed go.mod/go.sum files> && git commit -m "chore: bump dependencies to clear govulncheck findings (audit #10)"
```
(If govulncheck reports nothing, skip this step and note "clean baseline".)

- [ ] **Step 3: Fix the dead lint action step in ci.yml**

The current workflow has an `Install golangci-lint` step using `golangci/golangci-lint-action@v7` with `args: --help` (runs `--help`, lints nothing) followed by a manual per-module `Lint` loop that does the real work. Make the action install-only and leave the loop as the linter. Replace the install step's `args` so it doesn't run a bogus command — simplest correct form:
```yaml
      - name: Install golangci-lint
        uses: golangci/golangci-lint-action@v7
        with:
          version: latest
          install-mode: binary
          args: version
```
(`args: version` makes the action print the version instead of running `--help` or a real lint with no target; the actual linting remains the per-module `Lint` loop step.) If `golangci-lint-action@v7` errors on `args: version`, instead drop the action step entirely and prepend the install to the `Lint` step:
```yaml
      - name: Lint
        run: |
          curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b "$(go env GOPATH)/bin" latest
          export PATH="$(go env GOPATH)/bin:$PATH"
          for dir in pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/worker pkg/plugintest \
                     plugins/credential-akamai plugins/credential-aws plugins/credential-azure \
                     plugins/credential-do plugins/credential-exoscale plugins/credential-gcp \
                     plugins/credential-oci plugins/credential-ovh plugins/credential-upcloud \
                     plugins/credential-vultr; do
            echo "=== Linting $dir ==="
            (cd "$dir" && golangci-lint run ./...)
          done
```
Pick whichever is cleaner; the requirement is: no step that runs golangci-lint with `--help`, and the per-module loop is the actual lint. Also add `pkg/plugintest` to the lint loop if it's currently missing (it was added in a prior batch).

- [ ] **Step 4: Add the govulncheck job to ci.yml**

Add a new job:
```yaml
  govulncheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version: '1.26'
      - name: Install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - name: Run govulncheck (per module)
        run: |
          export PATH="$(go env GOPATH)/bin:$PATH"
          for dir in pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/worker pkg/plugintest \
                     plugins/credential-akamai plugins/credential-aws plugins/credential-azure \
                     plugins/credential-do plugins/credential-exoscale plugins/credential-gcp \
                     plugins/credential-oci plugins/credential-ovh plugins/credential-upcloud \
                     plugins/credential-vultr; do
            echo "=== govulncheck $dir ==="
            (cd "$dir" && govulncheck ./...)
          done
```
This hard-fails the pipeline on any reachable vuln (no `|| true`, no `continue-on-error`).

- [ ] **Step 5: Add coverage upload to the test job**

The test step already runs `go test -race -coverprofile=coverage.out ...`. After it, add:
```yaml
      - name: Upload coverage
        uses: actions/upload-artifact@v4
        with:
          name: coverage
          path: coverage.out
          if-no-files-found: warn
```

- [ ] **Step 6: Validate the workflow YAML**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT>
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('CI YAML valid')"
```
Expected: `CI YAML valid`.

- [ ] **Step 7: Commit**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT>
git add .github/workflows/ci.yml
git commit -m "ci: fix dead lint step, add hard-fail govulncheck, upload coverage (audit #10)"
```

---

## Task 6: full verification + audit doc update

**Files:**
- Modify: `docs/audit-2026-05-31.md`

- [ ] **Step 1: Whole-workspace race test**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT>
go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | grep -E "^(ok|FAIL)"
```
Expected: all `ok`, no `FAIL`.

- [ ] **Step 2: Lint + smoke + govulncheck locally**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT>
export PATH="$(go env GOPATH)/bin:$PATH"
make lint
make smoke-test
for d in pkg/worker pkg/cloudconfig plugins/credential-do; do (cd $d && govulncheck ./... >/dev/null 2>&1 && echo "$d vuln-clean" || echo "$d VULN"); done
```
Expected: 0 lint issues; 10 plugins register; vuln-clean (or the reported-unfixable noted in Task 5).

- [ ] **Step 3: Mark #6/#8/#9/#10 resolved in docs/audit-2026-05-31.md**

Prefix the headings of items 6, 8, 9, 10 with `[RESOLVED 2026-05-31]` and add a one-line resolution under each:
- #6 → `worker.WithErrorHandler` + panic recovery; per-plugin log + `cloud_creds_worker_errors_total`. Tests in pkg/worker.
- #8 → table tests for ValidateSetName/ValidateRole/DefaultConfig; coverage raised.
- #9 → concurrency stress tests in pkg/recovery and credential-do under -race.
- #10 → dead lint step fixed; hard-fail govulncheck job; coverage.out uploaded.
Leave #5 and #7 open (deferred).

- [ ] **Step 4: Commit**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/<WT>
git add docs/audit-2026-05-31.md
git commit -m "docs: mark audit items #6, #8, #9, #10 resolved"
```

---

## Summary of files

```
pkg/worker/worker.go              (#6 ErrorHandler option + invoke/recover) + worker_test.go
plugins/credential-<cloud>/
├── telemetry.go                  (#6 workerErrorHandler — ×10)
└── workers.go                    (#6 pass handler to worker.New — ×10)
pkg/cloudconfig/validation_test.go (#8 NEW)
pkg/recovery/state_test.go        (#9 concurrency test)
plugins/credential-do/concurrency_test.go (#9 NEW)
.github/workflows/ci.yml          (#10 lint fix + govulncheck job + coverage upload)
<various go.mod/go.sum>           (#10 dep bumps if govulncheck finds fixable vulns)
docs/audit-2026-05-31.md          (mark #6/#8/#9/#10 resolved)
```
`<WT>` = the feature worktree path; subagents confirm the branch before committing.
```
```
