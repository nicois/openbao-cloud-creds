# Cross-Plugin Telemetry De-duplication (Audit #7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the byte-duplicated telemetry emit helpers into a shared `pkg/telemetry.Emitter`, and the byte-duplicated metrics query endpoint into a shared `pkg/metricspath.Paths`, across all 10 plugins — preserving per-plugin module isolation and behavior.

**Architecture:** Two new focused packages — `pkg/telemetry` (owns the `hashicorp/go-metrics` dependency; an `Emitter` value type carrying cloud identity) and `pkg/metricspath` (owns the OpenBao SDK dependency + imports `pkg/metrics`; a `Paths` constructor for the two metrics handlers). `pkg/metrics` stays import-pure. Each plugin's `telemetry.go`/`path_metrics.go` collapse to thin delegations. `health_check.go`/`workers.go`/`emitMinterMetrics`'s loop stay per-plugin.

**Tech Stack:** Go 1.26.1 workspace, `github.com/hashicorp/go-metrics` v0.5.4 (package name `metrics`), OpenBao SDK v2 (`framework`/`logical`), golangci-lint v2.12.2.

**Reference spec:** `docs/superpowers/specs/2026-06-01-telemetry-dedup-design.md`

---

## How to work this plan

- **Worktree:** all work on one branch (created by the execution skill). Never touch the parent checkout `/home/claude-aiven-2/code/openbao-cloud-creds`. Confirm `git branch --show-current` before each commit. Commit messages end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **CRITICAL (learned this session):** edit ONLY files under the worktree path. The worktree's `go.work` uses relative `use` paths, so editing the parent checkout silently has no effect on worktree tests.
- **Build/test (full module path):** `go build github.com/nicois/openbao-cloud-creds/...` ; `go test -race github.com/nicois/openbao-cloud-creds/...`
- **Per-module lint:** `export PATH="$(go env GOPATH)/bin:$PATH"; (cd <module> && golangci-lint run ./...)`
- **`go.work` IS a worktree file to edit** (the worktree's copy) when adding the two new modules.
- **Important fact (verified):** the per-plugin consts `cloudName`, `metricNamespace`, `fieldCloud`, `fieldRole`, `fieldMinterSet` are used widely across each plugin (path_roles/path_config/path_creds), NOT only in telemetry. They do NOT become dead after extraction — do not remove them. Only the *label-key string values* (`"cloud"`, `"role"`, `"minter_set"`, `"worker"`, `"cred_id"`, `"state"`) get hardcoded inside `pkg/telemetry`.
- Trust live code over plan line numbers; read before editing.

---

## Task 1: Create `pkg/telemetry.Emitter`

**Files:**
- Create: `pkg/telemetry/go.mod`, `pkg/telemetry/telemetry.go`, `pkg/telemetry/telemetry_test.go`
- Modify: `go.work` (worktree copy)

- [ ] **Step 1: Create the module + wire into go.work**

```bash
cd <WORKTREE>
mkdir -p pkg/telemetry
cat > pkg/telemetry/go.mod <<'EOF'
module github.com/nicois/openbao-cloud-creds/pkg/telemetry

go 1.26.1
EOF
```
Add `./pkg/telemetry` to the worktree `go.work` `use (...)` block in alpha order (the pkg group is cloudconfig, credenvelope, localexpiry, metrics, plugintest, reconciler, recovery, worker — `telemetry` goes after `recovery`, before `worker`). Read go.work first to match formatting.

- [ ] **Step 2: Write the failing test**

`pkg/telemetry/telemetry_test.go` — use go-metrics' in-memory sink to capture emitted samples:
```go
package telemetry_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	gometrics "github.com/hashicorp/go-metrics"

	"github.com/nicois/openbao-cloud-creds/pkg/telemetry"
)

// newCapturingSink installs a fresh in-memory metrics sink as the global sink
// and returns it for inspection.
func newCapturingSink(t *testing.T) *gometrics.InmemSink {
	t.Helper()
	sink := gometrics.NewInmemSink(time.Minute, time.Minute)
	cfg := gometrics.DefaultConfig("test")
	cfg.EnableHostname = false
	if _, err := gometrics.NewGlobal(cfg, sink); err != nil {
		t.Fatalf("install sink: %v", err)
	}
	return sink
}

func TestEmitter_Counter(t *testing.T) {
	sink := newCapturingSink(t)
	e := telemetry.Emitter{Cloud: "do", Namespace: "cloud_creds"}
	e.LeaseIssued("role-a")

	data := sink.Data()
	if len(data) == 0 {
		t.Fatal("no metrics captured")
	}
	found := false
	for _, iv := range data {
		for name, sample := range iv.Counters {
			if strings.Contains(name, "cloud_creds.lease_issued_total") {
				found = true
				assertLabel(t, sample.Labels, "cloud", "do")
				assertLabel(t, sample.Labels, "role", "role-a")
			}
		}
	}
	if !found {
		t.Fatalf("lease_issued_total counter not found in %v", data)
	}
}

func TestEmitter_Gauge(t *testing.T) {
	sink := newCapturingSink(t)
	e := telemetry.Emitter{Cloud: "aws", Namespace: "cloud_creds"}
	e.OrphansFound(3)

	found := false
	for _, iv := range sink.Data() {
		for name, sample := range iv.Gauges {
			if strings.Contains(name, "cloud_creds.orphans_found") {
				found = true
				if sample.Value != 3 {
					t.Fatalf("orphans_found: want 3, got %v", sample.Value)
				}
				assertLabel(t, sample.Labels, "cloud", "aws")
			}
		}
	}
	if !found {
		t.Fatal("orphans_found gauge not found")
	}
}

func TestEmitter_WorkerError(t *testing.T) {
	sink := newCapturingSink(t)
	e := telemetry.Emitter{Cloud: "oci", Namespace: "cloud_creds"}
	e.WorkerError("rotation", errors.New("boom"))

	found := false
	for _, iv := range sink.Data() {
		for name, sample := range iv.Counters {
			if strings.Contains(name, "cloud_creds.worker_errors_total") {
				found = true
				assertLabel(t, sample.Labels, "cloud", "oci")
				assertLabel(t, sample.Labels, "worker", "rotation")
			}
		}
	}
	if !found {
		t.Fatal("worker_errors_total counter not found")
	}
}

func assertLabel(t *testing.T, labels []gometrics.Label, name, val string) {
	t.Helper()
	for _, l := range labels {
		if l.Name == name {
			if l.Value != val {
				t.Fatalf("label %q: want %q, got %q", name, val, l.Value)
			}
			return
		}
	}
	t.Fatalf("label %q not present in %v", name, labels)
}
```

- [ ] **Step 3: Run, confirm fail**

```bash
cd <WORKTREE>
go test github.com/nicois/openbao-cloud-creds/pkg/telemetry/... 2>&1 | tail -6
```
Expected: build failure (no telemetry.go / no Emitter).

- [ ] **Step 4: Implement `pkg/telemetry/telemetry.go`**

```go
// Package telemetry emits cloud-creds metrics for the credential plugins,
// centralizing the per-plugin emit helpers that were previously duplicated.
// The label KEYS are fixed by the response-envelope contract (identical across
// all clouds); only the cloud VALUE and metric namespace vary, carried on the
// Emitter.
package telemetry

import (
	metrics "github.com/hashicorp/go-metrics"
)

// Metric label keys, fixed across all plugins by the envelope contract.
const (
	labelCloud     = "cloud"
	labelRole      = "role"
	labelMinterSet = "minter_set"
	labelWorker    = "worker"
)

// Emitter emits metrics for one plugin, carrying its cloud identity and the
// metric-key namespace. The zero value is unusable; set both fields.
type Emitter struct {
	Cloud     string // value of the "cloud" label, e.g. "do"
	Namespace string // leading metric-key segment, e.g. "cloud_creds"
}

// Gauge sets a gauge <namespace>.<name> with the given labels (the caller's
// labels are emitted as-is; use CloudLabel/etc. helpers if you need the
// standard keys).
func (e Emitter) Gauge(name string, val float32, labels []metrics.Label) {
	metrics.SetGaugeWithLabels([]string{e.Namespace, name}, val, labels)
}

// Counter increments a counter <namespace>.<name> by 1 with the given labels.
func (e Emitter) Counter(name string, labels []metrics.Label) {
	metrics.IncrCounterWithLabels([]string{e.Namespace, name}, 1, labels)
}

// CloudLabel returns the standard {cloud=<e.Cloud>} label, for building label
// slices in plugin code (e.g. emitMinterMetrics).
func (e Emitter) CloudLabel() metrics.Label {
	return metrics.Label{Name: labelCloud, Value: e.Cloud}
}

// LeaseIssued counts a credential issuance for the given role.
func (e Emitter) LeaseIssued(role string) {
	e.Counter("lease_issued_total", []metrics.Label{
		{Name: labelCloud, Value: e.Cloud},
		{Name: labelRole, Value: role},
	})
}

// LeaseRevokeFailed counts a failed lease revocation for the given role.
func (e Emitter) LeaseRevokeFailed(role string) {
	e.Counter("lease_revoke_failures_total", []metrics.Label{
		{Name: labelCloud, Value: e.Cloud},
		{Name: labelRole, Value: role},
	})
}

// OrphansFound records the orphan count from a reconcile pass.
func (e Emitter) OrphansFound(count int) {
	e.Gauge("orphans_found", float32(count), []metrics.Label{
		{Name: labelCloud, Value: e.Cloud},
	})
}

// WorkerError counts a periodic-worker error or recovered panic.
func (e Emitter) WorkerError(worker string, err error) {
	_ = err // counted, not labeled (cardinality); callers log the error text.
	e.Counter("worker_errors_total", []metrics.Label{
		{Name: labelCloud, Value: e.Cloud},
		{Name: labelWorker, Value: worker},
	})
}
```
Note: `labelMinterSet` is exported-via-`CloudLabel`? No — `emitMinterMetrics` builds its own label slice with `minter_set`/`cred_id`/`state` keys. To let plugins keep using the literal-free style, ALSO add small exported label-key helpers OR just let `emitMinterMetrics` use literal strings `"minter_set"`,`"cred_id"`,`"state"` (those are local to that one loop). Simplest: keep `labelMinterSet` unexported here (used by nothing external yet) — actually REMOVE `labelMinterSet`/`labelWorker` from the const block if unused after writing, to satisfy the `unused` linter. Keep only the keys the Emitter methods actually reference (`labelCloud`, `labelRole`, `labelWorker`). Verify with lint in Step 6.

- [ ] **Step 5: tidy + run green**

```bash
cd <WORKTREE>
(cd pkg/telemetry && go mod tidy && go test -race ./... 2>&1 | tail -8)
```
Expected: go.mod/go.sum populated with `go-metrics`; 3 tests pass.

- [ ] **Step 6: lint + workspace build + commit**

```bash
cd <WORKTREE>
(cd pkg/telemetry && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
go build github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -3
git add pkg/telemetry/ go.work go.work.sum
git commit -m "$(printf 'feat(telemetry): shared Emitter for plugin metrics (audit #7)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```
If lint flags an unused label const, remove it (keep only what the methods use). 0 issues required.

---

## Task 2: Route `credential-do` telemetry through `pkg/telemetry` (reference)

DO is the reference; Tasks 3–11 replicate for the other 9.

**Files:**
- Modify: `plugins/credential-do/telemetry.go`, `plugins/credential-do/go.mod`

- [ ] **Step 1: Read the current telemetry.go + confirm the existing tests**

```bash
cd <WORKTREE>
cat plugins/credential-do/telemetry.go
grep -rln 'emitLeaseIssued\|emitOrphansFound\|workerErrorHandler\|emitMinterMetrics\|TestMetrics' plugins/credential-do/*_test.go
```
Note which existing tests exercise telemetry/metrics (they are the behavior-preservation guard — must pass unchanged).

- [ ] **Step 2: Rewrite telemetry.go to delegate to the Emitter**

Replace `plugins/credential-do/telemetry.go` with (keeping the same exported/package surface the rest of the plugin calls — `emitLeaseIssued(role)`, `emitLeaseRevokeFailed(role)`, `emitOrphansFound(count)`, `b.emitMinterMetrics()`, `b.workerErrorHandler()`):
```go
package credentialdo

import (
	"time"

	metrics "github.com/hashicorp/go-metrics"

	"github.com/nicois/openbao-cloud-creds/pkg/telemetry"
	"github.com/nicois/openbao-cloud-creds/pkg/worker"
)

// emit is this plugin's shared metrics emitter (cloud identity + namespace).
var emit = telemetry.Emitter{Cloud: cloudName, Namespace: metricNamespace}

func emitLeaseIssued(role string)       { emit.LeaseIssued(role) }
func emitLeaseRevokeFailed(role string) { emit.LeaseRevokeFailed(role) }
func emitOrphansFound(count int)        { emit.OrphansFound(count) }

// emitMinterMetrics stays here: it reaches into b.minterSets / state machines.
func (b *backend) emitMinterMetrics() {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	for setName, states := range b.minterSets {
		for id, ms := range states {
			labels := []metrics.Label{
				emit.CloudLabel(),
				{Name: fieldMinterSet, Value: setName},
				{Name: "cred_id", Value: id},
			}

			state := string(ms.sm.State())
			emit.Gauge("upstream_state", 1, append(labels, metrics.Label{Name: "state", Value: state}))
			emit.Gauge("upstream_consecutive_failures", float32(ms.sm.ConsecutiveFailures()), labels)

			lastSuccess := ms.sm.LastSuccessAt()
			if !lastSuccess.IsZero() {
				emit.Gauge("upstream_last_success_seconds_ago", float32(now.Sub(lastSuccess).Seconds()), labels)
			}

			if !ms.minter.ExpiresAt.IsZero() {
				expiresIn := ms.minter.ExpiresAt.Sub(now).Seconds()
				emit.Gauge("upstream_expires_in_seconds", float32(expiresIn), labels)
			}
		}
	}
}

func (b *backend) workerErrorHandler() worker.ErrorHandler {
	return func(name string, err error) {
		b.Logger().Warn("worker error", "worker", name, "error", err)
		emit.WorkerError(name, err)
	}
}
```
Notes: the old `emitGauge`/`emitCounter` package funcs are GONE (replaced by `emit.*`). If anything ELSE in the DO plugin called `emitCounter`/`emitGauge` directly (grep: `grep -rn 'emitCounter\|emitGauge' plugins/credential-do/*.go | grep -v telemetry.go`), update those call sites to `emit.Counter`/`emit.Gauge`. `fieldMinterSet` is still defined in consts.go (used elsewhere) — keep using it for the minter_set label. `metrics` import is still needed (for the `[]metrics.Label` in emitMinterMetrics).

- [ ] **Step 3: add the module require + build**

```bash
cd <WORKTREE>
(cd plugins/credential-do && go mod tidy 2>&1 | tail -3)
go build github.com/nicois/openbao-cloud-creds/plugins/credential-do/... 2>&1 | tail -3
```
`go mod tidy` may fail on the network (pkg/plugintest is go.work-only — a known pre-existing condition). If tidy fails, manually add to `plugins/credential-do/go.mod` a `require github.com/nicois/openbao-cloud-creds/pkg/telemetry v0.0.0` + `replace github.com/nicois/openbao-cloud-creds/pkg/telemetry => ../../pkg/telemetry`, matching the convention already used for the other pkg deps in that go.mod (check how pkg/worker is required there — mirror exactly). The build via go.work is the real check.

- [ ] **Step 4: existing tests pass UNCHANGED**

```bash
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-do/... 2>&1 | tail -12
```
Expected: all DO tests pass with NO test-file edits. If a test fails, the delegation changed observable behavior — fix the delegation, not the test. (Metrics emit to the global sink; existing tests likely don't assert on metric samples, only on the response/storage behavior — so they should be unaffected.)

- [ ] **Step 5: lint + commit**

```bash
cd <WORKTREE>
(cd plugins/credential-do && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add plugins/credential-do/
git commit -m "$(printf 'refactor(do): route telemetry through pkg/telemetry (audit #7)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Tasks 3–11: Route the other 9 plugins' telemetry through `pkg/telemetry`

Each of aws, azure, gcp, oci, ovh, upcloud, exoscale, vultr, akamai gets the **exact Task 2 treatment** in its `telemetry.go` + go.mod. Per plugin:

1. `cat plugins/credential-<p>/telemetry.go` — confirm its emit set.
2. Rewrite telemetry.go to the delegation form (Task 2 Step 2), adapted:
   - **No-revoke plugins (aws, gcp, ovh):** OMIT `emitLeaseRevokeFailed` (they don't define it — verified: aws's set is emitGauge/emitCounter/emitMinterMetrics/emitLeaseIssued/emitOrphansFound/workerErrorHandler). Only define the wrappers that plugin actually had.
   - **oci:** its telemetry.go is the lone 3rd cluster — `cat` it; it likely has the same emit set plus possibly an extra metric. Replicate whatever emit functions it defines, each delegating to `emit.*`. If oci emits a metric with no Emitter method, use `emit.Gauge`/`emit.Counter` directly with the literal name + labels (don't add a one-off Emitter method for a single caller).
   - Keep each plugin's `emitMinterMetrics` per-plugin, rewired to `emit.Gauge`/`emit.CloudLabel()` as in Task 2.
   - Update any direct `emitCounter`/`emitGauge` call sites elsewhere in that plugin to `emit.Counter`/`emit.Gauge` (grep per plugin).
3. go.mod: add the telemetry require+replace (mirror the plugin's existing pkg-dep convention; build via go.work is the check).
4. `go build` + `go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-<p>/...` green (existing tests UNCHANGED).
5. gofmt + lint that plugin; commit `refactor(<p>): route telemetry through pkg/telemetry (audit #7)`.

Do them one at a time (one commit each). After all 9:
```bash
cd <WORKTREE>
go build github.com/nicois/openbao-cloud-creds/... && go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | grep -E 'FAIL|ok ' | tail -20
```

> **Per-plugin note:** the consts `cloudName`/`metricNamespace`/`fieldMinterSet` stay (used widely). Do NOT remove them. The only thing removed is the local `emitGauge`/`emitCounter`/`emitLeaseIssued`/etc. function *bodies* (now `emit.*`).

---

## Task 12: Create `pkg/metricspath.Paths`

**Files:**
- Create: `pkg/metricspath/go.mod`, `pkg/metricspath/metricspath.go`, `pkg/metricspath/metricspath_test.go`
- Modify: `go.work` (worktree copy)

- [ ] **Step 1: Create the module + go.work**

```bash
cd <WORKTREE>
mkdir -p pkg/metricspath
cat > pkg/metricspath/go.mod <<'EOF'
module github.com/nicois/openbao-cloud-creds/pkg/metricspath

go 1.26.1
EOF
```
Add `./pkg/metricspath` to the worktree go.work `use (...)` block in alpha position (after `./pkg/metrics`, before `./pkg/plugintest`).

- [ ] **Step 2: Write the failing test**

`pkg/metricspath/metricspath_test.go`:
```go
package metricspath_test

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
	"github.com/nicois/openbao-cloud-creds/pkg/metricspath"
)

func trackerWith(t *testing.T, entity, role string, at time.Time) *metrics.AccessTracker {
	t.Helper()
	tr := metrics.NewAccessTracker("node-1", metrics.NewInMemoryStore())
	tr.RecordAccess(entity, role, at)
	return tr
}

// findPath returns the framework.Path whose Pattern contains substr.
func findPath(t *testing.T, paths []*framework.Path, substr string) *framework.Path {
	t.Helper()
	for _, p := range paths {
		if strings.Contains(p.Pattern, substr) {
			return p
		}
	}
	t.Fatalf("no path matching %q", substr)
	return nil
}

func TestPaths_EntityReturnsMergedFields(t *testing.T) {
	now := time.Now()
	tr := trackerWith(t, "ent-1", "role-a", now)
	paths := metricspath.Paths(func() *metrics.AccessTracker { return tr }, 604800)

	p := findPath(t, paths, "metrics/entity/")
	resp, err := p.Operations[logical.ReadOperation].Handler()(context.Background(),
		&logical.Request{}, &framework.FieldData{
			Raw:    map[string]interface{}{"entity_id": "ent-1"},
			Schema: p.Fields,
		})
	if err != nil {
		t.Fatalf("entity read: %v", err)
	}
	if resp == nil || resp.Data["access_count"] == nil {
		t.Fatalf("expected access_count in %v", resp)
	}
}

func TestPaths_EntityUnknownReturnsNil(t *testing.T) {
	tr := metrics.NewAccessTracker("node-1", metrics.NewInMemoryStore())
	paths := metricspath.Paths(func() *metrics.AccessTracker { return tr }, 604800)
	p := findPath(t, paths, "metrics/entity/")
	resp, err := p.Operations[logical.ReadOperation].Handler()(context.Background(),
		&logical.Request{}, &framework.FieldData{
			Raw:    map[string]interface{}{"entity_id": "nope"},
			Schema: p.Fields,
		})
	if err != nil {
		t.Fatalf("entity read: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil resp for unknown entity, got %v", resp)
	}
}

func TestPaths_NilTrackerErrors(t *testing.T) {
	paths := metricspath.Paths(func() *metrics.AccessTracker { return nil }, 604800)
	p := findPath(t, paths, "metrics/entity/")
	resp, err := p.Operations[logical.ReadOperation].Handler()(context.Background(),
		&logical.Request{}, &framework.FieldData{
			Raw:    map[string]interface{}{"entity_id": "x"},
			Schema: p.Fields,
		})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response for nil tracker, got %v", resp)
	}
}

func TestPaths_StaleReturnsList(t *testing.T) {
	now := time.Now()
	tr := metrics.NewAccessTracker("node-1", metrics.NewInMemoryStore())
	tr.RecordAccess("old-ent", "role-a", now.Add(-10*24*time.Hour))
	paths := metricspath.Paths(func() *metrics.AccessTracker { return tr }, 604800)
	p := findPath(t, paths, "metrics/stale")
	resp, err := p.Operations[logical.ListOperation].Handler()(context.Background(),
		&logical.Request{}, &framework.FieldData{
			Raw:    map[string]interface{}{"older_than": 604800},
			Schema: p.Fields,
		})
	if err != nil {
		t.Fatalf("stale list: %v", err)
	}
	if resp == nil {
		t.Fatal("expected stale list response")
	}
}
```
(Add `"strings"` to the import block — `findPath` uses it.)

- [ ] **Step 3: Run, confirm fail**

```bash
cd <WORKTREE>
go test github.com/nicois/openbao-cloud-creds/pkg/metricspath/... 2>&1 | tail -6
```
Expected: build failure (no metricspath.go / no Paths).

- [ ] **Step 4: Implement `pkg/metricspath/metricspath.go`**

Move the two handlers + path defs verbatim from a plugin's `path_metrics.go` (read `plugins/credential-aws/path_metrics.go` — the 7-identical rep), parameterized by the tracker accessor:
```go
// Package metricspath provides the shared per-node access-metrics query
// endpoints (metrics/entity, metrics/stale) used by every credential plugin.
// It is backed by a metrics.AccessTracker supplied via an accessor closure so
// the plugin retains its own lock discipline.
package metricspath

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
)

// Paths returns the metrics/entity and metrics/stale framework paths backed by
// the AccessTracker the accessor returns (the accessor is responsible for any
// locking). staleDefaultSeconds is the schema default for the stale window.
func Paths(accessor func() *metrics.AccessTracker, staleDefaultSeconds int) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "metrics/entity/" + framework.MatchAllRegex("entity_id"),
			Fields: map[string]*framework.FieldSchema{
				"entity_id": {
					Type:        framework.TypeString,
					Description: "Cloud entity ID to query",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: entityHandler(accessor)},
			},
		},
		{
			Pattern: "metrics/stale$",
			Fields: map[string]*framework.FieldSchema{
				"older_than": {
					Type:        framework.TypeDurationSecond,
					Default:     staleDefaultSeconds,
					Description: "Return entities not accessed within this duration",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: staleHandler(accessor)},
			},
		},
	}
}

func entityHandler(accessor func() *metrics.AccessTracker) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		tracker := accessor()
		if tracker == nil {
			return logical.ErrorResponse("metrics not initialized"), nil
		}
		entityID := d.Get("entity_id").(string)
		merged, err := tracker.MergeEntity(ctx, entityID, time.Now())
		if err != nil {
			return logical.ErrorResponse("metrics query failed: %v", err), nil
		}
		if merged.AccessCount == 0 {
			return nil, nil
		}
		return &logical.Response{
			Data: map[string]interface{}{
				"last_access_at":    merged.LastAccessAt.UTC().Format(time.RFC3339),
				"access_count":      merged.AccessCount,
				"staleness_seconds": merged.StalenessSeconds,
				"source":            merged.Source,
			},
		}, nil
	}
}

func staleHandler(accessor func() *metrics.AccessTracker) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		tracker := accessor()
		if tracker == nil {
			return logical.ErrorResponse("metrics not initialized"), nil
		}
		olderThan := time.Duration(d.Get("older_than").(int)) * time.Second
		stale, err := tracker.ListStaleEntities(ctx, olderThan, time.Now())
		if err != nil {
			return logical.ErrorResponse("stale query failed: %v", err), nil
		}
		return logical.ListResponse(stale), nil
	}
}
```
Confirm the response keys/patterns EXACTLY match the original `path_metrics.go` (they're verbatim above; cross-check against aws's file). Confirm `merged.Source` is a real field on `MergedEntry` (read `pkg/metrics/access.go` — adjust if the field name differs).

- [ ] **Step 5: tidy + run green**

```bash
cd <WORKTREE>
(cd pkg/metricspath && go mod tidy && go test -race ./... 2>&1 | tail -10)
```

- [ ] **Step 6: lint + build + commit**

```bash
cd <WORKTREE>
(cd pkg/metricspath && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
go build github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -3
git add pkg/metricspath/ go.work go.work.sum
git commit -m "$(printf 'feat(metricspath): shared metrics query endpoints (audit #7)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 13: Route `credential-do` path_metrics through `pkg/metricspath` (reference)

**Files:**
- Modify: `plugins/credential-do/path_metrics.go`, `plugins/credential-do/go.mod`

- [ ] **Step 1: read the current file + how b exposes the tracker**

```bash
cd <WORKTREE>
cat plugins/credential-do/path_metrics.go
grep -n 'accessTracker' plugins/credential-do/*.go | grep -v _test | head
```
Confirm `b.accessTracker` field + `b.mu` guard the access (the handler reads it under RLock).

- [ ] **Step 2: collapse path_metrics.go to the delegation**

Replace `plugins/credential-do/path_metrics.go` with (keep the `metricsPaths()` method name + the `defaultStaleAfterSeconds` const if defined here — confirm where it lives; if it's in this file, keep it):
```go
package credentialdo

import (
	"github.com/openbao/openbao/sdk/v2/framework"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
	"github.com/nicois/openbao-cloud-creds/pkg/metricspath"
)

func (b *backend) metricsPaths() []*framework.Path {
	return metricspath.Paths(func() *metrics.AccessTracker {
		b.mu.RLock()
		defer b.mu.RUnlock()
		return b.accessTracker
	}, defaultStaleAfterSeconds)
}
```
If `defaultStaleAfterSeconds` was defined in path_metrics.go, move it to consts.go (or keep it in this file — it's still referenced here). Confirm `b.accessTracker` is the real field name + type `*metrics.AccessTracker` (grep). Remove the now-unused imports (`context`, `time`, `logical`) — gofmt/goimports.

- [ ] **Step 3: build + tests UNCHANGED**

```bash
cd <WORKTREE>
(cd plugins/credential-do && go mod tidy 2>&1 | tail -2)  # or manual require+replace for pkg/metricspath
go build github.com/nicois/openbao-cloud-creds/plugins/credential-do/... 2>&1 | tail -3
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-do/... 2>&1 | tail -12
```
The existing `TestMetricsEntityEndpoint` (or equivalent) MUST pass unchanged — it's the behavior guard.

- [ ] **Step 4: lint + commit**

```bash
cd <WORKTREE>
(cd plugins/credential-do && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add plugins/credential-do/
git commit -m "$(printf 'refactor(do): route path_metrics through pkg/metricspath (audit #7)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Tasks 14–22: Route the other 9 plugins' path_metrics through `pkg/metricspath`

Each of aws, azure, gcp, oci, ovh, upcloud, exoscale, vultr, akamai gets the **exact Task 13 treatment**. Per plugin:
1. `cat plugins/credential-<p>/path_metrics.go` — confirm the stale-default const name (9 use `defaultStaleAfterSeconds`; akamai uses `defaultStaleOlderThanSeconds`) and that handlers are the standard pair.
2. Collapse to the `metricsPaths()` delegation (Task 13 Step 2), passing that plugin's stale-default const.
3. go.mod: add the metricspath require+replace (mirror convention; build via go.work is the check).
4. `go build` + `go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-<p>/...` green (existing metrics test UNCHANGED).
5. gofmt + lint; commit `refactor(<p>): route path_metrics through pkg/metricspath (audit #7)`.

One commit each. After all 9, full workspace build + test.

> **Note:** if any plugin's path_metrics.go has a NON-standard handler (e.g. an extra field or different response key), the normalized-hash clustering said only exoscale/akamai differed and ONLY in the const name — so all 10 handlers are behaviorally identical. If you find a real handler difference, STOP and report (don't force it).

---

## Task 23: Wire new modules into CI + Makefile; full verification + mark audit #7 resolved

**Files:** `Makefile`, `.github/workflows/ci.yml`, `docs/audit-2026-05-31.md`

- [ ] **Step 1: Add both modules to Makefile LINT_DIRS + both CI loops**

In `Makefile`, add `pkg/telemetry pkg/metricspath` to the `LINT_DIRS` pkg list. In `.github/workflows/ci.yml`, add both to the Lint loop AND the govulncheck loop (match formatting/continuation).

- [ ] **Step 2: confirm wiring**

```bash
cd <WORKTREE>
grep -c 'pkg/telemetry' Makefile .github/workflows/ci.yml      # Makefile 1, ci.yml 2
grep -c 'pkg/metricspath' Makefile .github/workflows/ci.yml    # Makefile 1, ci.yml 2
python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/ci.yml')); print('jobs:', list(d['jobs'].keys()))"
```

- [ ] **Step 3: full-workspace verification gate**

```bash
cd <WORKTREE>
export PATH="$(go env GOPATH)/bin:$PATH"
go build github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -3; echo "build: $?"
go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -30
fail=0
for d in pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/worker pkg/plugintest pkg/localexpiry pkg/telemetry pkg/metricspath \
         plugins/credential-akamai plugins/credential-aws plugins/credential-azure plugins/credential-do \
         plugins/credential-exoscale plugins/credential-gcp plugins/credential-oci plugins/credential-ovh \
         plugins/credential-upcloud plugins/credential-vultr; do
  (cd "$d" && golangci-lint run ./... 2>&1 | grep -q '0 issues') || { echo "LINT FAIL $d"; fail=1; }
done
[ $fail -eq 0 ] && echo "ALL 20 MODULES CLEAN"
make lint 2>&1 | tail -3; echo "make lint: $?"
make smoke-test 2>&1 | tail -4
```
Expected: build OK, all tests pass, ALL 20 MODULES CLEAN, make lint exit 0, smoke green.

- [ ] **Step 4: verify pkg/metrics stayed pure**

```bash
cd <WORKTREE>
grep -E 'go-metrics|openbao/sdk|framework|logical' pkg/metrics/*.go | grep -v _test && echo "WARN: pkg/metrics gained a dep (should be pure)" || echo "pkg/metrics still pure (stdlib only)"
```
Expected: still pure.

- [ ] **Step 5: confirm no byte-duplicated emit/query bodies remain**

```bash
cd <WORKTREE>
# telemetry.go files should now be thin delegations (no local SetGaugeWithLabels/IncrCounterWithLabels)
grep -rl 'SetGaugeWithLabels\|IncrCounterWithLabels' plugins/*/telemetry.go && echo "WARN: a plugin still calls go-metrics directly" || echo "no direct go-metrics calls in plugin telemetry"
# path_metrics.go files should be one-method delegations (no MergeEntity/ListStaleEntities)
grep -rl 'MergeEntity\|ListStaleEntities' plugins/*/path_metrics.go && echo "WARN: a plugin still has the inline query" || echo "no inline metrics query in plugins"
```

- [ ] **Step 6: mark audit #7 resolved**

In `docs/audit-2026-05-31.md`, add `— [RESOLVED 2026-06-01]` to the `## 7.` heading + a `**Resolved:**` paragraph: emit helpers → `pkg/telemetry.Emitter`, metrics query → `pkg/metricspath.Paths`, both as new focused packages (NOT pkg/metrics, which was verified pure and kept so). Record that `health_check.go` (all 10 verified-distinct — audit's "identical" claim was stale) and `workers.go` (mostly per-plugin) were deliberately NOT touched, and `emitMinterMetrics` stays per-plugin (b.minterSets-coupled) with only its gauge calls routed through the shared Emitter.

- [ ] **Step 7: no stray nolint; commit**

```bash
cd <WORKTREE>
git diff main..HEAD | grep -nE '^\+.*nolint' || echo "no nolint added"
git add Makefile .github/workflows/ci.yml docs/audit-2026-05-31.md
git commit -m "$(printf 'ci+docs: wire pkg/telemetry + pkg/metricspath; mark audit #7 resolved\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
git log --oneline main..HEAD
```

---

## Self-review notes (for the executor)

- **Task ordering:** Task 1 (pkg/telemetry) before Tasks 2–11 (consumers). Task 12 (pkg/metricspath) before Tasks 13–22 (consumers). Task 23 last (CI wiring needs both modules to exist). Telemetry and metricspath are independent — could interleave, but do telemetry fully then metricspath for clarity.
- **Behavior preservation is the bar for every plugin task:** existing tests pass UNCHANGED. If a test needs editing, the delegation diverged — fix the code.
- **Consts are NOT dead:** `cloudName`/`metricNamespace`/`fieldCloud`/`fieldRole`/`fieldMinterSet` are used across each plugin (path_roles/config/creds), not just telemetry. Do not remove them. (Spec's "dead const" caveat was over-cautious — verified they stay live.)
- **New modules (×2) MUST be wired** into go.work (done in Tasks 1/12), Makefile + both CI loops (Task 23) — the recurring gap caught for plugintest/localexpiry.
- **pkg/metrics must stay pure** — Task 23 Step 4 verifies. If the implementer accidentally put Emitter or Paths in pkg/metrics, that's wrong per the spec.
- **No new nolint** (the project's record). If lint forces a choice, restructure rather than suppress (the localexpiry/audit-#5 lesson).
- Trust live code over plan line numbers; read before editing.
