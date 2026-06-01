# Audit-2 Effort 4a: Minter Observability (#9 part 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make stale long-lived minter credentials observable: emit a `minter_age_seconds` gauge for every minter (including `never_expires`), and warn-log when an expiring minter is within a configurable threshold of expiry.

**Architecture:** Add `MinterExpiryWarn` to the shared `cloudconfig.PluginConfig` (JSON-persisted, so reload rehydration via the existing `loadConfig` is automatic). Each of the 10 plugins gains a `minter_expiry_warn` config field and extends its existing `emitMinterMetrics` (called on the health-check cadence) with an unconditional age gauge + the warn-log.

**Tech Stack:** Go 1.26.1 workspace; OpenBao SDK v2.5.1 (`framework.TypeDurationSecond`); hashicorp/go-metrics (gauge sink); hashicorp/go-hclog (warn-log); golangci-lint v2.12.2.

**Spec:** `docs/superpowers/specs/2026-06-01-audit2-minter-observability-design.md`

**CRITICAL EXECUTION CONSTRAINTS (these bit prior efforts):**
- Work ONLY in the effort's worktree. Prefix every bash call with `cd <worktree> && ...` and READ each file (absolute worktree path) immediately before editing it — bash cwd resets between calls; stray edits have landed in the main checkout before.
- ZERO new `//nolint`. If an internal test introduces a repeated string literal that trips `goconst` package-wide, hoist it to a `const`.
- Lint MUST use the v2 binary at `/home/claude-aiven-2/code/qualcheck/bin/golangci-lint` (PATH `golangci-lint` is v1 and fails on the v2 config). Run `<v2> cache clean` before linting.
- Full module path for go commands: `github.com/nicois/openbao-cloud-creds/...` (NOT `./...`).
- After each task, verify the main checkout is clean: `git -C /home/claude-aiven-2/code/openbao-cloud-creds status --short | grep -v '.claude'` returns nothing.

---

## File Structure

- `pkg/cloudconfig/config.go` — add `MinterExpiryWarn time.Duration` field + `DefaultConfig` default (= `MinMinterGap`). One new test in `config_test.go`.
- Each plugin (×10), two files:
  - `path_config.go` — `minter_expiry_warn` field schema (+ `defaultMinterExpiryWarnSeconds` const = 604800), write-parse into `PluginConfig.MinterExpiryWarn`, read-render in the config read response.
  - `telemetry.go` — `emitMinterMetrics`: add the unconditional `minter_age_seconds` gauge; add the warn-log inside the existing `!ExpiresAt.IsZero()` branch, threshold read from `b.config` (fallback `cloudconfig.MinMinterGap`).

Reference plugin: **credential-do**. The other 9 are mechanical replicas (their `emitMinterMetrics` and `path_config.go` `flush_interval` blocks are near-identical — OCI's `emitMinterMetrics` loop is structurally the same, just at different line numbers).

---

## Task 1: `pkg/cloudconfig` — `MinterExpiryWarn` field + default

**Files:**
- Modify: `pkg/cloudconfig/config.go`
- Test: `pkg/cloudconfig/config_test.go` (create if absent, else append)

- [ ] **Step 1: Write the failing test**

Check whether `pkg/cloudconfig/config_test.go` exists (`ls pkg/cloudconfig/`). If it exists, append the function; if not, create it with this content:
```go
package cloudconfig_test

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

func TestDefaultConfig_MinterExpiryWarnDefaultsToMinMinterGap(t *testing.T) {
	cfg := cloudconfig.DefaultConfig("do")
	if cfg.MinterExpiryWarn != cloudconfig.MinMinterGap {
		t.Fatalf("MinterExpiryWarn = %v, want MinMinterGap (%v)", cfg.MinterExpiryWarn, cloudconfig.MinMinterGap)
	}
}
```
(If the package already has a `package cloudconfig_test` test file, just add the function there and skip the imports that already exist.)

- [ ] **Step 2: Run it to verify it fails**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/pkg/cloudconfig/ -run TestDefaultConfig_MinterExpiryWarn 2>&1 | tail`
Expected: FAIL — `cfg.MinterExpiryWarn undefined` (compile error).

- [ ] **Step 3: Implement** — edit `pkg/cloudconfig/config.go`

Add the field to `PluginConfig` (after `MaxDeletesPerPass`):
```go
	MaxDeletesPerPass int           `json:"max_deletes_per_pass"`
	MinterExpiryWarn  time.Duration `json:"minter_expiry_warn"`
```
And set the default in `DefaultConfig` (after `MaxDeletesPerPass: defaultMaxDeletesPerPass,`):
```go
		MaxDeletesPerPass: defaultMaxDeletesPerPass,
		MinterExpiryWarn:  MinMinterGap,
```
(`MinMinterGap` is already defined in `pkg/cloudconfig/minter.go:10` = `7 * 24 * time.Hour`; `time` is already imported in config.go.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/pkg/cloudconfig/ 2>&1 | tail`
Expected: PASS (ok), all pre-existing cloudconfig tests still green.

- [ ] **Step 5: Lint**

```bash
cd <worktree>
/home/claude-aiven-2/code/qualcheck/bin/golangci-lint cache clean
(cd pkg/cloudconfig && gofmt -w . && /home/claude-aiven-2/code/qualcheck/bin/golangci-lint run ./... 2>&1 | tail -4); echo "exit ${PIPESTATUS[0]}"
```
Expected: 0 issues.

- [ ] **Step 6: Commit**

```bash
cd <worktree>
git add pkg/cloudconfig/config.go pkg/cloudconfig/config_test.go
git commit -m "$(printf 'feat(cloudconfig): MinterExpiryWarn field, defaults to MinMinterGap (audit2 #9)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2: credential-do — config field + age gauge + warn-log (REFERENCE)

This is the reference implementation. Tasks 3-11 replicate it across the other 9 plugins.

**Files:**
- Modify: `plugins/credential-do/path_config.go` (const block ~13-32; field schema ~38-54; write ~63-73; read ~152-158)
- Modify: `plugins/credential-do/telemetry.go` (`emitMinterMetrics` ~20-48)
- Test: `plugins/credential-do/minter_observability_test.go` (create)

- [ ] **Step 1: Write the failing test** — create `plugins/credential-do/minter_observability_test.go`

This test uses the PROVEN pattern from the existing `plugins/credential-do/cooldown_internal_test.go` (Effort 2): build the backend via `Factory` (NOT a hand-built `backend{}` literal — `recovery.NewStateMachine` takes a `Config` struct, and the in-memory `minterSets` map is populated by the minter-set write path, so go through `HandleRequest`). To capture warn-logs, set a buffer-backed `hclog` logger on `config.Logger` BEFORE calling `Factory` (the framework wires `config.Logger` into `b.Logger()`). `expires_at` IS accepted via the minter-set write path (RFC3339), so near/far expiry is set through the API; `CreatedAt` is set to `time.Now()` at write, so the age gauge is asserted as "small but present" (≥0) rather than backdated.

```go
package credentialdo

import (
	"context"
	"strings"
	"testing"
	"time"

	gometrics "github.com/hashicorp/go-metrics"
	"github.com/hashicorp/go-hclog"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// newObservabilityBackend builds a DO backend via Factory with a buffer-backed
// logger (so warn-logs are assertable) and the given minter-set written through
// the API. minterExpiryWarn is the config threshold in seconds (0 = omit, use default).
func newObservabilityBackend(t *testing.T, minters []interface{}, minterExpiryWarnSecs int) (*backend, *strings.Builder, *gometrics.InmemSink) {
	t.Helper()
	// capturing metrics sink
	sink := gometrics.NewInmemSink(time.Minute, time.Minute)
	mcfg := gometrics.DefaultConfig("test")
	mcfg.EnableHostname = false
	if _, err := gometrics.NewGlobal(mcfg, sink); err != nil {
		t.Fatalf("install sink: %v", err)
	}

	srv := fakes.NewDOServer()
	t.Cleanup(srv.Close)

	logBuf := &strings.Builder{}
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.Logger = hclog.New(&hclog.LoggerOptions{Output: logBuf, Level: hclog.Warn})

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	bk := b.(*backend)
	storage := config.StorageView

	cfgData := map[string]interface{}{"do_api_url": srv.URL}
	if minterExpiryWarnSecs > 0 {
		cfgData["minter_expiry_warn"] = minterExpiryWarnSecs
	}
	if resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage, Data: cfgData,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}

	if resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]interface{}{"minters": minters},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write: err=%v resp=%v", err, resp)
	}
	return bk, logBuf, sink
}

func gaugePresent(sink *gometrics.InmemSink, suffix string) bool {
	for _, iv := range sink.Data() {
		for name := range iv.Gauges {
			if strings.Contains(name, suffix) {
				return true
			}
		}
	}
	return false
}

func TestEmitMinterMetrics_AgeGaugeForNeverExpires(t *testing.T) {
	bk, logBuf, sink := newObservabilityBackend(t, []interface{}{
		map[string]interface{}{"id": "m1", "token": "dop_v1_x", "never_expires": true},
	}, 0)

	bk.emitMinterMetrics()

	if !gaugePresent(sink, "minter_age_seconds") {
		t.Fatalf("minter_age_seconds gauge not emitted for never_expires minter; gauges: %v", sink.Data())
	}
	if strings.Contains(logBuf.String(), "nearing expiry") {
		t.Fatalf("never_expires minter must not warn; log: %s", logBuf.String())
	}
}

func TestEmitMinterMetrics_WarnsWithinThreshold(t *testing.T) {
	// Two minters >=7d apart so the set validates (>=2 expiring, >=7d gap);
	// the nearer one (3d) is within the 7d warn threshold.
	soon := time.Now().Add(3 * 24 * time.Hour).UTC().Format(time.RFC3339)
	later := time.Now().Add(40 * 24 * time.Hour).UTC().Format(time.RFC3339)
	bk, logBuf, _ := newObservabilityBackend(t, []interface{}{
		map[string]interface{}{"id": "m1", "token": "dop_v1_x", "expires_at": soon},
		map[string]interface{}{"id": "m2", "token": "dop_v1_y", "expires_at": later},
	}, 0) // default 7d threshold

	bk.emitMinterMetrics()

	if !strings.Contains(logBuf.String(), "nearing expiry") {
		t.Fatalf("expected 'nearing expiry' warn for minter expiring in 3d; log: %s", logBuf.String())
	}
}

func TestEmitMinterMetrics_NoWarnOutsideThreshold(t *testing.T) {
	// Both minters far out (>7d), so neither is within the default threshold.
	a := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	b := time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339)
	bk, logBuf, _ := newObservabilityBackend(t, []interface{}{
		map[string]interface{}{"id": "m1", "token": "dop_v1_x", "expires_at": a},
		map[string]interface{}{"id": "m2", "token": "dop_v1_y", "expires_at": b},
	}, 0)

	bk.emitMinterMetrics()

	if strings.Contains(logBuf.String(), "nearing expiry") {
		t.Fatalf("minters expiring in 30d/60d must not warn at 7d threshold; log: %s", logBuf.String())
	}
}

func TestConfig_MinterExpiryWarnRoundTrip(t *testing.T) {
	bk, _, _ := newObservabilityBackend(t, []interface{}{
		map[string]interface{}{"id": "m1", "token": "dop_v1_x", "never_expires": true},
	}, 86400) // write 1d

	resp, err := bk.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: bk.testStorage(t),
	})
	_ = resp
	_ = err
	// NOTE: config read needs the same storage the writes used. The helper does
	// not expose it; simplest is to capture `storage` from the helper. The
	// implementer MUST adjust newObservabilityBackend to also return `storage`
	// (logical.Storage) and use it here for the read. Then assert:
	//   got := resp.Data["minter_expiry_warn"]; want 86400 (int seconds).
}
```

**IMPORTANT for the implementer:**
- The `TestConfig_MinterExpiryWarnRoundTrip` sketch above is incomplete on purpose re: storage handle — **adjust `newObservabilityBackend` to ALSO return the `logical.Storage`** (`config.StorageView`) and use it for the config read. Then assert `resp.Data["minter_expiry_warn"]` equals `86400`. Mirror how `cooldown_internal_test.go` and `path_config_test.go` issue read requests. Remove the `testStorage`/placeholder lines — they are pseudo-code.
- This is an INTERNAL test (`package credentialdo`) so it can call `bk.emitMinterMetrics()` directly. The `cooldown_internal_test.go` in this same package already declares `const minterTokenKey = "token"` and uses `"token"` literals — if your new file repeats the `"token"` literal ≥ a few times, reuse that const (it's package-scoped) or you'll trip `goconst`. Check `cooldown_internal_test.go` first.
- Do NOT hand-construct `backend{}` or call `recovery.NewStateMachine` directly — `Factory` + `HandleRequest` populates `minterSets` correctly (its signature is `NewStateMachine(Config)`, not a duration).

- [ ] **Step 2: Run to verify failure**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/plugins/credential-do/ -run 'TestEmitMinterMetrics|TestConfig_MinterExpiryWarn' 2>&1 | tail`
Expected: FAIL — `minter_age_seconds` gauge not found / no "nearing expiry" warn / `minter_expiry_warn` not in read output.

- [ ] **Step 3a: Implement the config field** — edit `plugins/credential-do/path_config.go`

Add the const (in the `const (` block near `defaultFlushIntervalSeconds`):
```go
	// defaultMinterExpiryWarnSeconds is the default near-expiry warn threshold (7d),
	// matching cloudconfig.MinMinterGap.
	defaultMinterExpiryWarnSeconds = 604800 // 7d
```
Add the field schema (after the `reconcile_cadence` field):
```go
				"minter_expiry_warn": {
					Type:        framework.TypeDurationSecond,
					Default:     defaultMinterExpiryWarnSeconds,
					Description: "Warn in logs when an expiring minter is within this many seconds of expiry",
				},
```
In `pathConfigWrite`, parse it and set it on the config:
```go
	flushInterval := time.Duration(d.Get("flush_interval").(int)) * time.Second
	reconcileCadence := time.Duration(d.Get("reconcile_cadence").(int)) * time.Second
	minterExpiryWarn := time.Duration(d.Get("minter_expiry_warn").(int)) * time.Second

	cfg := &cloudconfig.PluginConfig{
		Cloud:             cloudName,
		FlushInterval:     flushInterval,
		ReconcileCadence:  reconcileCadence,
		BootstrapDelay:    reconcilerBootstrapDelay,
		MaxDeletesPerPass: maxDeletesPerPass,
		MinterExpiryWarn:  minterExpiryWarn,
	}
```
In `pathConfigRead`, render it:
```go
			"flush_interval":     int(cfg.FlushInterval.Seconds()),
			"reconcile_cadence":  int(cfg.ReconcileCadence.Seconds()),
			"minter_expiry_warn": int(cfg.MinterExpiryWarn.Seconds()),
```

- [ ] **Step 3b: Implement the telemetry change** — edit `plugins/credential-do/telemetry.go`

In `emitMinterMetrics`, after `labels` is built and before the `upstream_state` gauge (or anywhere inside the per-minter loop after `labels`), add the unconditional age gauge:
```go
				emit.Gauge("minter_age_seconds", float32(now.Sub(ms.minter.CreatedAt).Seconds()), labels)
```
Then change the existing expiry block to add the warn-log:
```go
			if !ms.minter.ExpiresAt.IsZero() {
				expiresIn := ms.minter.ExpiresAt.Sub(now)
				emit.Gauge("upstream_expires_in_seconds", float32(expiresIn.Seconds()), labels)

				warnThreshold := cloudconfig.MinMinterGap
				if b.config != nil && b.config.MinterExpiryWarn > 0 {
					warnThreshold = b.config.MinterExpiryWarn
				}
				if expiresIn > 0 && expiresIn < warnThreshold {
					b.Logger().Warn("minter nearing expiry",
						"cloud", cloudName, "minter_set", setName, "minter_id", id,
						"expires_in_seconds", int(expiresIn.Seconds()),
						"warn_threshold_seconds", int(warnThreshold.Seconds()))
				}
			}
```
Add the `cloudconfig` import to telemetry.go if not present (`"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"`). NOTE: `emitMinterMetrics` already holds `b.mu.RLock()` (it reads `b.minterSets`), so reading `b.config` inside it is lock-safe — confirm the `RLock` is held across the loop (it is; the `defer b.mu.RUnlock()` is at the top).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/plugins/credential-do/ 2>&1 | tail`
Expected: PASS — the 4 new tests + all pre-existing DO tests.

- [ ] **Step 5: Lint**

```bash
cd <worktree>
GL=/home/claude-aiven-2/code/qualcheck/bin/golangci-lint
"$GL" cache clean
(cd plugins/credential-do && gofmt -w . && "$GL" run ./... 2>&1 | tail -4); echo "exit ${PIPESTATUS[0]}"
grep -rn 'nolint' plugins/credential-do/ && echo "NOLINT (bad)" || echo "no nolint"
```
Expected: 0 issues, no nolint.

- [ ] **Step 6: Commit**

```bash
cd <worktree>
git add plugins/credential-do/
git commit -m "$(printf 'feat(do): minter_age_seconds gauge + configurable near-expiry warn (audit2 #9)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Tasks 3-11: replicate across the other 9 plugins

Each of **aws, gcp, azure, ovh, upcloud, exoscale, vultr, akamai, oci** gets the exact Task 2 treatment. These may be done as ONE batch implementer (single git index, sequential per plugin) since they are mechanical replicas with the same shape — OR one task each. The controller decides; if batched, the prompt must still produce one commit per plugin or one combined commit clearly listing all 9.

For EACH plugin `<p>`:

- [ ] **Step A: config field** — in `plugins/credential-<p>/path_config.go`:
  - Add `defaultMinterExpiryWarnSeconds = 604800 // 7d` to the const block.
  - Add the `minter_expiry_warn` field schema (same as Task 2 Step 3a) after that plugin's `reconcile_cadence` (or `flush_interval` if it has no reconcile field — check; all have flush_interval).
  - In that plugin's `pathConfigWrite`, parse `minterExpiryWarn` and set `MinterExpiryWarn:` on the `cloudconfig.PluginConfig{...}` literal.
  - In that plugin's `pathConfigRead`, add `"minter_expiry_warn": int(cfg.MinterExpiryWarn.Seconds()),`.
  - **Caveat:** the `PluginConfig{...}` literal field set varies per plugin (e.g. some pass different fields). READ the plugin's `pathConfigWrite` first and add only the `MinterExpiryWarn:` line; do not disturb the others. If a plugin's `pathConfigWrite` does NOT construct a `cloudconfig.PluginConfig` the same way (e.g. injected-client plugins aws/gcp/oci may differ), adapt: the goal is `cfg.MinterExpiryWarn` is set from the parsed field and persisted.

- [ ] **Step B: telemetry** — in `plugins/credential-<p>/telemetry.go` `emitMinterMetrics`:
  - Add `emit.Gauge("minter_age_seconds", float32(now.Sub(ms.minter.CreatedAt).Seconds()), labels)` (unconditional, in the per-minter loop after `labels`).
  - Add the warn-log inside the existing `if !ms.minter.ExpiresAt.IsZero() {` block (same code as Task 2 Step 3b), reading the threshold from `b.config` with the `cloudconfig.MinMinterGap` fallback.
  - Add the `cloudconfig` import if absent.

- [ ] **Step C: test** — create `plugins/credential-<p>/minter_observability_test.go`:
  - Mirror Task 2's `newObservabilityBackend`/test shape (Factory + HandleRequest, buffer logger via `config.Logger`, capturing metrics sink), adapting per plugin: package name (`package credential<x>`); the **fake server** constructor (`fakes.New<Cloud>Server()` — read the plugin's existing `cooldown_internal_test.go`/`resilience_test.go` for the exact name and the config field that points at it, e.g. `do_api_url` for DO); the **minter token field name + value format** (DO uses `"token": "dop_v1_..."`; others differ — copy from the plugin's existing internal test that writes a minter-set); and the config field the cloud uses for its API URL.
  - At minimum each plugin MUST assert: (1) `minter_age_seconds` emitted for a `never_expires` minter with no warn, (2) a warn fires for a minter within the threshold (use two `expires_at` minters ≥7d apart so the set validates, the nearer within 7d), (3) config round-trip of `minter_expiry_warn`.
  - Use an INTERNAL-package test (`package credential<x>`) so it can call `bk.emitMinterMetrics()` directly. Do NOT hand-construct `backend{}` or call `recovery.NewStateMachine` (signature is `NewStateMachine(Config)`). If a repeated string literal (e.g. the minter token key) trips `goconst`, reuse the package-scoped const the plugin's existing internal test already defines, or hoist a new one. NO `//nolint`.
  - **Injected-client plugins (aws/gcp/oci):** these may not have a fakes HTTP server (they inject a cloud client). Read the plugin's existing internal/resilience test to see how it builds a backend + writes a minter-set without a live server; mirror that. If `emitMinterMetrics` can be exercised by directly populating via the minter-set write path against the injected fake, do so; if the plugin has no internal test precedent, construct the backend via `Factory` and write the minter-set through `HandleRequest` exactly as the JIT plugins do (the minter-set write path does not call the cloud API).

- [ ] **Step D: per-plugin verify + commit**
```bash
cd <worktree>
go test github.com/nicois/openbao-cloud-creds/plugins/credential-<p>/ 2>&1 | tail -5
GL=/home/claude-aiven-2/code/qualcheck/bin/golangci-lint; "$GL" cache clean >/dev/null 2>&1
(cd plugins/credential-<p> && gofmt -w . && "$GL" run ./... 2>&1 | tail -3); echo "exit ${PIPESTATUS[0]}"
git -C /home/claude-aiven-2/code/openbao-cloud-creds status --short | grep -v '.claude' && echo "MAIN DIRTY" || echo "main clean"
git add plugins/credential-<p>/
git commit -m "$(printf 'feat(<p>): minter_age_seconds gauge + configurable near-expiry warn (audit2 #9)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```
Expected: tests pass, 0 lint issues, main clean.

**OCI note:** OCI's `emitMinterMetrics` is structurally identical (same `b.minterSets` loop, `ms.minter`, expiry gate at telemetry.go:60) — the change applies the same way. OCI's `pathConfigWrite` may construct `PluginConfig` differently (it's phased-rotation); read it and set `MinterExpiryWarn` consistently.

---

## Task 12: Full-workspace verification + mark progress

**Files:**
- Modify: `docs/audit-2026-06-01.md` (annotate #9 as partially resolved — observability done, self-rotation = Effort 4b)

- [ ] **Step 1: Full build + race test + lint + smoke**

```bash
cd <worktree>
echo "=== build ===" && go build github.com/nicois/openbao-cloud-creds/... && echo "build OK"
echo "=== race ===" && go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | grep -E 'FAIL|^ok |panic' | tail -22
GL=/home/claude-aiven-2/code/qualcheck/bin/golangci-lint
"$GL" cache clean
fail=0
for d in pkg/cloudconfig pkg/credenvelope pkg/credenvelope/fakes pkg/localexpiry pkg/metrics pkg/metricspath pkg/plugintest pkg/reconciler pkg/recovery pkg/telemetry pkg/worker plugins/credential-akamai plugins/credential-aws plugins/credential-azure plugins/credential-do plugins/credential-exoscale plugins/credential-gcp plugins/credential-oci plugins/credential-ovh plugins/credential-upcloud plugins/credential-vultr; do
  (cd "$d" && "$GL" run ./... >/dev/null 2>&1) && echo "0: $d" || { echo "ISSUES: $d"; fail=1; }
done
echo "lint overall: $([ $fail -eq 0 ] && echo CLEAN || echo ISSUES)"
echo "=== nolint added this effort ===" && git diff main..HEAD | grep -cE '^\+.*nolint'
echo "=== smoke ===" && make smoke-test 2>&1 | tail -4
```
Expected: build OK; all `ok` (no FAIL/panic); lint CLEAN (all 21 dirs); nolint 0; smoke 10/10.
If ANYTHING fails, STOP and report BLOCKED with the exact failure.

- [ ] **Step 2: Annotate #9 in `docs/audit-2026-06-01.md`**

READ the `## 9.` heading. Append ` — [PARTIALLY RESOLVED 2026-06-01]` and insert a bold note under the heading:
> **Partially resolved (Effort 4a — observability):** All 10 plugins now emit `cloud_creds_minter_age_seconds` for EVERY minter (including `never_expires` — closing the "never-expiring minter invisible forever" gap), and warn-log "minter nearing expiry" when an expiring minter is within a configurable `minter_expiry_warn` threshold (per-plugin config field, default 7d = `MinMinterGap`). The pre-existing `upstream_expires_in_seconds` gauge already covered expiring minters. **Remaining (Effort 4b — self-rotation):** actual minter rotation (a `MinterRotator` interface + per-cloud successor-minting + manual/auto rotation) — its own spec/plan; feasible for most clouds but not OVH (OAuth2 grant can't mint successors) and quota-tight for OCI/AWS.

- [ ] **Step 3: Verify main clean, then commit**

```bash
cd <worktree>
git -C /home/claude-aiven-2/code/openbao-cloud-creds status --short | grep -v '.claude' && echo "MAIN DIRTY" || echo "main clean"
git add docs/audit-2026-06-01.md
git commit -m "$(printf 'docs(audit2): mark #9 observability done (Effort 4a); rotation = 4b\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Self-review notes (for the executor)

- **Spec coverage:** Task 1 (PluginConfig field + default), Task 2 (DO reference: config field + age gauge + warn-log), Tasks 3-11 (9 replicas), Task 12 (gate + doc). Covers all three spec success criteria (field round-trip; age gauge for every minter incl never_expires; warn within configurable threshold).
- **Type consistency:** `MinterExpiryWarn time.Duration` (config), `minter_expiry_warn` (field name, seconds), `defaultMinterExpiryWarnSeconds = 604800`, `minter_age_seconds` (gauge), `"minter nearing expiry"` (warn message) — used identically across all tasks.
- **Known hazards:**
  - Build backends via `Factory` + `HandleRequest` (the proven `cooldown_internal_test.go` pattern), NOT a hand-built `backend{}` literal — `recovery.NewStateMachine` takes a `Config` struct (not a duration), and `minterSets` is populated by the minter-set write path. Task 2's test was authored against this reality.
  - Capture warn-logs by setting `config.Logger = hclog.New(... Output: buf ...)` BEFORE `Factory` (the framework wires it into `b.Logger()`). The age gauge is asserted "present" (CreatedAt is `time.Now()` at write, so not backdatable via the API).
  - The metrics sink matcher uses `strings.Contains(name, "minter_age_seconds")` over `sink.Data()[*].Gauges`; `pkg/telemetry/telemetry_test.go` has the canonical `newCapturingSink` shape — mirror it.
  - The `TestConfig_MinterExpiryWarnRoundTrip` sketch needs `newObservabilityBackend` to ALSO return `logical.Storage` for the config read — the implementer completes that (flagged in Task 2's IMPORTANT note).
  - injected-client plugins (aws/gcp/oci) may build `PluginConfig` differently in `pathConfigWrite` AND may lack a fakes HTTP server — read each before editing; only add the `MinterExpiryWarn` line to the config literal, and mirror the plugin's existing internal/resilience test for backend construction.
- **DRY/YAGNI:** the warn-threshold fallback (`MinMinterGap` when config nil/zero) is repeated in each plugin's `emitMinterMetrics` — acceptable (it's 3 lines mirroring the existing per-plugin telemetry structure; not worth a shared helper given the per-plugin module isolation convention).
