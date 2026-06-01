# Audit-2 Effort 2: Upstream Error Handling (#4, #5, #8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Classify upstream errors into the right client-visible `error_code` (#4), stop leaking raw upstream bodies to clients (#5), and add a 429 cool-down so a rate-limited minter is briefly de-selected instead of re-hammered (#8).

**Architecture:** A shared `credenvelope.ClassifyUpstream(status) ErrorCode` + a 429 `cooldownUntil`/`Selectable(now)` in `pkg/recovery`. Per-plugin issue/revoke error sites switch to: log raw err operator-side, return classified-code + generic message. `selectMinter` consults `Selectable(now)`.

**Tech Stack:** Go 1.26.1 workspace, OpenBao SDK v2, golangci-lint v2.12.2.

**Reference spec:** `docs/superpowers/specs/2026-06-01-audit2-upstream-errors-design.md`

---

## How to work this plan

- **Worktree:** one branch (created by the execution skill). Never touch the parent checkout. **Edit ONLY worktree files via absolute worktree paths** — bash cwd resets between calls; prior efforts repeatedly stray-edited the main checkout. After each task verify main is clean.
- **Build/test:** `go build github.com/nicois/openbao-cloud-creds/...` ; `go test -race github.com/nicois/openbao-cloud-creds/...`
- **Per-module lint:** `export PATH="$(go env GOPATH)/bin:$PATH"; (cd <module> && golangci-lint run ./...)`. Note: the v2.12.2 binary may be at `/home/claude-aiven-2/code/qualcheck/bin/golangci-lint` if `golangci-lint` on PATH is v1.
- **No new `//nolint`** (project record). Commit messages end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Trust live code over plan line numbers; read before editing.

**Verified facts (from brainstorming):**
- 9 plugins have the identical issue-error site `return credenvelope.ErrorResponse(credenvelope.ErrInternal, "upstream error: %v", err), nil` (aws:68, exoscale:80, azure:70, gcp:65, do:69, ovh:70, vultr:72, akamai:62, upcloud:68). OCI has NO such JIT mint site (slot-read).
- Status availability splits: **6 plugins** (do, exoscale, azure, vultr, akamai, upcloud) have a bare `httpStatus int` in scope at the site. **3 plugins** (aws, gcp, ovh) compute the status inline as `classify{AWS,GCP,OVH}Error(err)` (passed to recordMinterError) — no standalone `httpStatus` var; the fix must capture it into one.
- `pkg/recovery.RecordError(httpStatus int, at time.Time)` is the cooldown insertion point; `isAuthError(status)` shows the status idiom. selectMinter (all plugins) checks `ms.sm.State() == Healthy || TransientFailing` and does NOT currently take `now`.
- The cloud-fakes have `SetNextStatus(code int)` to force an upstream status (e.g. 429) — used by the #4 per-plugin test.

---

## Task 1: `credenvelope.ClassifyUpstream` (#4 shared classifier)

**Files:**
- Modify: `pkg/credenvelope/errors.go`
- Test: `pkg/credenvelope/errors_test.go` (create if absent)

- [ ] **Step 1: Write the failing table test**

Append to (or create) `pkg/credenvelope/errors_test.go`:
```go
package credenvelope

import (
	"net/http"
	"testing"
)

func TestClassifyUpstream(t *testing.T) {
	cases := []struct {
		status int
		want   ErrorCode
	}{
		{http.StatusTooManyRequests, ErrUpstreamQuotaExceeded}, // 429
		{http.StatusRequestTimeout, ErrUpstreamTimeout},        // 408
		{http.StatusGatewayTimeout, ErrUpstreamTimeout},        // 504
		{http.StatusUnauthorized, ErrUpstreamAuthFailed},       // 401
		{http.StatusForbidden, ErrUpstreamAuthFailed},          // 403
		{http.StatusNotFound, ErrEntityUnavailable},            // 404
		{http.StatusInternalServerError, ErrInternal},          // 500
		{http.StatusBadGateway, ErrInternal},                   // 502
		{http.StatusServiceUnavailable, ErrInternal},           // 503
		{0, ErrInternal},
		{http.StatusOK, ErrInternal}, // 200 shouldn't reach here, but maps safely
	}
	for _, c := range cases {
		if got := ClassifyUpstream(c.status); got != c.want {
			t.Errorf("ClassifyUpstream(%d) = %q, want %q", c.status, got, c.want)
		}
	}
}
```
(Package `credenvelope` internal test — ClassifyUpstream is in the same package.)

- [ ] **Step 2: Run, confirm fail**

```bash
cd <WT>
go test -run TestClassifyUpstream github.com/nicois/openbao-cloud-creds/pkg/credenvelope/ 2>&1 | tail -6
```
Expected: build failure — `undefined: ClassifyUpstream`.

- [ ] **Step 3: Implement**

In `pkg/credenvelope/errors.go` add (ensure `"net/http"` is imported):
```go
// ClassifyUpstream maps an upstream HTTP status to the stable error_code a
// client sees, so callers can distinguish retryable (quota/timeout) from fatal
// (auth/not-found). Unknown and 5xx statuses map to ErrInternal. No new code is
// introduced — adding an error_code is a spec change (see techrfc).
func ClassifyUpstream(httpStatus int) ErrorCode {
	switch httpStatus {
	case http.StatusTooManyRequests:
		return ErrUpstreamQuotaExceeded
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return ErrUpstreamTimeout
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrUpstreamAuthFailed
	case http.StatusNotFound:
		return ErrEntityUnavailable
	default:
		return ErrInternal
	}
}
```

- [ ] **Step 4: Run, confirm pass**

```bash
cd <WT>
go test -race github.com/nicois/openbao-cloud-creds/pkg/credenvelope/... 2>&1 | tail -6
```

- [ ] **Step 5: lint + commit**

```bash
cd <WT>
(cd pkg/credenvelope && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add pkg/credenvelope/
git commit -m "$(printf 'feat(credenvelope): ClassifyUpstream maps HTTP status to error_code (audit2 #4)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2: credential-do — classified code + no body leak (#4/#5 reference)

**Files:**
- Modify: `plugins/credential-do/path_creds.go`
- Test: `plugins/credential-do/path_creds_test.go` (or a new error-classification test file)

DO has a bare `httpStatus` at the issue site (`path_creds.go:64-69`) — the simpler group.

- [ ] **Step 1: Write the failing test**

The DO fake has `SetNextStatus(code)`. Add a test that a forced 429 yields the quota code + no raw body:
```go
// A 429 from upstream surfaces as upstream_quota_exceeded, not internal, and the
// client message does NOT leak the raw upstream body.
func TestCredsIssue_ClassifiesQuotaError(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL)
	srv.SetNextStatus(http.StatusTooManyRequests) // next create returns 429

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response, got %v", resp)
	}
	msg := resp.Error().Error()
	if !strings.HasPrefix(msg, string(credenvelope.ErrUpstreamQuotaExceeded)+":") {
		t.Fatalf("expected upstream_quota_exceeded code, got %q", msg)
	}
	// #5: the raw upstream body / injected error value must NOT leak to the client.
	if strings.Contains(msg, "server_error") || strings.Contains(strings.ToLower(msg), "body") {
		t.Fatalf("client message leaked upstream detail: %q", msg)
	}
}
```
Adapt: confirm `setupConfiguredBackend(t, srv.URL)` is the DO test helper (it is, from path_creds_test.go), the role name (`test-role`), and that the fake's injected-error value/body string is `server_error` or similar — read `pkg/credenvelope/fakes/do.go` SetNextStatus path to see what body it writes, and assert that string is absent from the client message. Import `net/http`, `strings`, `credenvelope`.

- [ ] **Step 2: Run, confirm fail**

```bash
cd <WT>
go test -run TestCredsIssue_ClassifiesQuotaError github.com/nicois/openbao-cloud-creds/plugins/credential-do/ -v 2>&1 | tail -15
```
Expected: FAIL — current code returns `ErrInternal` (not quota), and the message embeds the raw err.

- [ ] **Step 3: Implement at the issue-error site**

In `plugins/credential-do/path_creds.go`, replace (around line 64-69):
```go
	tokenResp, httpStatus, err := client.CreateToken(ctx, tokenName, scopes)
	if err != nil {
		b.recordMinterError(setName, minterID, httpStatus, now)
		// We can't reliably classify ...
		return credenvelope.ErrorResponse(credenvelope.ErrInternal, "upstream error: %v", err), nil
	}
```
with:
```go
	tokenResp, httpStatus, err := client.CreateToken(ctx, tokenName, scopes)
	if err != nil {
		b.recordMinterError(setName, minterID, httpStatus, now)
		b.Logger().Warn("upstream credential issuance failed",
			"cloud", cloudName, "status", httpStatus, "error", err)
		return credenvelope.ErrorResponse(credenvelope.ClassifyUpstream(httpStatus),
			"upstream credential issuance failed"), nil
	}
```
ALSO check the revoke/secondary site in the same file (there's a second `recordMinterError` ~line 154): if it returns an error envelope that interpolates `err`/body to the CLIENT, give it the same treatment (classified code + generic msg + operator log). If revoke errors are only logged (not returned to a client) or already use ErrLeaseRevokeFailed, leave as-is — read it and report.

- [ ] **Step 4: Run, confirm green**

```bash
cd <WT>
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-do/... 2>&1 | tail -12
```
Expected: new test passes; existing DO tests pass (they don't assert on the old "upstream error: %v" message — confirm; if one does, update it to the new generic message, preserving intent).

- [ ] **Step 5: lint + commit**

```bash
cd <WT>
(cd plugins/credential-do && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add plugins/credential-do/
git commit -m "$(printf 'fix(do): classify upstream error_code + stop leaking body to client (audit2 #4,#5)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Tasks 3–10: the other 8 JIT plugins — classified code + no body leak (#4/#5)

Each of exoscale, azure, vultr, akamai, upcloud (bare-`httpStatus` group) and aws, gcp, ovh (classify-helper group) gets the Task 2 treatment at its issue-error site. Per plugin:

1. Read the issue-error site (`grep -n 'ErrorResponse(credenvelope.ErrInternal, "upstream error' plugins/credential-<p>/path_creds.go`).
2. Apply the fix:
   - **bare-httpStatus group (exoscale, azure, vultr, akamai, upcloud):** the `httpStatus` var is already in scope — same edit as DO (log + `ClassifyUpstream(httpStatus)` + generic msg).
   - **classify-helper group (aws, gcp, ovh):** there's no standalone `httpStatus` var — the status is computed inline as `classify<X>Error(err)`. Capture it ONCE:
     ```go
     status := classifyAWSError(err)   // (or classifyGCPError / classifyOVHError)
     b.recordMinterError(sel.setID, sel.minterID, status, now)
     b.Logger().Warn("upstream credential issuance failed", "cloud", cloudName, "status", status, "error", err)
     return credenvelope.ErrorResponse(credenvelope.ClassifyUpstream(status), "upstream credential issuance failed"), nil
     ```
     (adapt the recordMinterError args to the plugin's real signature — aws uses sel.setID/sel.minterID; gcp/ovh use setName/minterID).
3. Check that plugin's revoke/secondary error site for the same body-leak; fix if it returns `err` to the client (report per plugin).
4. Add a `TestCredsIssue_ClassifiesQuotaError`-style test (lighter — assert the classified code surfaces for a forced 429 and no raw body), using that plugin's fake `SetNextStatus`/error knob (confirm the knob name per fake — some may differ, e.g. `SetNextStatus`, `FailNext`).
5. `go test -race` that plugin green; existing tests unchanged. gofmt + lint. Commit `fix(<p>): classify upstream error_code + stop leaking body to client (audit2 #4,#5)`.

One commit each. After all 8:
```bash
cd <WT>
go build github.com/nicois/openbao-cloud-creds/... && go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | grep -E 'FAIL|ok ' | tail -22
# Confirm NO client-facing envelope still interpolates err:
grep -rn 'ErrorResponse(.*err)' plugins/*/path_creds.go || echo "no err-interpolating envelopes remain"
```

> **Per-plugin notes:** OCI has no JIT issue site (skip it for #4/#5 — its read path returns slot creds or pool_exhausted, no upstream mint error). The azure/akamai CLIENT errors still embed the body in their `err` (operator log) — that's fine; only the envelope must not interpolate it. Confirm each plugin's fake has a status-injection knob; if one truly lacks it, assert the classified code via a different forced-error path and note it.

---

## Task 11: 429 cool-down in `pkg/recovery` (#8 core)

**Files:**
- Modify: `pkg/recovery/state.go`
- Test: `pkg/recovery/state_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `pkg/recovery/state_test.go`:
```go
func TestSelectable_429Cooldown(t *testing.T) {
	sm := NewStateMachine(Config{AuthFailThreshold: time.Hour, HealthCheckInterval: time.Minute})
	t0 := time.Now()
	sm.RecordError(http.StatusTooManyRequests, t0) // 429

	if sm.Selectable(t0.Add(1 * time.Second)) {
		t.Fatal("expected not selectable during 429 cool-down")
	}
	if !sm.Selectable(t0.Add(RateLimitCooldown + time.Second)) {
		t.Fatal("expected selectable after cool-down elapsed")
	}
}

func TestSelectable_NonRateLimitErrorNoCooldown(t *testing.T) {
	sm := NewStateMachine(Config{AuthFailThreshold: time.Hour, HealthCheckInterval: time.Minute})
	t0 := time.Now()
	sm.RecordError(http.StatusInternalServerError, t0) // 500 → TransientFailing, no cooldown
	if !sm.Selectable(t0.Add(time.Second)) {
		t.Fatal("a transient (non-429) error must not make the minter unselectable")
	}
}

func TestSelectable_AuthFailingNotSelectable(t *testing.T) {
	sm := NewStateMachine(Config{AuthFailThreshold: 0, HealthCheckInterval: time.Minute})
	t0 := time.Now()
	sm.RecordError(http.StatusUnauthorized, t0) // 401, threshold 0 → AuthFailing immediately
	if sm.Selectable(t0.Add(time.Second)) {
		t.Fatal("auth_failing minter must not be selectable")
	}
}

func TestSelectable_SuccessClearsCooldown(t *testing.T) {
	sm := NewStateMachine(Config{AuthFailThreshold: time.Hour, HealthCheckInterval: time.Minute})
	t0 := time.Now()
	sm.RecordError(http.StatusTooManyRequests, t0)
	sm.RecordSuccess(t0.Add(time.Second))
	if !sm.Selectable(t0.Add(2 * time.Second)) {
		t.Fatal("RecordSuccess must clear the cool-down")
	}
}
```
(`pkg/recovery` internal test — add `"net/http"` import.)

- [ ] **Step 2: Run, confirm fail**

```bash
cd <WT>
go test -run 'TestSelectable' github.com/nicois/openbao-cloud-creds/pkg/recovery/ -v 2>&1 | tail -15
```
Expected: build failure — `undefined: RateLimitCooldown` / `sm.Selectable`.

- [ ] **Step 3: Implement**

In `pkg/recovery/state.go`:
3a. Add the const (near the `State` consts):
```go
// RateLimitCooldown is how long a minter is skipped by selectors after the
// upstream returns 429, so a rate-limited minter is not immediately re-hammered.
const RateLimitCooldown = 5 * time.Second
```
3b. Add a field to `StateMachine`:
```go
	cooldownUntil time.Time
```
3c. In `RecordError`, at the top (after `sm.lastErrorAt = at`), set the cool-down on 429:
```go
	if httpStatus == http.StatusTooManyRequests {
		sm.cooldownUntil = at.Add(RateLimitCooldown)
	}
```
(add `"net/http"` import to state.go).
3d. In `RecordSuccess`, clear it: add `sm.cooldownUntil = time.Time{}` alongside the other resets.
3e. Add `Selectable`:
```go
// Selectable reports whether a minter in this state may be chosen to mint a
// credential at the given time. It is false while a 429 cool-down is active and
// for states that should not serve (AuthFailing, Missing).
func (sm *StateMachine) Selectable(now time.Time) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if now.Before(sm.cooldownUntil) {
		return false
	}
	return sm.state == Healthy || sm.state == TransientFailing
}
```

- [ ] **Step 4: Run, confirm green**

```bash
cd <WT>
go test -race github.com/nicois/openbao-cloud-creds/pkg/recovery/... 2>&1 | tail -10
```
Expected: the 4 new tests pass; all existing recovery tests pass (incl the concurrent-access stress test — Selectable takes RLock, consistent).

- [ ] **Step 5: lint + commit**

```bash
cd <WT>
(cd pkg/recovery && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add pkg/recovery/
git commit -m "$(printf 'feat(recovery): 429 cool-down + Selectable(now) gate (audit2 #8)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 12: credential-do selectMinter uses Selectable(now) (#8 reference)

**Files:**
- Modify: `plugins/credential-do/path_creds.go`
- Test: `plugins/credential-do/path_creds_test.go`

DO's `selectMinter(setName)` (path_creds.go:184) and the related selection loops (lines ~232, ~248 — likely in `anyHealthyMinter`/reconcile-client helpers) check `ms.sm.State() == Healthy || TransientFailing`. They don't take `now`.

- [ ] **Step 1: write the failing test**

```go
// A 429'd minter is skipped by selection within the cool-down window; a sibling
// healthy minter in the same set is chosen instead.
func TestSelectMinter_SkipsCooldownMinter(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackendTwoMinters(t, srv.URL) // a set with minter-1 + minter-2
	bk := b.(*backend)
	// Drive minter-1 into 429 cool-down.
	bk.recordMinterError("default", "minter-1", http.StatusTooManyRequests, time.Now())
	sel, err := bk.selectMinter("default") // signature may now take now — adapt
	if err != nil {
		t.Fatalf("selectMinter: %v", err)
	}
	if sel.minterID == "minter-1" {
		t.Fatal("expected the cooling-down minter-1 to be skipped")
	}
}
```
Adapt heavily to reality: DO's existing tests configure a single minter (`minter-1`); you need a two-minter set to prove the skip picks the sibling. Either add a `setupConfiguredBackendTwoMinters` helper (mirror the existing setup, with two minters in the set — both `never_expires` or valid) or write the minter-set with two minters inline via HandleRequest. If `selectMinter` is changed to take `now`, call it with `time.Now()`. Read the existing selectMinter + recordMinterError to get exact signatures.

- [ ] **Step 2: run, confirm fail**

```bash
cd <WT>
go test -run TestSelectMinter_SkipsCooldownMinter github.com/nicois/openbao-cloud-creds/plugins/credential-do/ -v 2>&1 | tail -12
```
Expected: FAIL — current selectMinter accepts TransientFailing (which a 429'd minter is), so it can still pick minter-1.

- [ ] **Step 3: implement**

In `plugins/credential-do/path_creds.go`:
- Change `selectMinter(setName string)` → `selectMinter(setName string, now time.Time)` (and update its caller in `pathCredsRead` to pass the `now` it already computes).
- Replace each `ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing` (3 sites: in selectMinter and the two other selection helpers ~232/248) with `ms.sm.Selectable(now)`.
- For the non-selectMinter helpers (e.g. `anyHealthyMinter` used by the reconciler — confirm), if they don't have a `now`, pass `time.Now()` at the call or thread it; the reconciler/health paths can use `time.Now()` directly (they're not the hot read path, but consistency is fine).

- [ ] **Step 4: run green + existing tests**

```bash
cd <WT>
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-do/... 2>&1 | tail -12
```
Expected: new test passes; existing DO tests pass (selectMinter signature change is internal; update any test that calls selectMinter directly to pass `now`).

- [ ] **Step 5: lint + commit**

```bash
cd <WT>
(cd plugins/credential-do && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add plugins/credential-do/
git commit -m "$(printf 'fix(do): selectMinter honors 429 cool-down via Selectable(now) (audit2 #8)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Tasks 13–21: the other 9 plugins selectMinter → Selectable(now) (#8)

Each of aws, gcp, azure, oci, ovh, upcloud, exoscale, vultr, akamai gets the Task 12 treatment. Per plugin:
1. `grep -n 'State() == recovery.Healthy\|State() == recovery.TransientFailing\|func (b \*backend) selectMinter\|anyHealthyMinter\|func.*selectMinterForSet' plugins/credential-<p>/*.go` — find all selection checks (count varies; OCI uses `selectMinterForSet` in its rotation/reconcile paths).
2. Replace each `State()==Healthy||TransientFailing` selection check with `ms.sm.Selectable(now)`, threading `now` (from the call site; the read/rotation path has a `now`, else `time.Now()`).
3. Add the `TestSelectMinter_SkipsCooldownMinter`-style test (two-minter set, 429 one, assert the other chosen). For OCI (no JIT selectMinter, but selectMinterForSet picks a minter for rotation/list) adapt: drive a minter into cool-down, assert selectMinterForSet skips it. If OCI's selection genuinely has no sibling-fallback shape, assert at least that a cooled-down minter is not returned when a healthy sibling exists.
4. `go test -race` that plugin green; gofmt + lint; commit `fix(<p>): selectMinter honors 429 cool-down via Selectable(now) (audit2 #8)`.

One commit each. **Note:** the selection-check sites differ per plugin (the #7 de-dup did NOT merge selectMinter — it's still per-plugin); grep each. After all 9, confirm NO `State() == recovery.Healthy || ... TransientFailing` selection checks remain (they should all be `Selectable(now)`):
```bash
cd <WT>
grep -rn 'State() == recovery.Healthy' plugins/*/  | grep -v _test || echo "all selection checks now use Selectable"
```
(Health-check/state-display reads of `State()` for OTHER purposes — logging, metrics, NeedsHealthCheck — are fine and stay; only the SELECTION checks change.)

---

## Task 22: Full verification + mark #4/#5/#8 resolved

**Files:** `docs/audit-2026-06-01.md`.

- [ ] **Step 1: full-workspace gate**

```bash
cd <WT>
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
Expected: build OK, all tests pass, ALL 20 MODULES CLEAN, make lint exit 0, smoke green. (If `golangci-lint` on PATH is v1, use `/home/claude-aiven-2/code/qualcheck/bin/golangci-lint` for the loop.)

- [ ] **Step 2: confirm the leak is gone + no nolint**

```bash
cd <WT>
grep -rn 'ErrorResponse(.*err)' plugins/*/path_creds.go || echo "no err-interpolating client envelopes remain"
grep -rn 'State() == recovery.Healthy' plugins/*/*.go | grep -v _test || echo "all selection checks use Selectable"
git diff main..HEAD | grep -nE '^\+.*nolint' || echo "no nolint added"
```

- [ ] **Step 3: mark #4/#5/#8 resolved in docs/audit-2026-06-01.md**

Append ` — [RESOLVED 2026-06-01]` to the `## 4.`, `## 5.`, `## 8.` headings + a one-line `**Resolved:**` note each:
- #4: `credenvelope.ClassifyUpstream(status)` maps upstream HTTP status to the existing error_code at every JIT plugin's issue-error site (429→quota, 408/504→timeout, 401/403→auth_failed, 404→entity_unavailable, 5xx→internal).
- #5: issue-error sites now log the raw upstream err/body operator-side and return only the classified code + a generic message; no client-facing envelope interpolates the upstream body/err.
- #8: `pkg/recovery` gained a 5s 429 cool-down (`RateLimitCooldown`, `cooldownUntil`) + `Selectable(now)`; all plugins' minter-selection now uses `Selectable(now)`, so a rate-limited minter is skipped for the window and a healthy sibling is chosen.

- [ ] **Step 4: commit + summary**

```bash
cd <WT>
git add docs/audit-2026-06-01.md
git commit -m "$(printf 'docs: mark audit2 #4/#5/#8 resolved (effort 2)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
git log --oneline main..HEAD | wc -l
```

---

## Self-review notes (for the executor)

- **Task ordering:** Task 1 (ClassifyUpstream) before Tasks 2–10 (consumers). Task 11 (recovery Selectable) before Tasks 12–21 (consumers). The #4/#5 track (1–10) and #8 track (11–21) are independent — could interleave, but do classifier fully then cool-down for clarity. Task 22 last.
- **The two #4 groups:** bare-`httpStatus` plugins (do/exoscale/azure/vultr/akamai/upcloud) vs classify-helper plugins (aws/gcp/ovh — capture `status := classify<X>Error(err)` first). OCI has no JIT issue site — skip #4/#5 for it.
- **#8 selectMinter signature change** to `(setName, now)` is internal; update direct callers + the reconciler/health selection helpers (which can pass `time.Now()`). The selection-check sites are per-plugin (not de-duped), so grep each plugin.
- **Behavior preservation:** existing tests pass unchanged except where a NEW test is added or a test asserted the OLD "upstream error: %v" message (update to the generic message, preserving intent — report any).
- **Strictly-safer for #8:** Selectable can only make selection skip MORE (never select a previously-rejected minter); pool_exhausted is the honest fallback when the whole set is cooling down.
- **No new error code, no api_version bump** — the response shape is unchanged; only which existing error_code value appears.
- Trust live code over plan line numbers; read before editing; edit only worktree paths.
