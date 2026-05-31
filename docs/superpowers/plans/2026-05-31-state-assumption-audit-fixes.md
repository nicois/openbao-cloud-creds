# State-Assumption Audit Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify, then fix, a class of bugs where code assumes backend/upstream/goroutine state without confirming it — the most dangerous being a dead reconciler grace-guard that can delete live credentials.

**Architecture:** Verify-then-fix is embedded in each task via TDD: write the verification test first and run it. A RED result confirms the finding is REAL → implement the fix → GREEN. A finding whose test cannot be made to fail is REFUTED → document it in the verification report and skip the fix (do NOT invent a fix for a non-bug). Concurrency findings use `testing/synctest` (GA in Go 1.25; repo is on 1.26.1) for deterministic repro. Reconciler safety fix is fail-closed: when an entity's age is unconfirmable, skip the delete.

**Tech Stack:** Go 1.26.1 workspace (`go.work`, per-module `go.mod`), `testing/synctest`, golangci-lint v2.12.2, OpenBao SDK v2.

**Reference spec:** `docs/superpowers/specs/2026-05-31-state-assumption-audit-fixes-design.md`

---

## How to work this plan

- **Worktree:** all work on one branch (created by the execution skill). Never touch `main`. Confirm `git branch --show-current` before every commit.
- **Build/test (full module path, NOT `./...`):**
  ```bash
  go build github.com/nicois/openbao-cloud-creds/...
  go test -race github.com/nicois/openbao-cloud-creds/...
  ```
- **Per-module lint** (auto-discovers the repo `.golangci.yml`):
  ```bash
  export PATH="$(go env GOPATH)/bin:$PATH"
  (cd <module-dir> && golangci-lint run ./...)
  ```
- **synctest note:** the GA API is `synctest.Test(t, func(t *testing.T){ ... })` (Go 1.25+). Inside the bubble, the clock is fake and only advances when every goroutine in the bubble is durably blocked; `synctest.Wait()` blocks until all bubble goroutines are durably blocked. `time.Sleep`, `time.NewTicker`, `time.After` are all faked. Import `"testing/synctest"`.
- **Definition of done per task:** the verification test exists and behaves as the task states (red-then-green for REAL findings; green-and-documented for REFUTED); workspace `go test -race` green; touched modules lint clean.
- **The verification report** `docs/state-assumption-verification-2026-05-31.md` is created in Task 1 and appended to by every subsequent task with that finding's verdict + artifact.

---

## Task 1: Verification report scaffold + static-provable findings

**Files:**
- Create: `docs/state-assumption-verification-2026-05-31.md`

- [ ] **Step 1: Re-confirm the dead `ConfirmationHold` guard (static)**

```bash
cd /path/to/worktree
grep -n 'CreatedAt' pkg/reconciler/reconciler.go
grep -rn 'reconciler.UpstreamEntity{' plugins/*/reconciler_integration.go
```
Expected: `reconciler.go:62` gates on `!entity.CreatedAt.IsZero()`; every `reconciler.UpstreamEntity{...}` in the six listers (do, azure, vultr, exoscale, upcloud, akamai) sets only `ID` and `Name`, never `CreatedAt`. This proves the guard is unreachable. Verdict: **REAL**.

- [ ] **Step 2: Confirm GCP/OVH lack a client-side HTTP timeout (static)**

```bash
grep -n 'http.DefaultClient\|Timeout' plugins/credential-gcp/iam_client.go plugins/credential-ovh/token_client.go
grep -rn 'httpTimeout' plugins/credential-do/do_client.go
```
Expected: gcp `iam_client.go:156,208` and ovh `token_client.go:63` use `http.DefaultClient` (no Timeout); DO (and the other 7) use a `httpTimeout`-bounded client. Verdict: **REAL**.

- [ ] **Step 3: Write the report scaffold**

Create `docs/state-assumption-verification-2026-05-31.md`:
```markdown
# State-Assumption Findings — Verification Report (2026-05-31)

Each finding: verdict (REAL / REFUTED / DOCUMENTED-RISK), artifact (test path or static proof), action.

| # | Finding | Verdict | Artifact | Action |
|---|---------|---------|----------|--------|
| F1 | Reconciler ConfirmationHold guard dead (6 plugins) | REAL | static: reconciler.go:62 gated on CreatedAt, no lister sets it | fix (Task 3,4) |
| F2 | GCP/OVH no HTTP client timeout | REAL | static: http.DefaultClient at iam_client.go:156,208 + token_client.go:63 | fix (Task 8) |
| F3 | OCI fakeOCIClient unsynchronized map | TBD | Task 2 | — |
| F4 | OCI rotation-vs-reconcile delete race | TBD | Task 2 | — |
| F5 | Reconciler DeleteEntity not 404-idempotent (5 plugins) | TBD | Task 6 | — |
| F6 | Create-then-track: untracked live cred on Put failure | TBD | Task 7 | — |
| F7 | Azure addPassword Graph propagation lag | TBD | Task 9 | — |
| F8 | pkg/worker tests sleep-based / flaky | REAL | static: worker_test.go fixed sleeps + [4,6] band | fix (Task 10) |

## Notes
(Subsequent tasks append per-finding detail here.)
```

- [ ] **Step 4: Commit**

```bash
git add docs/state-assumption-verification-2026-05-31.md
git commit -m "docs: verification report scaffold + static findings (F1,F2,F8 REAL)"
```

---

## Task 2: Verify OCI concurrency findings with synctest (F3, F4)

**Files:**
- Create: `plugins/credential-oci/concurrency_test.go`
- Append: `docs/state-assumption-verification-2026-05-31.md`

First READ these to ground the test in reality:
```bash
sed -n '64,175p' plugins/credential-oci/oci_client.go   # fakeOCIClient + methods
sed -n '40,165p' plugins/credential-oci/workers.go       # rotation + reconcileWorker + rotateDueSlots
sed -n '1,60p'  plugins/credential-oci/path_reconcile.go # collectKnownTokenIDs + reconcileOrphans
```

- [ ] **Step 1: F3 — write a `-race` test exercising the fake from two goroutines**

`fakeOCIClient` (oci_client.go:64) has `tokens map`, `nextID`, `failNext` with NO mutex. Write a test that calls fake methods concurrently to see if `-race` flags it:
```go
package credentialoci

import (
	"context"
	"sync"
	"testing"
)

func TestFakeOCIClient_ConcurrentAccess(t *testing.T) {
	f := newFakeOCIClient()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _, _ = f.CreateAuthToken(context.Background(), "user-1", "cloud-creds-x")
				_ = f.TokenCount()
				_, _ = f.ListAuthTokens(context.Background(), "user-1")
			}
		}(i)
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run F3 test under -race**

```bash
go test -race -run TestFakeOCIClient_ConcurrentAccess github.com/nicois/openbao-cloud-creds/plugins/credential-oci/ 2>&1 | tail -20
```
Expected if REAL: `DATA RACE` on the `tokens` map / `nextID`. Record the verdict. (This is test-only infra; the fix is the mutex in Task 5 Step 1. If `-race` does NOT flag it even with concurrent writes, verdict REFUTED — but concurrent map writes are a definite race, so REAL is expected.)

- [ ] **Step 3: F4 — write a synctest deterministic repro of the rotation/reconcile delete race**

The hazard: rotation creates+persists a new token while reconcile snapshots the known-set then lists+deletes. Drive it deterministically. Write into the same file:
```go
import "testing/synctest"

// TestRotationReconcileRace asserts a token created by rotation is never
// deleted by a concurrent reconcile pass. Uses synctest so the interleaving
// is deterministic rather than timing-dependent.
func TestRotationReconcileRace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Build a backend with the fake OCI client, one role with N=2 slots,
		// a rotation interval and reconcile cadence that both fire inside the
		// bubble. Start workers. synctest.Wait() until both are durably blocked
		// between ticks; advance the fake clock to force both to run; assert
		// fake.TokenCount() never drops a freshly-rotated token (i.e. no live
		// token is reconciled away).
		//
		// Construct via the same setup the OCI resilience/rotation tests use
		// (read rotation_test.go for setupConfiguredBackend equivalent), or
		// drive rotateDueSlots + reconcileWorker directly against a shared
		// fake + InmemStorage from two goroutines and synctest.Wait between.
	})
}
```
IMPORTANT: ground this in the real setup helpers — read `plugins/credential-oci/rotation_test.go` and `resilience_test.go` for how a configured backend + fake is built, and reuse that. The test must (a) share ONE backend + fake + storage, (b) cause rotation to create a token and reconcile to run against a stale known-set snapshot in the same logical instant, (c) assert the rotated token survives.

- [ ] **Step 4: Run F4 repro**

```bash
go test -race -run TestRotationReconcileRace github.com/nicois/openbao-cloud-creds/plugins/credential-oci/ 2>&1 | tail -25
```
- If it FAILS (rotated token deleted, or `-race`/`concurrent map` fires): verdict **REAL** → fix in Task 5.
- If it consistently PASSES even when forced (e.g. because rotation and reconcile already can't interleave destructively, or the known-set is rebuilt post-list): verdict **REFUTED** → document why, and Task 5 Step 2 becomes a no-op (skip it, note in report). Be honest: if you cannot construct an interleaving that deletes a live token, say so.

- [ ] **Step 5: Append verdicts to the report and commit**

Append F3/F4 detail (verdict, what the test showed, the exact interleaving for F4) to `docs/state-assumption-verification-2026-05-31.md`.
```bash
go vet ./plugins/credential-oci/... 2>/dev/null; (cd plugins/credential-oci && gofmt -w . && golangci-lint run ./...)
git add plugins/credential-oci/concurrency_test.go docs/state-assumption-verification-2026-05-31.md
git commit -m "test(oci): synctest repro for fake-map race (F3) and rotation/reconcile race (F4)"
```
(Commit the tests even if a finding is REFUTED — a passing test that pins the safe behavior is valuable. If F3/F4 are REAL, these tests stay RED until Task 5; note that the commit may leave a known-red test — that's acceptable mid-plan, or mark them `t.Skip("RED until Task 5 fix")` with a clear reason and unskip in Task 5.)

---

## Task 3: Reconciler fail-closed guard (F1 core — the safety-critical fix)

**Files:**
- Modify: `pkg/reconciler/reconciler.go:62-66`
- Test: `pkg/reconciler/reconciler_test.go`

- [ ] **Step 1: Write the failing test (verification)**

Append to `pkg/reconciler/reconciler_test.go`:
```go
// TestRun_FailsClosedWhenAgeUnconfirmable proves that with a ConfirmationHold
// set, an orphan whose CreatedAt is zero (age unconfirmable) is NOT deleted.
// This is the safety core: absent age info, do not delete.
func TestRun_FailsClosedWhenAgeUnconfirmable(t *testing.T) {
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		{ID: "orphan-zerotime", Name: "cloud-creds-role-a-1"}, // CreatedAt zero
	}}
	reg := &fakeRegistry{known: map[string]bool{}}
	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  1 * time.Hour,
	}, cloud, reg)

	res, err := r.Run(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Deleted != 0 {
		t.Fatalf("fail-closed: expected 0 deletes for unconfirmable-age orphan, got %d", res.Deleted)
	}
	if len(cloud.entities) != 1 {
		t.Fatal("unconfirmable-age orphan must not be deleted")
	}
}

// TestRun_DeletesConfirmablyOldOrphan proves a CreatedAt older than the hold
// is still deleted (the precision path still works).
func TestRun_DeletesConfirmablyOldOrphan(t *testing.T) {
	now := time.Now()
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		{ID: "old-orphan", Name: "cloud-creds-role-a-1", CreatedAt: now.Add(-2 * time.Hour)},
	}}
	reg := &fakeRegistry{known: map[string]bool{}}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10, ConfirmationHold: 1 * time.Hour}, cloud, reg)
	res, err := r.Run(context.Background(), now)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Deleted != 1 {
		t.Fatalf("expected confirmably-old orphan deleted, got %d", res.Deleted)
	}
}

// TestRun_SkipsRecentConfirmableOrphan: CreatedAt within the hold => skip.
func TestRun_SkipsRecentConfirmableOrphan(t *testing.T) {
	now := time.Now()
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		{ID: "fresh-orphan", Name: "cloud-creds-role-a-1", CreatedAt: now.Add(-5 * time.Minute)},
	}}
	reg := &fakeRegistry{known: map[string]bool{}}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10, ConfirmationHold: 1 * time.Hour}, cloud, reg)
	res, err := r.Run(context.Background(), now)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Deleted != 0 {
		t.Fatalf("expected fresh orphan skipped, got %d", res.Deleted)
	}
}
```

- [ ] **Step 2: Run, confirm the fail-closed test fails**

```bash
go test -run 'TestRun_FailsClosedWhenAgeUnconfirmable|TestRun_DeletesConfirmablyOldOrphan|TestRun_SkipsRecentConfirmableOrphan' github.com/nicois/openbao-cloud-creds/pkg/reconciler/ -v 2>&1 | tail -25
```
Expected: `TestRun_FailsClosedWhenAgeUnconfirmable` FAILS (current code deletes the zero-CreatedAt orphan because the guard is skipped — proving F1). The other two: `DeletesConfirmablyOldOrphan` passes already; `SkipsRecentConfirmableOrphan` passes already (the guard works WHEN CreatedAt is set). The failing one is the bug.

- [ ] **Step 3: Implement the fail-closed guard**

Replace `pkg/reconciler/reconciler.go:62-66`:
```go
		if r.config.ConfirmationHold > 0 && !entity.CreatedAt.IsZero() {
			if now.Sub(entity.CreatedAt) < r.config.ConfirmationHold {
				continue
			}
		}
```
with:
```go
		// Fail closed: when a confirmation hold is configured, only delete an
		// orphan whose age we can confirm is older than the hold. If CreatedAt
		// is unknown (zero), we cannot confirm the entity isn't a just-issued
		// credential still in its create-then-track window, so we skip it this
		// pass rather than risk deleting a live credential.
		if r.config.ConfirmationHold > 0 {
			if entity.CreatedAt.IsZero() || now.Sub(entity.CreatedAt) < r.config.ConfirmationHold {
				continue
			}
		}
```

- [ ] **Step 4: Run all reconciler tests, confirm green**

```bash
go test -race github.com/nicois/openbao-cloud-creds/pkg/reconciler/ -v 2>&1 | tail -30
```
Expected: ALL pass, including the three new ones. The pre-existing `TestDetectsOrphans`/`TestMaxDeletesPerPass`/`TestRun_OnlyDeletesListedOrphans` use `ConfirmationHold: 0` (or unset), so the new guard branch doesn't affect them — verify they still pass.

- [ ] **Step 5: Lint + commit**

```bash
(cd pkg/reconciler && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add pkg/reconciler/
git commit -m "fix(reconciler): fail closed on unconfirmable entity age (audit F1 core)"
```

> **Behavior-change note for the executor:** this fix means that UNTIL Task 4 populates `CreatedAt`, the worker reconcile pass (ConfirmationHold=1h) will skip ALL orphans (all have zero CreatedAt) — i.e. orphan cleanup is effectively paused on the worker path. That is the intended safe state (better to leak an orphan than delete a live cred). The manual `/reconcile` path sets `ConfirmationHold: 0`, so it still deletes (operator-initiated, accepts the risk). Task 4 restores precise cleanup. Do NOT skip Task 4.

---

## Task 4: Populate `CreatedAt` from each cloud's list response (F1 precision)

Restores precise orphan cleanup on the worker path by giving the reconciler real creation timestamps. DO is the reference; the other five follow the same shape. **Only do the clouds whose list API actually returns a timestamp** — for any cloud whose list response has no creation time, document it in the report and rely on the fail-closed guard (the worker won't delete those orphans, which is acceptable; note it).

**Files (reference, DO):**
- Modify: `plugins/credential-do/do_client.go` (the `tokenInfo` struct + parse)
- Modify: `plugins/credential-do/reconciler_integration.go` (set `CreatedAt`)
- Test: `plugins/credential-do/reconciler_integration_test.go` (or the existing reconcile test file)

- [ ] **Step 1: Check what each cloud's list API returns for creation time**

For each of do, upcloud, azure, akamai, exoscale, vultr: read the client's list response struct and the corresponding cloud-fake in `pkg/credenvelope/fakes/<cloud>.go`. Determine the JSON field carrying creation time (DO token `created_at`, UpCloud `created`, Azure passwordCredential `startDateTime`, Akamai `createdDate`/`created`, Exoscale/Vultr — check). Record per-cloud findings in the verification report. If a cloud's list (and its fake) has no creation timestamp, mark it "no upstream timestamp — relies on fail-closed" and skip its `CreatedAt` wiring.

- [ ] **Step 2 (DO reference): write the failing test**

Add to DO's reconcile test file a test that the lister surfaces `CreatedAt`. First confirm the fake (`pkg/credenvelope/fakes/do.go`) returns a `created_at` for listed tokens; if not, add it to the fake (small, behavior-preserving — a fixed timestamp on created tokens). Then:
```go
func TestReconcile_PopulatesCreatedAt(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	// ... build a doCloudLister against srv.URL (mirror the existing reconcile
	// test's setup) and call ListTaggedEntities; assert the returned entity's
	// CreatedAt is non-zero and matches the fake's value.
}
```

- [ ] **Step 3: implement — parse + map the timestamp**

In `do_client.go`, extend `tokenInfo`:
```go
type tokenInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}
```
In `reconciler_integration.go`, parse and set it (RFC3339; tolerate empty/unparseable as zero — which the fail-closed guard then handles safely):
```go
		if strings.HasPrefix(t.Name, tokenPrefix) {
			var created time.Time
			if t.CreatedAt != "" {
				if ts, perr := time.Parse(time.RFC3339, t.CreatedAt); perr == nil {
					created = ts
				}
			}
			entities = append(entities, reconciler.UpstreamEntity{
				ID:        t.ID,
				Name:      t.Name,
				CreatedAt: created,
			})
		}
```
(Add the `"time"` import.)

- [ ] **Step 4: run DO tests green**

```bash
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-do/... 2>&1 | tail -15
```

- [ ] **Step 5: repeat Steps 2-4 for upcloud, azure, akamai, exoscale, vultr**

Same shape per cloud, using that cloud's real list-response timestamp field and its fake. For Azure, the timestamp is on the passwordCredential (`startDateTime`); map it in `azure`'s lister. For any cloud with no timestamp, skip and document. Each cloud: extend the client list struct, parse in the lister, set `CreatedAt`, add/extend a test, run that plugin's tests green.

- [ ] **Step 6: verify the worker path now cleans confirmably-old orphans**

For DO, add (or extend) a test proving end-to-end that with `ConfirmationHold: 1h`, an orphan whose fake `created_at` is 2h old IS deleted, and one 5m old is NOT. This proves Task 3 + Task 4 together restore correct behavior.

- [ ] **Step 7: lint each touched plugin + commit**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
for p in do upcloud azure akamai exoscale vultr; do (cd plugins/credential-$p && gofmt -w . && golangci-lint run ./...) || echo "LINT FAIL $p"; done
go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -20
git add plugins/ pkg/credenvelope/fakes/ docs/state-assumption-verification-2026-05-31.md
git commit -m "fix(reconciler): populate UpstreamEntity.CreatedAt from cloud list APIs (audit F1 precision)"
```

---

## Task 5: Fix OCI concurrency (F3 fake mutex; F4 race — only if Task 2 confirmed REAL)

**Files:**
- Modify: `plugins/credential-oci/oci_client.go` (fakeOCIClient mutex)
- Modify: `plugins/credential-oci/workers.go` and/or `path_reconcile.go` (serialize rotation vs reconcile) — ONLY if F4 was REAL

- [ ] **Step 1: F3 — add a mutex to `fakeOCIClient`**

In `oci_client.go`, add `mu sync.Mutex` to the struct and guard EVERY method that reads/writes `tokens`/`nextID`/`failNext` (`CreateAuthToken`, `DeleteAuthToken`, `ListAuthTokens`, `GetUser`, `SetNextError`, `TokenCount`, `TokenCountForUser`):
```go
type fakeOCIClient struct {
	mu       sync.Mutex
	tokens   map[string]map[string]*fakeToken
	nextID   int
	failNext error
}
```
Each method: `f.mu.Lock(); defer f.mu.Unlock()` at entry (use a non-deferred unlock only if a method calls another locking method — check for re-entrancy; `TokenCount` etc. are leaf methods, safe to defer).

- [ ] **Step 2: run F3 test green under -race**

```bash
go test -race -run TestFakeOCIClient_ConcurrentAccess github.com/nicois/openbao-cloud-creds/plugins/credential-oci/ 2>&1 | tail -8
```
Expected: PASS, no DATA RACE.

- [ ] **Step 3: F4 — serialize rotation and reconcile (ONLY if Task 2 verdict was REAL)**

If F4 was REFUTED in Task 2, SKIP this step and note "F4 refuted, no fix" in the report. If REAL: add a mutex on the backend that both the rotation delete-path and the reconcile pass hold, so a reconcile cannot list+delete while a rotation is mid-create-persist. Read `workers.go`/`path_reconcile.go` to place it minimally — wrap the reconcile pass (snapshot→list→delete) and the rotation's create+persist+delete in the same `b.<mu>.Lock()`. Prefer a dedicated `b.rotateReconcileMu sync.Mutex` to avoid contending the request-path `b.mu`. Make the synctest repro (`TestRotationReconcileRace`) the proof.

- [ ] **Step 4: run F4 repro green (if applicable) + full OCI suite**

```bash
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-oci/... 2>&1 | tail -20
```
Unskip any `t.Skip` added in Task 2.

- [ ] **Step 5: lint + commit**

```bash
(cd plugins/credential-oci && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add plugins/credential-oci/ docs/state-assumption-verification-2026-05-31.md
git commit -m "fix(oci): synchronize fake client map (F3) + serialize rotation/reconcile (F4)"
```
(If F4 refuted, adjust the message to F3 only.)

---

## Task 6: Reconciler `DeleteEntity` 404-idempotency (F5)

The five non-Azure listers do `_, err := l.client.Delete...(ctx, id); return err`, discarding the status int. The client returns `(httpStatus int, err error)` and errors on 404. So a reconcile pass aborts (`reconciler.go:79-81`) on an already-gone entity. Fix: treat 404 as success.

**Files:** `plugins/credential-{do,vultr,exoscale,upcloud,akamai}/reconciler_integration.go`; a test in one representative plugin (DO).

- [ ] **Step 1: write the failing test (DO, representative)**

The DO fake must return 404 on delete of an unknown id. Confirm/extend `pkg/credenvelope/fakes/do.go` so deleting a non-existent token yields 404. Then:
```go
func TestDeleteEntity_404IsSuccess(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	lister := &doCloudLister{client: newDOClient(srv.URL, "minter-token")}
	// id that does not exist upstream -> upstream returns 404
	if err := lister.DeleteEntity(context.Background(), "nonexistent-id"); err != nil {
		t.Fatalf("DeleteEntity should treat upstream 404 as success, got: %v", err)
	}
}
```

- [ ] **Step 2: run, confirm it fails**

```bash
go test -run TestDeleteEntity_404IsSuccess github.com/nicois/openbao-cloud-creds/plugins/credential-do/ -v 2>&1 | tail -12
```
Expected: FAIL (DeleteEntity returns the 404 error). Verdict F5 **REAL**.

- [ ] **Step 3: fix DeleteEntity in all 5 plugins**

Each plugin's `DeleteEntity` (do/vultr/exoscale/upcloud/akamai) — capture the status and treat 404 as success. DO example:
```go
func (l *doCloudLister) DeleteEntity(ctx context.Context, id string) error {
	status, err := l.client.DeleteToken(ctx, id)
	if err != nil && status != http.StatusNotFound {
		return err
	}
	return nil
}
```
(Add `"net/http"` import.) Apply the identical pattern with each plugin's delete fn name: vultr `DeleteUser`, exoscale `DeleteAPIKey`, upcloud `DeleteToken`, akamai `DeleteClient`. Azure already swallows errors — leave it, but note in the report that Azure is already idempotent.

- [ ] **Step 4: (defense in depth) make the reconciler log-and-continue per entity**

In `pkg/reconciler/reconciler.go`, change the delete failure from aborting the whole pass to skipping that entity, so one bad entity can't wedge the pass. Replace lines 79-82:
```go
		if err := r.cloud.DeleteEntity(ctx, entity.ID); err != nil {
			return result, err
		}
		result.Deleted++
```
with:
```go
		if err := r.cloud.DeleteEntity(ctx, entity.ID); err != nil {
			result.Errors = append(result.Errors, entity.ID)
			continue
		}
		result.Deleted++
```
Add `Errors []string` to the `Result` struct. Add a reconciler-level test (`fakeCloudLister` returns an error for one id) asserting the pass continues and deletes the others. NOTE: check whether any caller asserts on the old abort-on-error behavior (`grep -rn 'Run(' plugins/*/path_reconcile.go plugins/*/workers.go`) and update expectations if needed.

- [ ] **Step 5: run all touched tests green**

```bash
go test -race github.com/nicois/openbao-cloud-creds/pkg/reconciler/ github.com/nicois/openbao-cloud-creds/plugins/credential-do/... github.com/nicois/openbao-cloud-creds/plugins/credential-vultr/... github.com/nicois/openbao-cloud-creds/plugins/credential-exoscale/... github.com/nicois/openbao-cloud-creds/plugins/credential-upcloud/... github.com/nicois/openbao-cloud-creds/plugins/credential-akamai/... 2>&1 | tail -20
```

- [ ] **Step 6: lint + commit**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
for d in pkg/reconciler plugins/credential-do plugins/credential-vultr plugins/credential-exoscale plugins/credential-upcloud plugins/credential-akamai; do (cd $d && gofmt -w . && golangci-lint run ./...) || echo "FAIL $d"; done
git add pkg/reconciler/ plugins/ pkg/credenvelope/fakes/ docs/state-assumption-verification-2026-05-31.md
git commit -m "fix(reconciler): treat upstream 404 as success + log-and-continue per entity (audit F5)"
```

---

## Task 7: Create-then-track compensation (F6)

When issuance creates the upstream credential then fails to persist the `active-tokens/` record, today it only logs a Warn and returns a live-but-untracked credential. Verify, then compensate.

**Files:** one representative plugin first (DO — `path_creds.go`); a test using an InmemStorage that fails Put.

- [ ] **Step 1: assess feasibility + write the verification test**

Read DO `path_creds.go` around the `active-tokens/` Put (the Warn-on-failure site). To force a Put failure, you need a storage that errors on Put. Check whether `logical.InmemStorage` can be wrapped (a failing-storage decorator implementing `logical.Storage` that returns an error from `Put` for keys with a given prefix). Write:
```go
func TestIssue_CompensatesOnTrackingPutFailure(t *testing.T) {
	// backend configured against the DO fake, but with storage whose Put fails
	// for "active-tokens/" keys. Issue a credential. Assert EITHER the request
	// fails (preferred) OR no orphaned upstream token remains (fake.tokenCount
	// unchanged after the failed issue). A live-but-untracked token => REAL bug.
}
```
If wrapping storage is infeasible within the harness, mark F6 **DOCUMENTED-RISK** in the report with the rationale (and skip Steps 2-4). Be honest about feasibility rather than forcing a brittle test.

- [ ] **Step 2: run, confirm current behavior is the bug (if testable)**

Expected: the test shows an upstream token created but untracked after the Put failure → F6 REAL.

- [ ] **Step 3: implement compensation (DO)**

At the Put-failure site in `path_creds.go`, instead of only `Warn`, best-effort revoke the just-created upstream credential and return an error envelope (`credenvelope.ErrInternal`), so the caller never receives an untrackable credential:
```go
	if err := req.Storage.Put(ctx, entry); err != nil {
		// Tracking write failed: revoke the just-minted upstream credential so
		// we never hand out a credential we cannot later revoke/reconcile.
		_, _ = client.DeleteToken(ctx, upstreamID) // best-effort
		b.Logger().Error("failed to persist active-token record; revoked upstream credential", "error", err)
		return credenvelope.ErrorResponse(credenvelope.ErrInternal, "failed to persist credential tracking record"), nil
	}
```
(Adapt field/var names to the real code: the upstream id var, the client var, the delete fn.)

- [ ] **Step 4: run green; decide on other plugins**

Run DO tests. If F6 is confirmed and the fix is clean, apply the same compensation to the other hard-revoke plugins (azure, vultr, exoscale, upcloud, akamai) — same shape, each best-effort-deletes its upstream entity on Put failure. The no-revoke plugins (aws/gcp/ovh) can't revoke (tokens expire), so for those the correct compensation is to return the error envelope WITHOUT a delete (document that the short-lived token will expire on its own).

- [ ] **Step 5: lint + commit**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
# lint each touched plugin
git add plugins/ docs/state-assumption-verification-2026-05-31.md
git commit -m "fix(plugins): compensate (revoke upstream) when active-token tracking write fails (audit F6)"
```

---

## Task 8: GCP/OVH HTTP client timeout (F2)

**Files:** `plugins/credential-gcp/iam_client.go`, `plugins/credential-ovh/token_client.go`.

- [ ] **Step 1: implement — give each a bounded client**

GCP `iam_client.go`: add a package const + client and replace both `http.DefaultClient.Do(req)` (lines ~156, ~208):
```go
const httpTimeout = 30 * time.Second

var httpClient = &http.Client{Timeout: httpTimeout}
```
Replace `http.DefaultClient.Do(req)` → `httpClient.Do(req)` at both sites. (Add `"time"` import if absent.) Same for OVH `token_client.go` (one site, line ~63). Confirm neither file already defines `httpTimeout` (other plugins define it in their *_client.go — these two don't yet).

- [ ] **Step 2: verify build + existing tests green**

```bash
go build github.com/nicois/openbao-cloud-creds/plugins/credential-gcp/... github.com/nicois/openbao-cloud-creds/plugins/credential-ovh/...
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-gcp/... github.com/nicois/openbao-cloud-creds/plugins/credential-ovh/... 2>&1 | tail -10
```
(No new test needed — this is a robustness hardening; the existing fakes use injected clients so behavior is unchanged. Note in the report that F2 fix is verified by build + unchanged test behavior.)

- [ ] **Step 3: lint + commit**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
for p in gcp ovh; do (cd plugins/credential-$p && gofmt -w . && golangci-lint run ./...) || echo "FAIL $p"; done
git add plugins/credential-gcp/ plugins/credential-ovh/ docs/state-assumption-verification-2026-05-31.md
git commit -m "fix(gcp,ovh): bound upstream HTTP calls with a client timeout (audit F2)"
```

---

## Task 9: Azure propagation — DOCUMENTED-RISK (F7)

Graph replication lag for a freshly-added client secret cannot be reproduced against the fake. Per the spec, document it rather than fake a test.

**Files:** `docs/known-issues.md` (append), `docs/state-assumption-verification-2026-05-31.md`, optionally `plugins/credential-azure/path_creds.go` (a doc comment).

- [ ] **Step 1: record the risk**

Append to `docs/known-issues.md` a KI entry: Azure `addPassword` returns a `client_secret` that may fail auth for a few seconds due to Entra/AAD directory replication lag; clients should retry transient 401 (`AADSTS7000215`) immediately after issuance rather than treat it as fatal. Note it self-heals within seconds. Mark verdict **DOCUMENTED-RISK** in the verification report.

- [ ] **Step 2: (optional) add a code comment**

At the Azure secret-return site in `path_creds.go`/`buildEnvelope`, add a brief comment pointing to the KI entry so future readers know the propagation caveat is known and intentional (not an oversight).

- [ ] **Step 3: commit**

```bash
git add docs/known-issues.md docs/state-assumption-verification-2026-05-31.md plugins/credential-azure/
git commit -m "docs: record Azure addPassword propagation as known risk (audit F7)"
```

---

## Task 10: Convert pkg/worker timing tests to synctest (F8)

Replace fixed-`time.Sleep` + tight tick-count assertions with deterministic synctest. The flaky one is `TestWorkerTicks` ([4,6] band); `TestWorkerInitialDelay` is also timing-fragile.

**Files:** `pkg/worker/worker_test.go`. First confirm `pkg/worker/worker.go run()` uses fakeable time primitives.

- [ ] **Step 1: confirm the worker uses fakeable time**

```bash
grep -n 'time.NewTicker\|time.After\|time.Sleep\|time.NewTimer' pkg/worker/worker.go
```
Expected: `time.NewTicker` / `time.After` (both faked by synctest). If it uses something unfakeable, note it; otherwise proceed.

- [ ] **Step 2: rewrite `TestWorkerTicks` under synctest**

```go
import "testing/synctest"

func TestWorkerTicks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var count atomic.Int32
		wm := worker.New()
		wm.Register("counter", 10*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
			count.Add(1)
			return nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		wm.Start(ctx)

		// Advance fake time deterministically: 5 intervals => exactly 5 ticks.
		for i := 0; i < 5; i++ {
			time.Sleep(10 * time.Millisecond)
			synctest.Wait() // let the tick fire and the worker re-block
		}
		cancel()
		wm.Wait()

		if got := count.Load(); got != 5 {
			t.Fatalf("expected exactly 5 ticks, got %d", got)
		}
	})
}
```
(Exact count, not a band — synctest makes it deterministic. Adjust the tick-vs-sleep relationship to match how `run()` schedules: if the ticker fires at the END of each interval, 5 sleeps of one interval = 5 ticks; verify against run() semantics and assert the exact number that holds.)

- [ ] **Step 3: rewrite `TestWorkerInitialDelay` under synctest**

```go
func TestWorkerInitialDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var count atomic.Int32
		wm := worker.New()
		wm.Register("delayed", 10*time.Millisecond, worker.Opts{InitialDelay: 30 * time.Millisecond}, func(ctx context.Context) error {
			count.Add(1)
			return nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		wm.Start(ctx)

		time.Sleep(25 * time.Millisecond)
		synctest.Wait()
		if count.Load() != 0 {
			t.Fatalf("expected 0 ticks during initial delay, got %d", count.Load())
		}

		time.Sleep(10 * time.Millisecond) // now past the 30ms delay
		synctest.Wait()
		if count.Load() < 1 {
			t.Fatalf("expected >=1 tick after delay, got %d", count.Load())
		}
		cancel()
		wm.Wait()
	})
}
```

- [ ] **Step 4: run the worker suite (no -race-flakes, deterministic)**

```bash
go test -race -count=5 github.com/nicois/openbao-cloud-creds/pkg/worker/ 2>&1 | tail -15
```
Expected: PASS all 5 runs (deterministic — `-count=5` proves no flakiness). Leave the panic/error-handler tests (`TestWorker_*`) as-is unless they also flake; the goal is the timing tests. If you also convert those, keep their assertions intact.

- [ ] **Step 5: lint + commit**

```bash
(cd pkg/worker && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add pkg/worker/worker_test.go docs/state-assumption-verification-2026-05-31.md
git commit -m "test(worker): deterministic timing tests via testing/synctest (audit F8)"
```

---

## Task 11: Final verification

**Files:** finalize `docs/state-assumption-verification-2026-05-31.md`.

- [ ] **Step 1: full workspace gates**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
go build github.com/nicois/openbao-cloud-creds/...
go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -30
fail=0
for d in pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/worker pkg/plugintest plugins/credential-akamai plugins/credential-aws plugins/credential-azure plugins/credential-do plugins/credential-exoscale plugins/credential-gcp plugins/credential-oci plugins/credential-ovh plugins/credential-upcloud plugins/credential-vultr; do
  (cd "$d" && golangci-lint run ./... 2>&1 | grep -q '0 issues') || { echo "LINT FAIL $d"; fail=1; }
done
[ $fail -eq 0 ] && echo "ALL LINT CLEAN"
```
Expected: build OK, all tests pass, ALL LINT CLEAN.

- [ ] **Step 2: smoke test still green**

```bash
make smoke-test 2>&1 | tail -5
```

- [ ] **Step 3: finalize the verification report**

Ensure every finding F1–F8 has a final verdict (REAL+fixed / REFUTED / DOCUMENTED-RISK) with its artifact (test name or proof) and the commit that addressed it. This report is the deliverable proving the verify-then-fix discipline was followed.

- [ ] **Step 4: confirm no stray `nolint` and commit the finalized report**

```bash
git diff main..HEAD | grep -nE '^\+.*nolint' || echo "no nolint added"
git add docs/state-assumption-verification-2026-05-31.md
git commit -m "docs: finalize state-assumption verification report"
```

---

## Self-review notes (for the executor)

- **The gate is real:** Tasks 2, 6, 7 begin with a test that must FAIL to confirm the finding. If a test can't be made to fail (F4, F6 especially), the finding is REFUTED or DOCUMENTED-RISK — record that and skip the fix. Do not fabricate a fix for a green test.
- **Task 3 before Task 4, always:** Task 3 makes the worker reconcile fail-closed (pauses orphan deletion on the worker path); Task 4 restores precise deletion via real timestamps. Shipping Task 3 without Task 4 is safe-but-incomplete (orphans leak); never ship Task 4 without Task 3 (would re-open the delete-live-credential window for zero-timestamp clouds).
- **Dependency order:** Task 1 (report) → Task 2 (OCI verify) → Tasks 3-10 (fixes, mostly independent; 3 before 4; 5 depends on 2's verdict) → Task 11 (final).
- **CI fixes are already on main** (`bdcb5a1`, pending push) — not part of this branch.
- Trust the LIVE test/grep output over the line numbers in this plan; the lint upgrade may have shifted lines. Always read the real code before editing.
