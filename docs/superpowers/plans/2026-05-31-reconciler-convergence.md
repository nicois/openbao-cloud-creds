# Reconciler Convergence (Audit #5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Floor the operator-facing manual-reconcile confirmation hold (remove the post-F1 delete-a-just-issued-credential footgun) across the 6 hard-revoke plugins, and de-duplicate the byte-identical AWS/GCP/OVH local-expiry pruner into one shared `pkg/localexpiry` package.

**Architecture:** Section 1 adds a shared `reconciler.MinConfirmationHold` const and floors operator-requested holds at the per-plugin call site (library `ConfirmationHold==0`-means-disabled semantics untouched). Section 2 extracts the identical AWS/GCP/OVH "prune expired local active-tokens entries" loop (manual + worker) into `pkg/localexpiry.PruneExpired`. OCI is not touched.

**Tech Stack:** Go 1.26.1 workspace, OpenBao SDK v2 (`framework`/`logical`, `b.Logger()` returns `hclog.Logger`), golangci-lint v2.12.2.

**Reference spec:** `docs/superpowers/specs/2026-05-31-reconciler-convergence-design.md`

---

## How to work this plan

- **Worktree:** all work on one branch (created by the execution skill). Never touch `main`. Confirm `git branch --show-current` before every commit. Commit messages end with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.
- **Build/test (full module path, NOT `./...`):**
  ```bash
  go build github.com/nicois/openbao-cloud-creds/...
  go test -race github.com/nicois/openbao-cloud-creds/...
  ```
- **Per-module lint:** `export PATH="$(go env GOPATH)/bin:$PATH"; (cd <module> && golangci-lint run ./...)`
- **Amend rule:** there is a local `prepare-commit-msg` hook that blocks `git commit --amend` of a commit already on a remote. Within this worktree branch (unpushed) amends are fine; the hook permits them.
- Trust the LIVE code over line numbers in this plan (other branches may have shifted lines). Read before editing.

---

## Task 1: `reconciler.MinConfirmationHold` constant + test

**Files:**
- Modify: `pkg/reconciler/reconciler.go`
- Test: `pkg/reconciler/reconciler_test.go`

- [ ] **Step 1: Write the failing test**

Append to `pkg/reconciler/reconciler_test.go`:
```go
func TestMinConfirmationHold(t *testing.T) {
	if reconciler.MinConfirmationHold != 5*time.Minute {
		t.Fatalf("MinConfirmationHold: expected 5m, got %v", reconciler.MinConfirmationHold)
	}
}
```

- [ ] **Step 2: Run, confirm it fails to compile**

```bash
go test -run TestMinConfirmationHold github.com/nicois/openbao-cloud-creds/pkg/reconciler/ 2>&1 | tail -6
```
Expected: build failure `undefined: reconciler.MinConfirmationHold`.

- [ ] **Step 3: Add the constant**

In `pkg/reconciler/reconciler.go`, after the imports / near the `Config` type, add:
```go
// MinConfirmationHold is the floor for an operator-requested confirmation hold
// on the manual reconcile path. A hold shorter than this (including zero) would
// re-expose the create-then-track window that the fail-closed guard protects
// against, so operator-facing callers clamp their requested hold up to this
// value. NOTE: this floor is applied by callers (the manual /reconcile
// handlers), NOT inside Run — Run's ConfirmationHold==0 still means "guard
// disabled" for internal/worker use and existing tests.
const MinConfirmationHold = 5 * time.Minute
```
(`time` is already imported in reconciler.go.)

- [ ] **Step 4: Run, confirm pass**

```bash
go test -race github.com/nicois/openbao-cloud-creds/pkg/reconciler/ 2>&1 | tail -6
```
Expected: all pass (existing tests + the new one). The const does NOT change `Run` behavior — confirm the F1 tests (`TestRun_FailsClosedWhenAgeUnconfirmable` etc.) still pass.

- [ ] **Step 5: Lint + commit**

```bash
(cd pkg/reconciler && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add pkg/reconciler/
git commit -m "$(printf 'feat(reconciler): add MinConfirmationHold floor constant (audit #5)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2: Floor the manual-reconcile hold in `credential-do` (reference)

DO is the reference; Tasks 3–7 replicate this for the other 5 hard-revoke plugins.

**Files:**
- Modify: `plugins/credential-do/path_reconcile.go`
- Test: `plugins/credential-do/path_reconcile_test.go` (or the existing reconcile test file — confirm with `ls plugins/credential-do/*reconcile*test*`)

Current DO `pathReconcile` (read it first) accepts only `mode`, and hardcodes `reconciler.Config{... ConfirmationHold: 0 ...}`.

- [ ] **Step 1: Write the failing tests**

Add to DO's reconcile test file. These need a backend + DO fake that can produce an orphan of a controlled age (the F1/Task-4 work added `created_at` to the DO fake — reuse that helper, e.g. `AddRawTokenWithCreatedAt` or whatever the fake exposes; read `plugins/credential-do/created_at_test.go` for the exact helper name and the lister/backend setup pattern, and mirror it):
```go
// Sub-floor request (0) must clamp to MinConfirmationHold (5m), so a
// 1-minute-old orphan is NOT deleted even on a "force" manual reconcile.
func TestPathReconcile_FloorsSubMinHold(t *testing.T) {
	// setup: backend + DO fake with one cloud-creds-prefixed orphan whose
	// upstream created_at is 1 minute ago, NOT in active-tokens/ (so it's an orphan).
	// issue an UpdateOperation on "reconcile" with confirmation_hold=0, mode=normal.
	// assert: resp.Data["deleted"] == 0, resp.Data["confirmation_hold"] == "5m0s",
	//         and the orphan still exists upstream (fake count unchanged).
}

// An orphan older than the floor IS deleted (cleanup still works).
func TestPathReconcile_DeletesOldOrphanAboveFloor(t *testing.T) {
	// orphan created 10 minutes ago, confirmation_hold=0 (→5m).
	// assert deleted == 1 (10m > 5m floor).
}

// Default (no confirmation_hold field) applies the 1h worker hold.
func TestPathReconcile_DefaultHoldIsOneHour(t *testing.T) {
	// orphan created 10 minutes ago, NO confirmation_hold field, mode=normal.
	// assert deleted == 0 (10m < 1h default) and resp.Data["confirmation_hold"] == "1h0m0s".
}
```
Write these against the REAL setup helpers in the existing DO reconcile/created_at tests — read those files and reuse their backend+fake construction verbatim. Use the fake's age-controlled-orphan helper to set `created_at`.

- [ ] **Step 2: Run, confirm they fail**

```bash
go test -run 'TestPathReconcile_FloorsSubMinHold|TestPathReconcile_DeletesOldOrphanAboveFloor|TestPathReconcile_DefaultHoldIsOneHour' github.com/nicois/openbao-cloud-creds/plugins/credential-do/ -v 2>&1 | tail -20
```
Expected: FloorsSubMinHold and DefaultHoldIsOneHour FAIL (current code: no `confirmation_hold` field; `ConfirmationHold: 0` deletes any-age orphan; no `confirmation_hold` in response). DeletesOldOrphanAboveFloor may pass-by-accident (current code deletes it anyway). The first two failing is the bug.

- [ ] **Step 3: Implement the floor in `pathReconcile`**

In `plugins/credential-do/path_reconcile.go`:

3a. Add the `confirmation_hold` field to the path's `Fields` map (alongside `mode`):
```go
				"confirmation_hold": {
					Type:        framework.TypeDurationSecond,
					Default:     int(time.Hour.Seconds()),
					Description: "Grace period (seconds) below which a recently-created orphan is not deleted. Operator requests are floored at the reconciler minimum (5m). Default: the worker hold (1h).",
				},
```

3b. In the handler, replace the hardcoded `ConfirmationHold: 0` with a floored value derived from the field:
```go
	mode := d.Get("mode").(string)
	dryRun := mode == "dry_run"

	requestedHold := time.Duration(d.Get("confirmation_hold").(int)) * time.Second
	effectiveHold := requestedHold
	if effectiveHold < reconciler.MinConfirmationHold {
		b.Logger().Info("manual reconcile: raising requested confirmation_hold to the floor",
			"requested", requestedHold.String(), "floor", reconciler.MinConfirmationHold.String())
		effectiveHold = reconciler.MinConfirmationHold
	}
```
Then in the `reconciler.Config{...}` literal, set `ConfirmationHold: effectiveHold` (was `0`).

3c. Add the effective hold to the response `Data` map:
```go
			"confirmation_hold": effectiveHold.String(),
```
(Confirm `time` is imported in path_reconcile.go — it is, for `time.Now()`.)

- [ ] **Step 4: Run, confirm green**

```bash
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-do/... 2>&1 | tail -15
```
Expected: the three new tests pass; all existing DO tests pass (the existing reconcile test used `mode` only — `confirmation_hold` defaulting to 1h must not break it; if an existing test asserted an orphan IS deleted by manual reconcile without setting a hold, it will now need `confirmation_hold=0` or a >floor-age orphan — update that test to pass the field, preserving its intent, and note it).

- [ ] **Step 5: Lint + commit**

```bash
(cd plugins/credential-do && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add plugins/credential-do/
git commit -m "$(printf 'fix(do): floor manual-reconcile confirmation_hold at 5m (audit #5)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Tasks 3–7: Floor the manual-reconcile hold in the other 5 hard-revoke plugins

Each of azure, vultr, exoscale, upcloud, akamai gets the **exact Task 2 change** (3a/3b/3c) in its `path_reconcile.go`. The handler shape is identical to DO's (confirm per plugin — each currently hardcodes `ConfirmationHold: 0`). Per plugin:

1. Read that plugin's `path_reconcile.go` + its reconcile/created_at test file for the setup helper.
2. Apply 3a (add `confirmation_hold` field), 3b (floor logic), 3c (response key) — identical code to Task 2.
3. Add a **lighter** test (the floor logic is shared, so one assertion suffices): `TestPathReconcile_FloorsSubMinHold` — `confirmation_hold=0` → `resp.Data["confirmation_hold"] == "5m0s"` and a 1-minute-old orphan is NOT deleted. Use that plugin's fake age-controlled-orphan helper (azure/akamai/upcloud got `created_at` helpers in the F1/Task-4 work; vultr/exoscale did NOT get `created_at` on their fakes — see note below).
4. Run `go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-<p>/...` green (fix any existing reconcile test that assumed immediate deletion, preserving intent).
5. Lint that plugin + commit `fix(<p>): floor manual-reconcile confirmation_hold at 5m (audit #5)`.

### Task 3: credential-azure
- Azure's fake has `startDateTime` (the created_at equivalent, added in Task 4 of the prior effort). Use its age-controlled-orphan helper.

### Task 4: credential-vultr
- **Vultr's list API has no creation timestamp** (per the prior effort — it relies on fail-closed, KI-004). So a Vultr orphan always has zero `CreatedAt`. Under the floored hold (≥5m), a zero-CreatedAt orphan is ALWAYS skipped (fail-closed). So the test for vultr asserts: `confirmation_hold=0` → `"5m0s"` in response AND the orphan is NOT deleted (because zero CreatedAt + hold>0 = skip). This is correct and even safer. Note in the commit that vultr manual reconcile now never deletes (consistent with KI-004); the operator path for vultr orphans is moot — document it.

### Task 5: credential-exoscale
- Same as vultr: **no list timestamp** (KI-004, fail-closed). Same test shape and same note.

### Task 6: credential-upcloud
- UpCloud's fake has `created` (added in Task 4). Use its age-controlled-orphan helper.

### Task 7: credential-akamai
- Akamai's fake has `createdDate` (added in Task 4). Use its age-controlled-orphan helper.

> **Cross-plugin note for the executor:** vultr/exoscale (Tasks 4/5) will show that flooring the hold makes their manual reconcile stop deleting orphans entirely (zero CreatedAt → always skipped under a >0 hold). That is the correct, KI-004-consistent outcome — the manual path was the documented escape hatch for those two, and the floor closes it. Surface this in those two commit messages and in the verification notes (Task 10) so it is a recorded, deliberate consequence, not a surprise. If the team wants an escape hatch for vultr/exoscale orphan cleanup, that is a separate decision (out of scope here — the safe default wins).

---

## Task 8: Create `pkg/localexpiry` shared pruner

**Files:**
- Create: `pkg/localexpiry/go.mod`, `pkg/localexpiry/localexpiry.go`, `pkg/localexpiry/localexpiry_test.go`
- Modify: `go.work`

- [ ] **Step 1: Create the module + wire into workspace**

```bash
mkdir -p pkg/localexpiry
cat > pkg/localexpiry/go.mod <<'EOF'
module github.com/nicois/openbao-cloud-creds/pkg/localexpiry

go 1.26.1
EOF
```
Add `./pkg/localexpiry` to the `use (...)` block in `go.work` (alphabetically, after `./pkg/credenvelope` group — keep the existing ordering: it goes between `./pkg/credenvelope` and `./pkg/metrics`... actually place it after `./pkg/credenvelope` to keep alpha order: cloudconfig, credenvelope, localexpiry, metrics, plugintest, reconciler, recovery, worker).

The helper imports the OpenBao SDK (`logical`) and hclog. Those are already in the workspace; run `go mod tidy` in the module after writing the code (Step 3) to populate its go.mod requires.

- [ ] **Step 2: Write the failing test**

`pkg/localexpiry/localexpiry_test.go`:
```go
package localexpiry_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nicois/openbao-cloud-creds/pkg/localexpiry"
)

func put(t *testing.T, s logical.Storage, key, expiresAt string) {
	t.Helper()
	e, err := logical.StorageEntryJSON("active-tokens/"+key, map[string]interface{}{"expires_at": expiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(context.Background(), e); err != nil {
		t.Fatal(err)
	}
}

func TestPruneExpired_DeletesPastEntries(t *testing.T) {
	s := &logical.InmemStorage{}
	now := time.Now()
	put(t, s, "old", now.Add(-time.Hour).Format(time.RFC3339))
	put(t, s, "fresh", now.Add(time.Hour).Format(time.RFC3339))

	res, err := localexpiry.PruneExpired(context.Background(), s, "active-tokens/", now, false, hclog.NewNullLogger())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 1 {
		t.Fatalf("expected 1 deleted, got %d", res.Deleted)
	}
	if len(res.Expired) != 1 || res.Expired[0] != "old" {
		t.Fatalf("expected [old] expired, got %v", res.Expired)
	}
	// fresh must survive
	if e, _ := s.Get(context.Background(), "active-tokens/fresh"); e == nil {
		t.Fatal("fresh entry was wrongly deleted")
	}
	if e, _ := s.Get(context.Background(), "active-tokens/old"); e != nil {
		t.Fatal("old entry was not deleted")
	}
}

func TestPruneExpired_DryRunDeletesNothing(t *testing.T) {
	s := &logical.InmemStorage{}
	now := time.Now()
	put(t, s, "old", now.Add(-time.Hour).Format(time.RFC3339))

	res, err := localexpiry.PruneExpired(context.Background(), s, "active-tokens/", now, true, hclog.NewNullLogger())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 0 {
		t.Fatalf("dry-run: expected 0 deleted, got %d", res.Deleted)
	}
	if len(res.Expired) != 1 {
		t.Fatalf("dry-run: expected 1 expired-found, got %d", len(res.Expired))
	}
	if e, _ := s.Get(context.Background(), "active-tokens/old"); e == nil {
		t.Fatal("dry-run must not delete")
	}
}

func TestPruneExpired_SkipsMalformedTimestamp(t *testing.T) {
	s := &logical.InmemStorage{}
	now := time.Now()
	put(t, s, "bad", "not-a-timestamp")
	put(t, s, "missing", "") // empty expires_at

	res, err := localexpiry.PruneExpired(context.Background(), s, "active-tokens/", now, false, hclog.NewNullLogger())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 0 || len(res.Expired) != 0 {
		t.Fatalf("malformed/empty must be skipped, got deleted=%d expired=%d", res.Deleted, len(res.Expired))
	}
}
```

- [ ] **Step 3: Implement the helper**

`pkg/localexpiry/localexpiry.go`:
```go
// Package localexpiry prunes local tracking-storage entries whose recorded
// expiry has passed. It is used by no-revoke plugins (AWS/GCP/OVH) whose
// upstream credentials expire on their own, so reconciliation is purely a
// local-storage cleanup — distinct from pkg/reconciler, which deletes orphaned
// UPSTREAM entities.
package localexpiry

import (
	"context"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Result reports a prune pass.
type Result struct {
	Scanned int      // entries listed under the prefix
	Expired []string // keys (relative to prefix) whose expires_at is past `now`
	Deleted int      // entries actually deleted (0 when dryRun)
}

// PruneExpired lists entries under prefix, reads each entry's stored
// "expires_at" (RFC3339), and deletes those already past `now`. A missing or
// malformed expires_at, or an unreadable entry, is skipped (not an error).
// dryRun reports what would be deleted without deleting. A delete failure is
// logged and counted as not-deleted; it does not abort the pass.
func PruneExpired(ctx context.Context, storage logical.Storage, prefix string, now time.Time, dryRun bool, log hclog.Logger) (Result, error) {
	keys, err := storage.List(ctx, prefix)
	if err != nil {
		return Result{}, err
	}
	res := Result{Scanned: len(keys)}
	for _, key := range keys {
		entry, err := storage.Get(ctx, prefix+key)
		if err != nil || entry == nil {
			continue
		}
		var data map[string]interface{}
		if err := entry.DecodeJSON(&data); err != nil {
			continue
		}
		expiresStr, ok := data["expires_at"].(string)
		if !ok || expiresStr == "" {
			continue
		}
		expiresAt, err := time.Parse(time.RFC3339, expiresStr)
		if err != nil || !now.After(expiresAt) {
			continue
		}
		res.Expired = append(res.Expired, key)
		if dryRun {
			continue
		}
		if err := storage.Delete(ctx, prefix+key); err != nil {
			if log != nil {
				log.Warn("localexpiry: failed to delete expired entry", "key", key, "error", err)
			}
			continue
		}
		res.Deleted++
	}
	return res, nil
}
```

- [ ] **Step 4: tidy, run, confirm pass**

```bash
(cd pkg/localexpiry && go mod tidy && go test -race ./... 2>&1 | tail -10)
```
Expected: go.mod/go.sum populated with the SDK + hclog requires; all three tests pass.

- [ ] **Step 5: workspace builds with the new module**

```bash
go build github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -5; echo "build: $?"
```

- [ ] **Step 6: Lint + commit**

```bash
(cd pkg/localexpiry && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add pkg/localexpiry/ go.work go.work.sum
git commit -m "$(printf 'feat(localexpiry): shared pruner for expired local tracking entries (audit #5)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 9: Route AWS/GCP/OVH reconcile (manual + worker) through `pkg/localexpiry`

The three plugins' manual `pathReconcile` and `reconcileWorker` bodies are byte-identical (modulo comments/whitespace — verified). Replace both with calls to the shared helper, preserving the EXACT response keys so existing tests pass.

**Files (×3):** `plugins/credential-{aws,gcp,ovh}/path_reconcile.go`, `plugins/credential-{aws,gcp,ovh}/workers.go`, each module's `go.mod` (add the localexpiry require).

Do AWS first (reference), then gcp/ovh identically.

- [ ] **Step 1: AWS — rewrite `pathReconcile` body to call the helper**

In `plugins/credential-aws/path_reconcile.go`, replace the manual list/parse/delete block (lines ~35–72) with:
```go
	mode := d.Get("mode").(string)
	dryRun := mode == "dry_run"

	res, err := localexpiry.PruneExpired(ctx, req.Storage, "active-tokens/", time.Now(), dryRun, b.Logger())
	if err != nil {
		return logical.ErrorResponse("reconcile failed: %v", err), nil
	}

	emitOrphansFound(len(res.Expired))

	return &logical.Response{
		Data: map[string]interface{}{
			"mode":             mode,
			"dry_run":          dryRun,
			"expired_found":    len(res.Expired),
			"deleted":          res.Deleted,
			"active_remaining": res.Scanned - res.Deleted,
		},
	}, nil
```
Add the import `"github.com/nicois/openbao-cloud-creds/pkg/localexpiry"`. Remove the now-unused `"time"` import ONLY if `time.Now()` is no longer referenced — it still is (passed to PruneExpired), so keep `time`. The response keys (`mode/dry_run/expired_found/deleted/active_remaining`) are unchanged — this preserves the existing test assertions.

- [ ] **Step 2: AWS — rewrite `reconcileWorker` to call the helper**

In `plugins/credential-aws/workers.go`, replace the `reconcileWorker` body (the list/parse/delete loop) with:
```go
func (b *backend) reconcileWorker(ctx context.Context, storage logical.Storage) error {
	res, err := localexpiry.PruneExpired(ctx, storage, "active-tokens/", time.Now(), false, b.Logger())
	if err != nil {
		return err
	}
	emitOrphansFound(len(res.Expired))
	return nil
}
```
Add the localexpiry import. Confirm `time` and `logical` are still used elsewhere in the file (they are — other workers); if `reconcileWorker` was the only `time` user, keep it (PruneExpired arg uses `time.Now()`). Run `goimports`/`gofmt` to drop any genuinely-unused import.

- [ ] **Step 3: AWS — add the module require + build**

```bash
(cd plugins/credential-aws && go mod tidy)
go build github.com/nicois/openbao-cloud-creds/plugins/credential-aws/... 2>&1 | tail -3
```
`go mod tidy` adds the `pkg/localexpiry` require (resolved via go.work).

- [ ] **Step 4: AWS — existing tests pass unchanged (regression guard)**

```bash
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-aws/... 2>&1 | tail -12
```
Expected: the existing `path_reconcile_test.go` (asserts `dry_run`, `expired_found`) passes WITHOUT modification — proves behavior preserved. If it fails, the response keys or semantics drifted; fix to match the original exactly. Add a small new test only if a worker-path assertion is missing; otherwise the existing test is the guard.

- [ ] **Step 5: GCP + OVH — identical treatment**

Repeat Steps 1–4 for `plugins/credential-gcp` and `plugins/credential-ovh`: replace `pathReconcile` body + `reconcileWorker` body with the same two helper calls, add the import + `go mod tidy`, confirm their existing reconcile tests pass unchanged. The bodies are identical to AWS's, so the replacement is identical.

- [ ] **Step 6: workspace build + test + lint all three**

```bash
go build github.com/nicois/openbao-cloud-creds/... && go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-aws/... github.com/nicois/openbao-cloud-creds/plugins/credential-gcp/... github.com/nicois/openbao-cloud-creds/plugins/credential-ovh/... 2>&1 | tail -15
export PATH="$(go env GOPATH)/bin:$PATH"
for p in aws gcp ovh; do (cd plugins/credential-$p && gofmt -w . && golangci-lint run ./...) || echo "FAIL $p"; done
```

- [ ] **Step 7: Commit**

```bash
git add plugins/credential-aws/ plugins/credential-gcp/ plugins/credential-ovh/
git commit -m "$(printf 'refactor(aws,gcp,ovh): route reconcile through pkg/localexpiry (audit #5)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 10: Wire `pkg/localexpiry` into CI + Makefile; full verification + notes

**Files:**
- Modify: `Makefile` (LINT_DIRS), `.github/workflows/ci.yml` (lint + govulncheck loops)
- Modify/append: a short verification note (append to the spec or a `docs/` note recording the audit #5 outcome)

- [ ] **Step 1: Add `pkg/localexpiry` to the lint/govulncheck loops**

In `Makefile`, add `pkg/localexpiry` to `LINT_DIRS` (after `pkg/cloudconfig` or `pkg/worker` — match the existing list ordering).
In `.github/workflows/ci.yml`, add `pkg/localexpiry` to BOTH per-module loops (the Lint loop ~line 41 and the govulncheck loop ~line 64), keeping the same line-continuation formatting.

- [ ] **Step 2: Confirm the loops include it**

```bash
grep -c 'pkg/localexpiry' Makefile .github/workflows/ci.yml
python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/ci.yml')); print('jobs:', list(d['jobs'].keys()))"
```
Expected: Makefile 1, ci.yml 2 (both loops); yaml parses.

- [ ] **Step 3: Full-workspace gate**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
go build github.com/nicois/openbao-cloud-creds/...
go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -30
fail=0
for d in pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/worker pkg/plugintest pkg/localexpiry \
         plugins/credential-akamai plugins/credential-aws plugins/credential-azure plugins/credential-do \
         plugins/credential-exoscale plugins/credential-gcp plugins/credential-oci plugins/credential-ovh \
         plugins/credential-upcloud plugins/credential-vultr; do
  (cd "$d" && golangci-lint run ./... 2>&1 | grep -q '0 issues') || { echo "LINT FAIL $d"; fail=1; }
done
[ $fail -eq 0 ] && echo "ALL 18 MODULES CLEAN"
make lint 2>&1 | tail -3
make smoke-test 2>&1 | tail -4
```
Expected: build OK, all tests pass, ALL 18 MODULES CLEAN (17 + the new localexpiry), make lint exit 0, smoke test green.

- [ ] **Step 4: Update the audit doc + record outcome**

In `docs/audit-2026-05-31.md`, mark item #5 `— [RESOLVED 2026-05-31]` with a `**Resolved:**` paragraph mirroring the existing resolved items: note the three claims' verdicts (A stale/already-removed, B fixed via `reconciler.MinConfirmationHold` floor on all 6 hard-revoke manual paths, C reinterpreted — AWS/GCP/OVH de-duped into `pkg/localexpiry`, OCI left as-is), and the vultr/exoscale consequence (manual reconcile now fail-closed for them, KI-004-consistent).

- [ ] **Step 5: No stray nolint; commit**

```bash
git diff main..HEAD | grep -nE '^\+.*nolint' || echo "no nolint added"
git add Makefile .github/workflows/ci.yml docs/audit-2026-05-31.md
git commit -m "$(printf 'ci+docs: wire pkg/localexpiry into lint/govulncheck; mark audit #5 resolved\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Self-review notes (for the executor)

- **Task ordering:** Task 1 (const) before Tasks 2–7 (they reference `reconciler.MinConfirmationHold`). Task 8 (localexpiry) before Task 9 (consumers). Task 10 last (CI wiring needs the module to exist).
- **The vultr/exoscale subtlety (Tasks 4/5):** flooring the hold makes their manual reconcile stop deleting (zero CreatedAt + hold>0 → fail-closed skip). This is correct and KI-004-consistent — record it, don't "fix" it.
- **Behavior preservation is the bar for Task 9:** the existing aws/gcp/ovh reconcile tests must pass UNCHANGED. If you must touch them, you changed behavior — revert and match the original response exactly.
- **Don't touch OCI** reconcile (its own model, reworked under F4) or the worker reconcile hold (already 1h, correct).
- **New module = CI breakage risk:** Task 10 wiring (go.work done in Task 8; Makefile + ci.yml here) is mandatory — a module missing from `make lint`/govulncheck loops is exactly the gap a prior task caught for `pkg/plugintest`.
- Trust live code over plan line numbers; read before editing.
