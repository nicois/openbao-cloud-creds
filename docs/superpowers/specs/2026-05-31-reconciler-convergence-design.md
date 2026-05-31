# Reconciler Convergence (Audit #5) — Design Spec

**Status:** Approved (2026-05-31)
**Goal:** Close the real correctness gap and the genuine duplication behind audit item #5, after verifying which of the audit's claims still hold.

## Scope

This is audit item **#5 only**. Audit #7 (the broad ×10 telemetry/workers/health-check de-dup) is a separate brainstorm→plan→execute cycle, explicitly out of scope here.

## Verification of the audit's claims (the audit text predates recent work)

Audit #5 (`docs/audit-2026-05-31.md`) made three claims. Re-verified against current `main`:

- **Claim A — OCI dead code `now := time.Now(); _ = now`:** STALE. Removed during the golangci-lint upgrade. No action.
- **Claim B — DO manual `pathReconcile` hardcodes `ConfirmationHold: 0` while the worker uses `1h`:** TRUE, and sharper post-F1. Our F1 fail-closed guard only engages when `ConfirmationHold > 0`; the manual path's hardcoded `0` therefore skips the guard entirely and deletes *any* matching orphan regardless of age — including a credential issued seconds earlier, still inside its create-then-track window. All 6 hard-revoke plugins' manual paths share this. **Fixed** (Section 1).
- **Claim C — "route OCI/AWS through `pkg/reconciler`":** REINTERPRETED. Verification found three genuinely distinct reconcile shapes, so the literal fix doesn't fit:
  1. **6 hard-revoke plugins** (do/azure/vultr/exoscale/upcloud/akamai): already use `pkg/reconciler` — list upstream by owner-tag, delete orphaned *upstream* entities.
  2. **AWS/GCP/OVH (no-revoke):** byte-identical inline loops that prune *local* `active-tokens/` storage entries past `expires_at`. No cloud lister, no upstream delete. Forcing these into `pkg/reconciler` (built around `ListTaggedEntities`/`DeleteEntity`) would be a leaky abstraction — they have nothing upstream to reconcile.
  3. **OCI (phased rotation):** slot-based upstream-token reconcile, just reworked under F4 (`runReconcilePass`, `rotateReconcileMu`). Leave as-is.
  So Claim C becomes: de-dup the identical AWS/GCP/OVH local-expiry pruner into one shared helper (Section 2); do NOT bend `pkg/reconciler`; do NOT touch OCI.

## Section 1 — Manual-reconcile `ConfirmationHold` floor

**Problem:** operator-triggered `/reconcile` on the 6 hard-revoke plugins hardcodes `ConfirmationHold: 0`, which (post-F1) disables the grace guard and can delete a just-issued credential.

**Fix — floor the operator-facing hold; preserve library semantics:**

- **Shared constant** in `pkg/reconciler`: `const MinConfirmationHold = 5 * time.Minute`. This is comfortably larger than the create-then-track window (a sub-second upstream round-trip) while still allowing far more aggressive cleanup than the 1h worker default.
- **The floor is applied at the operator call site, NOT globally in the library.** Library `ConfirmationHold == 0` retains its existing meaning — "guard disabled entirely" — which the worker path and the existing `pkg/reconciler` tests rely on. Clamping `0→5m` inside `Run` would change every existing `ConfirmationHold: 0` caller's semantics. So `Run` is unchanged; only the per-plugin manual handler floors its input.
- **Per-plugin manual `/reconcile` handler** (all 6 hard-revoke plugins):
  - Add a `confirmation_hold` field (`framework.TypeDurationSecond`, **default = the worker hold, `1h`**).
  - Compute `effective := requested; if effective < reconciler.MinConfirmationHold { effective = reconciler.MinConfirmationHold }`. So `0`, `30s`, `1m` → `5m`; `10m`, `1h` pass through. The operator can never request a hold below the floor (the footgun is removed).
  - Pass `effective` into `reconciler.Config.ConfirmationHold` (replacing the hardcoded `0`).
  - **Surface it:** add `"confirmation_hold": effective.String()` to the response map (shown in dry-run preview too), and log at INFO when a requested value was raised to the floor, so an operator who passed `0` is not surprised that `5m` took effect.
  - `mode=normal|dry_run` is unchanged (orthogonal: preview vs apply).

**Touch:** `pkg/reconciler/reconciler.go` (the const), and `path_reconcile.go` in do/azure/vultr/exoscale/upcloud/akamai (the field + floor + response key). The worker path (`workers.go`, `ConfirmationHold: 1h`) is already correct — unchanged.

## Section 2 — Shared local-expiry pruner for AWS/GCP/OVH

**Problem:** AWS, GCP, OVH have byte-identical manual `pathReconcile` bodies (and the same loop in their reconcile workers): List `active-tokens/`, Get each, parse `expires_at`, delete the storage entry if `now.After(expiresAt)`; `mode=normal|dry_run`. This is local-storage pruning of naturally-expired records — a different operation from `pkg/reconciler`.

**Fix — extract one shared helper:**

- **New shared package** `pkg/localexpiry` with:
  ```go
  // Result reports a prune pass.
  type Result struct {
      Scanned int
      Expired []string // keys (relative to prefix) past expires_at
      Deleted int
  }

  // PruneExpired lists `prefix`, reads each entry's stored "expires_at"
  // (RFC3339), and deletes entries already past `now`. dryRun previews
  // without deleting. A malformed/missing expires_at is skipped (not an
  // error). Delete failures are logged and counted-as-not-deleted, not
  // fatal (one bad entry does not abort the pass).
  func PruneExpired(ctx context.Context, storage logical.Storage, prefix string,
      now time.Time, dryRun bool, log hclog.Logger) (Result, error)
  ```
- The three plugins' manual `pathReconcile` collapse to: parse `mode`, call `localexpiry.PruneExpired(ctx, req.Storage, "active-tokens/", time.Now(), dryRun, b.Logger())`, format the response (`mode`, `dry_run`, `scanned`, `expired`/`orphans_found`, `deleted`). The reconcile *worker* loop in each plugin's `workers.go` routes through the same helper.
- Behavior must be **identical** to today — the existing `path_reconcile_test.go` for aws/gcp/ovh are the regression guard and must pass unchanged.

**Touch:** new `pkg/localexpiry/`, and `path_reconcile.go` + `workers.go` in aws/gcp/ovh. OCI is NOT touched.

## Section 3 — Testing, risk, success criteria

**Verification-first:** the three audit claims each get a recorded verdict in the verification notes / spec (done above: A stale-dropped, B fixed, C reinterpreted). No fixing of stale/misframed claims.

**Testing:**
- **Section 1:** `pkg/reconciler` test asserting `MinConfirmationHold == 5*time.Minute`. A representative full test in DO: `confirmation_hold=0` → effective `5m` → a 1-minute-old orphan is NOT deleted, a 10-minute-old orphan IS; default (no field) applies `1h`; explicit `30m` passes through; response echoes the effective hold. The other 5 hard-revoke plugins get a lighter assertion (field present, sub-floor request clamps) since the floor logic is shared via the const.
- **Section 2:** table tests on `localexpiry.PruneExpired` (expired→deleted, unexpired→kept, dry-run→no delete, malformed/missing `expires_at`→skipped, delete-error→counted not fatal). aws/gcp/ovh each keep a thin handler-wiring test; their existing `path_reconcile_test.go` must pass unchanged.

**Risk:**
- Section 1 re-touches the delete-safety invariant but strictly *tightens* it: operator requests are floored, the default is now the safe worker hold, and library `0`-means-disabled is untouched. It can only delete *less* than before, never more (same safety direction as F1). The shared const prevents per-cloud drift.
- Section 2 is behavior-preserving extraction; the unchanged existing tests are the guard.

**Success criteria:**
1. Audit #5's three claims each have a recorded verdict (A stale, B fixed, C reinterpreted).
2. Manual `/reconcile` on all 6 hard-revoke plugins: defaults to the `1h` worker hold, floors operator-requested holds at `reconciler.MinConfirmationHold` (5m, including `0`), surfaces the effective hold, and a sub-floor request provably will not delete a recent orphan.
3. AWS/GCP/OVH manual + worker reconcile route through one shared `pkg/localexpiry` pruner; their existing reconcile tests pass unchanged.
4. OCI reconcile untouched.
5. Whole workspace: `go build`, `go test -race`, `make lint`, `make smoke-test` green; all 17 modules 0 lint issues; CI green after merge (the new `pkg/localexpiry` module added to the lint + govulncheck loops + go.work).

**Out of scope:** audit #7 (broad ×10 de-dup); the worker reconcile hold (already correct); OCI reconcile; any change to `pkg/reconciler.Run`'s `ConfirmationHold==0` semantics.

## New-module checklist (pkg/localexpiry)

Adding a Go module requires wiring it into the workspace and CI:
- `pkg/localexpiry/go.mod` (module path `github.com/nicois/openbao-cloud-creds/pkg/localexpiry`), added to `go.work`.
- Added to the Makefile `LINT_DIRS` and the CI lint + govulncheck per-module loops in `.github/workflows/ci.yml`.
- (If it only imports the OpenBao SDK + hclog, its deps already exist in the workspace.)
