# Resilience Test Taxonomy — Design Spec

**Status:** Approved (2026-05-30)
**Scope:** New shared `pkg/plugintest` package + a `resilience_test.go` per plugin (×10) + uniform fake accessors + the KI-001/KI-002 fixes that the new tests turn green.

## Motivation

Two production bugs (KI-001, KI-002 in `docs/known-issues.md`) found during live raft-failover testing share one root cause: **every existing test exercises a freshly-configured, never-perturbed backend.** Concretely, across all 10 plugins:

- No test re-instantiates a backend from already-populated storage without a config write (the failover/reload path → KI-001).
- No test mutates config/minter-sets/roles while leases are outstanding (the re-seed/rebind path → KI-002).
- Cloud fakes are created per-test and reset, so cross-instance persistence is never observed.

This is a **test-discipline gap**, not two isolated bugs. The fix is a named taxonomy of resilience categories, backed by reusable helpers so authors actually write them, applied to every plugin.

## The taxonomy (three evidence-driven categories)

Each category corresponds to an operator-triggerable real-world event.

| Cat | Name | Real-world trigger | Catches |
|-----|------|--------------------|---------|
| **R** | Reload / persistence | raft failover, plugin reload, OpenBao restart, plugin upgrade | KI-001 |
| **P** | Mid-lease perturbation | re-seeding minters, deleting/rebinding a minter set or role while leases exist | KI-002 |
| **X** | Revoke-path resilience | upstream error or missing minter at revoke time; double revoke | (hardening) |

The taxonomy is **extensible by rule**: when a future bug would have been caught by a new category, add the category here and backfill it across plugins. This doc is the authoritative list.

## Architecture

A new module `pkg/plugintest/` (own `go.mod`, added to `go.work`). It must NOT import any plugin (cycle), so it is parameterized by a `Harness` the plugin's test supplies.

```go
package plugintest

// Harness is supplied by each plugin's resilience_test.go.
type Harness struct {
    // Factory is the plugin's logical.Factory.
    Factory logical.Factory
    // Configure writes config + a minter set named "default" + a role bound to it,
    // pointed at the plugin's fake. After it returns, IssuePath must be issuable.
    Configure func(t *testing.T, b logical.Backend, storage logical.Storage)
    // IssuePath is the read path that issues a credential, e.g. "creds/test-role".
    IssuePath string
    // RewriteDefaultSetWithout writes minter-sets/default containing a single
    // minter whose id differs from the originally-issuing minter (so the issuing
    // minter id is absent), simulating a re-seed. Pointed at the same fake.
    RewriteDefaultSetWithout func(t *testing.T, b logical.Backend, storage logical.Storage)
    // ProvisionedCount reports how many upstream credentials currently exist in
    // the plugin's fake (for asserting upstream effects of issue/revoke).
    ProvisionedCount func() int
    // ExpectsHardRevoke is true for plugins that delete the upstream credential on
    // revoke (DO, UpCloud, Exoscale, Azure, Vultr, Akamai); false for no-revoke
    // plugins (AWS, GCP, OVH). Lets the perturbation suite assert the right outcome.
    ExpectsHardRevoke bool
}
```

### Generic primitives

```go
// ReloadBackend calls factory again against the same StorageView, returning a
// fresh backend with no intervening config write — simulating failover/restart.
func ReloadBackend(t *testing.T, factory logical.Factory, storage logical.Storage) logical.Backend
```

### Category runners

```go
func RunReloadSuite(t *testing.T, h Harness)            // Category R
func RunPerturbationSuite(t *testing.T, h Harness)      // Category P
func RunRevokeResilienceSuite(t *testing.T, h Harness)  // Category X
```

Each plugin's `resilience_test.go` builds a `Harness` and calls the three runners. Expected size: ~30–50 lines per plugin, mostly the `Configure`/`RewriteDefaultSetWithout` closures.

## Category assertions (must have teeth)

### Category R — RunReloadSuite
1. `Configure` a backend A against fresh storage.
2. `ReloadBackend` → backend B from the same storage. **No config write between.**
3. Issue via B at `IssuePath`.
4. **Assert:** issuance succeeds (non-error response with a credential).

*Pre-fix outcome:* FAILS for UpCloud (B has `username=""` → 401 → all minters `AuthFailing` → `upstream_auth_failed`). This is KI-001. May also fail any other plugin with config-only-set fields (audit during impl: azure tenant/endpoints, akamai host).

### Category P — RunPerturbationSuite
1. `Configure`; issue a credential, capturing `resp.Secret`.
2. `RewriteDefaultSetWithout` — rewrite `minter-sets/default` so the issuing minter id is gone.
3. Revoke using the captured secret.
4. **Assert:** revoke returns no error (the lease releases cleanly; OpenBao will not infinitely retry).
5. If `ExpectsHardRevoke`, also assert the operation is a defined outcome (either the credential was deleted, or it is intentionally left to TTL-expire) — not an error.

*Pre-fix outcome:* FAILS for all 6 hard-revoke plugins (`getMinter` returns "minter not found" → error → infinite retry). This is KI-002.

### Category X — RunRevokeResilienceSuite
1. **5xx on delete (hard-revoke plugins only):** issue; set the fake to return 5xx on the next delete; revoke. Assert revoke fails *without* a stuck state, OR (after the KI-002 philosophy) is tolerated — exact assertion decided in impl per the decisions.md note. The credential TTL-expires regardless.
2. **Double revoke:** issue; revoke twice. Assert the second revoke is a clean no-op (no error).

## Fake accessor uniformity

Add a uniform method to all 10 fakes:
```go
func (s *<Cloud>Server) ProvisionedCount() int  // live upstream credentials right now
```
Azure (`PasswordCount`) and OVH (`TokenCount`) already have equivalents — add `ProvisionedCount` as the canonical name (may delegate to the existing method). Purely additive; no behavior change.

## The fixes (turned green by the new tests)

Sequencing is **red → green**: land the taxonomy + failing tests first, then fix.

### KI-001 — load config on backend init
In each affected plugin's `Factory`, after `loadAllMinterSets`, also load operational config from `conf.StorageView` so fields set only in `pathConfigWrite` are rehydrated. UpCloud needs `b.username`; audit and apply to any plugin whose Category R test fails. Sketch:
```go
if conf.StorageView != nil {
    _ = b.loadConfig(ctx, conf.StorageView)        // sets b.config + cloud-specific auth fields
    _ = b.loadAllMinterSets(ctx, conf.StorageView)
}
```
`loadConfig` reads the `config` (and e.g. `config/username`) storage entries that `pathConfigWrite` already persists. (Akamai's existing `loadHost` is the precedent.)

### KI-002 — revoke tolerates a missing issuing minter
In `pathCredsRevoke` of each hard-revoke plugin: when `getMinter(set, id)` reports the minter is absent, treat revoke as a **successful no-op** (log a warning) rather than returning an error — optionally first falling back to any healthy minter in the same set to attempt the upstream delete. The upstream credential TTL-expires regardless. Add a rationale note to `docs/decisions.md` (this deliberately weakens active-delete in favor of TTL expiry as the real guarantee).

## Out of scope

- Speculative categories (concurrency, storage-write-failure injection, format migration) — added later only when a bug demonstrates the need (per the extensibility rule).
- Changing the envelope/lease contract.
- Real-cloud (`cloud_real`) tests — these resilience tests use the existing fakes.

## Files

```
pkg/plugintest/                         (NEW module)
├── go.mod
├── harness.go        # Harness struct, ReloadBackend
├── reload.go         # RunReloadSuite
├── perturbation.go   # RunPerturbationSuite
└── revoke.go         # RunRevokeResilienceSuite

pkg/credenvelope/fakes/<cloud>.go       # + ProvisionedCount() (×10)

plugins/credential-<cloud>/
├── resilience_test.go                  # NEW (×10): builds Harness, calls 3 runners
├── backend.go                          # KI-001 fix: loadConfig in Factory (affected plugins)
├── path_config.go                      # KI-001: loadConfig helper
└── path_creds.go                       # KI-002 fix: tolerant revoke (hard-revoke plugins)

docs/decisions.md                       # KI-002 rationale note
docs/known-issues.md                    # mark KI-001/KI-002 resolved, ref the suite
```

## Success criteria

1. `pkg/plugintest` exists and is consumed by all 10 plugins' `resilience_test.go`.
2. Category R + P tests demonstrably FAIL before the fixes and PASS after (verified by landing tests first).
3. All 17+ packages pass `go test -race`; `make lint` clean; `make smoke-test` green.
4. `docs/known-issues.md` KI-001/KI-002 marked resolved with a pointer to the regression suite.
5. Taxonomy documented (this spec + a short pointer in CLAUDE.md) so new plugins are required to include `resilience_test.go`.
