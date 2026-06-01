# Audit-2 Effort 4a: Minter Observability (#9, part 1) — Design Spec

**Status:** Approved (2026-06-01)
**Scope:** Close the monitoring blind spot for the long-lived "minter" credentials. The first of two sub-efforts decomposed from audit #9 (the largest standing security exposure). **4a (this spec):** observability — a minter-age gauge for every minter (incl. `never_expires`) + a configurable near-expiry warn-log. **4b (separate, later spec):** minter self-rotation (a `MinterRotator` interface + per-cloud impls + manual endpoint + auto worker).

Re-verified against the code at HEAD `a8da331` during brainstorming (file:line below). Each fix is TDD.

## Verification: what already exists (audit #9 was partly stale)

- All 10 plugins ALREADY emit `upstream_expires_in_seconds` per expiring minter, from `emitMinterMetrics` (e.g. `credential-do/telemetry.go:42-45`), called on the health-check cadence (`health_check.go:42`). So the audit's "emit a `cloud_creds_minter_expiry_seconds` gauge" is largely already done (different name).
- `docs/decisions.md:19` already documents the intended external alert (`expires_in_seconds < 14d`), which explicitly does NOT fire for `never_expires` minters.
- `Minter.CreatedAt` is always set at write time (`pkg/cloudconfig/minter.go:18`; populated `CreatedAt: time.Now()` in each plugin's `parseMinters`, e.g. `credential-do/path_minter_sets.go:57`).

## The genuine gaps (what 4a fixes)

1. **`never_expires` minters emit NO lifetime signal at all.** `emitMinterMetrics` gates the only lifetime gauge on `if !ms.minter.ExpiresAt.IsZero()` (`telemetry.go:42`), so a `never_expires` minter — the exact "a never-expiring minter satisfies the [validation] rule forever" case the audit flags — is invisible to monitoring. There is no age/staleness signal for it.
2. **No proactive warn-log as a minter nears expiry.** Operators rely entirely on an external Prometheus alert that may not be wired; the plugin itself says nothing in its logs as a minter approaches expiry.

## Fix

### 1. `minter_age_seconds` gauge — unconditional, every minter

In each plugin's `emitMinterMetrics`, after building `labels`, emit (always, regardless of expiry type):
```go
emit.Gauge("minter_age_seconds", float32(now.Sub(ms.minter.CreatedAt).Seconds()), labels)
```
This makes a stale, never-rotated minter (including `never_expires`) visible — operators can alert on `cloud_creds_minter_age_seconds > <policy>` (e.g. 90d). The existing `upstream_expires_in_seconds` gauge stays unchanged (still gated on an expiring minter). Labels are the existing set (`CloudLabel`, `minter_set`, `cred_id`).

Edge case: if a minter somehow has a zero `CreatedAt` (legacy data written before the field existed), `now.Sub(zero)` yields a huge positive age — which is the correct alarming signal (an un-dated minter is suspicious), not a bug. No special-casing.

### 2. Configurable near-expiry warn-log

**`pkg/cloudconfig`:** add to `PluginConfig`:
```go
MinterExpiryWarn time.Duration `json:"minter_expiry_warn"`
```
and in `DefaultConfig`, `MinterExpiryWarn: MinMinterGap` (the existing `7 * 24 * time.Hour`). Reusing `MinMinterGap` as the default ties the warn threshold to the validation rule's gap, which is the natural "a minter this close to expiry needs attention" boundary.

**Each plugin's `config` endpoint** (×10): add a `minter_expiry_warn` field (mirroring `flush_interval`):
- Schema: `framework.TypeDurationSecond`, `Default: defaultMinterExpiryWarnSeconds` (a new per-plugin const = `604800` // 7d, expressed in seconds like the existing `defaultFlushIntervalSeconds`).
- Write-parse: `minterExpiryWarn := time.Duration(d.Get("minter_expiry_warn").(int)) * time.Second`, set on the `PluginConfig`.
- Read-render: `"minter_expiry_warn": int(cfg.MinterExpiryWarn.Seconds())` in the config read response.

**`emitMinterMetrics`** (×10): the function already holds `b.mu.RLock()`. Read the threshold from `b.config` (guard nil → `cloudconfig.MinMinterGap`), and per minter:
```go
if !ms.minter.ExpiresAt.IsZero() {
    expiresIn := ms.minter.ExpiresAt.Sub(now)
    emit.Gauge("upstream_expires_in_seconds", float32(expiresIn.Seconds()), labels)  // existing
    if expiresIn > 0 && expiresIn < warnThreshold {
        b.Logger().Warn("minter nearing expiry",
            "cloud", cloudName, "minter_set", setName, "minter_id", id,
            "expires_in_seconds", int(expiresIn.Seconds()),
            "warn_threshold_seconds", int(warnThreshold.Seconds()))
    }
}
```
`never_expires` minters take neither branch (correct — they don't expire). An already-expired minter (`expiresIn <= 0`) does NOT warn here — it is past the warn window; the `upstream_state`/issuance-failure signals cover a dead minter. The warn is specifically the *approaching-expiry* heads-up.

Threshold sourcing (per plugin, inside the already-held `b.mu.RLock`):
```go
warnThreshold := cloudconfig.MinMinterGap
if b.config != nil && b.config.MinterExpiryWarn > 0 {
    warnThreshold = b.config.MinterExpiryWarn
}
```
(The `> 0` guard means a zero/unset stored config falls back to the 7d default rather than disabling warnings — disabling is not a goal; the operator lowers/raises, not zeroes.)

## Components touched

- `pkg/cloudconfig/config.go` — `MinterExpiryWarn` field + default (+ test).
- Each plugin (×10):
  - `path_config.go` — `minter_expiry_warn` field schema, write-parse, read-render; a `defaultMinterExpiryWarnSeconds` const.
  - `telemetry.go` — `emitMinterMetrics`: unconditional age gauge + the configurable warn-log.
  - `consts.go` — only if the const lives there per the plugin's convention (most duration-second defaults live in `path_config.go`; follow each plugin's existing placement).

## Testing

- **`pkg/cloudconfig`:** `DefaultConfig` test asserting `MinterExpiryWarn == MinMinterGap`.
- **Per-plugin (DO representative; lighter for the other 9):** a test calling `emitMinterMetrics` (or its logic) with:
  - a minter with `CreatedAt` 30d ago → asserts a positive `minter_age_seconds` is emitted (use the go-metrics in-memory sink the existing telemetry tests use, or assert via a seam — check how existing `telemetry`-related tests inspect emitted metrics; if none exist, assert the warn-log path via a captured `hclog` test logger and the age via the metric sink).
  - an expiring minter within the threshold → a "minter nearing expiry" warn is logged (capture with an `hclog.New` writing to a buffer set as `b.Logger()`).
  - a `never_expires` minter → `minter_age_seconds` emitted, NO warn logged.
  - config round-trip: write `minter_expiry_warn=86400` (1d), read back `86400`.
- The other 9 plugins get the config round-trip assertion + a lighter "warn fires within threshold" check, reusing the DO shape.
- **Full gate:** 20 modules `go build` / `go test -race` / golangci-lint v2.12.2 (binary at `/home/claude-aiven-2/code/qualcheck/bin/golangci-lint`) 0 issues / `make smoke-test` 10/10; no new `//nolint`.

## Risk

- **Low.** Additive: one new always-on gauge, one new optional config field (defaulted), one warn-log. No behavior change to issuance, revoke, reconcile, or the envelope. The existing `upstream_expires_in_seconds` gauge and all existing tests are untouched.
- The warn-log fires once per health-check tick per near-expiry minter — bounded by minter count and the health-check cadence; not log-spam (a minter is near-expiry for at most the warn window, and the cadence is minutes-to-hours).
- No envelope/error-contract change; no `api_version` bump; no new error code.

## Success criteria

1. `pkg/cloudconfig.PluginConfig` has `MinterExpiryWarn`, defaulting to `MinMinterGap` (7d), round-trippable via each plugin's `config` endpoint as `minter_expiry_warn` (seconds).
2. All 10 plugins emit `minter_age_seconds` for EVERY minter (including `never_expires`); a stale never-rotated minter is now observable.
3. All 10 plugins warn-log "minter nearing expiry" when an expiring minter is within the configured threshold; `never_expires` and already-expired minters do not warn.
4. Whole workspace `go build` / `go test -race` / `make lint` / `make smoke-test` green; all 20 modules 0 lint; no new `//nolint`.

## Out of scope (→ Effort 4b)

- Minter self-rotation: the `MinterRotator` interface, per-cloud successor-minting impls (feasible for azure/gcp/aws/do/upcloud/exoscale/vultr/akamai; NOT OVH whose OAuth2 grant can't mint successors; OCI quota-tight), the manual `cloud-creds/<cloud>/minter-sets/<set>/rotate` endpoint, the auto-rotation worker, and the mint→validate→swap→retire orchestration. Its own spec → plan → merge cycle.
- Changing the validation rule or the `MinMinterGap` constant.
- Wiring external Prometheus alerts (operator infra, not plugin code).
