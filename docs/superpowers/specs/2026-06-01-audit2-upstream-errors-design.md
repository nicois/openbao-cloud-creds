# Audit-2 Effort 2: Upstream Error Handling (#4, #5, #8) — Design Spec

**Status:** Approved (2026-06-01)
**Scope:** Three verified findings from `docs/audit-2026-06-01.md` that share the issue/error path: #4 (error_code classification), #5 (raw-body info leak), #8 (429 thundering-herd). Grouped because they touch the same per-plugin sites and shared packages.

All three re-verified against the code at HEAD `ea0e6a8` during brainstorming (file:line below). Each fix is TDD; logic centralized in `pkg/`, applied mechanically at per-plugin sites.

## #4 + #5 — shared upstream-error classifier + leak-free envelope

**Bugs (verified):**
- **#4:** Every issue-time upstream failure returns `ErrInternal` ("upstream error: %v", e.g. `credential-do/path_creds.go:69`). The other 4 error codes meant for upstream failures (`ErrUpstreamQuotaExceeded`, `ErrUpstreamTimeout`, `ErrEntityUnavailable`, plus the existing `ErrUpstreamAuthFailed` which IS used in a few spots) are never emitted at the issue path. AWS/GCP compute a status (`classifyAWSError`/`classifyGCPError(err) int`) but feed it only to the state machine, not the client envelope. Clients can't distinguish retryable (429/timeout) from fatal.
- **#5:** akamai (`akamai_client.go:78,122`) and azure client errors embed the full upstream body (`fmt.Errorf("akamai API returned %d: %s", status, string(bodyBytes))`); that `err` flows verbatim into the client-facing `resp.Error()` via `ErrorResponse(ErrInternal, "upstream error: %v", err)`. Graph/Akamai bodies carry tenant IDs, app object IDs, internal request IDs.

**Fix — one classifier, generic client messages, operator-side logging:**

1. **`pkg/credenvelope` gains a classifier:**
   ```go
   // ClassifyUpstream maps an upstream HTTP status to the stable error_code a
   // client sees, so callers can distinguish retryable (quota/timeout) from
   // fatal (auth/not-found). Unknown / 5xx → ErrInternal.
   func ClassifyUpstream(httpStatus int) ErrorCode {
       switch {
       case httpStatus == http.StatusTooManyRequests:        // 429
           return ErrUpstreamQuotaExceeded
       case httpStatus == http.StatusRequestTimeout,         // 408
            httpStatus == http.StatusGatewayTimeout:         // 504
           return ErrUpstreamTimeout
       case httpStatus == http.StatusUnauthorized,           // 401
            httpStatus == http.StatusForbidden:              // 403
           return ErrUpstreamAuthFailed
       case httpStatus == http.StatusNotFound:               // 404
           return ErrEntityUnavailable
       default:                                              // 5xx, 0, anything else
           return ErrInternal
       }
   }
   ```
   No NEW error code is added — the techrfc froze the 10-constant set and "adding one is a spec change" (CLAUDE.md). 5xx maps to the existing `ErrInternal`; a timeout/cancelled context is surfaced by callers passing `http.StatusGatewayTimeout` (or `408`) when `errors.Is(err, context.DeadlineExceeded)` — a small caller-side helper or inline check (the classifier is status-only; callers that have a Go error rather than a status map it first, as AWS/GCP already do via classify*Error).

2. **Each issue-error site (all 10 plugins, ~2 sites each — the issue path + any renew/secondary mint):** replace
   ```go
   return credenvelope.ErrorResponse(credenvelope.ErrInternal, "upstream error: %v", err), nil
   ```
   with
   ```go
   b.Logger().Warn("upstream credential issuance failed",
       "cloud", cloudName, "status", httpStatus, "error", err)
   return credenvelope.ErrorResponse(credenvelope.ClassifyUpstream(httpStatus),
       "upstream credential issuance failed"), nil
   ```
   - The raw `err` (which may embed the upstream body) goes ONLY to the operator log, never the client. The client gets a generic message + the classified code.
   - Every site already has an HTTP `httpStatus int` in scope (DO/exoscale/etc. return it from the client; AWS/GCP have `classifyAWSError`/`classifyGCPError(err)`). Pass that.
   - Keep the existing `recordMinterError(...)` call (state-machine feed) unchanged — it already gets the status.
   - The generic message can be tailored per site (e.g. "upstream credential issuance failed" vs "upstream credential revoke failed") but must contain NO `err`/body interpolation.

**Touch:** `pkg/credenvelope/errors.go` (the classifier + a test), and each plugin's `path_creds.go` issue/revoke error sites (10 plugins). The akamai/azure client `fmt.Errorf("...%s", body)` strings stay AS-IS (they're the operator-log err); only the envelope-building site changes to not interpolate them.

## #8 — 429 cool-down in the recovery state machine

**Bug (verified):** `selectMinter` accepts `State() == Healthy || TransientFailing` (`credential-do/path_creds.go:194,232,248`, same across plugins). A 429 lands a minter in `TransientFailing` (`RecordError` → `state.go:75/80`), which is still selectable — so the next read picks the same rate-limited minter and re-hammers it. No retry/backoff or cool-down anywhere. At scale, many nodes doing this deepen the rate-limit (thundering herd).

**Fix — a short cool-down the selector honors:**

1. **`pkg/recovery` state machine:**
   - Add a `cooldownUntil time.Time` field. In `RecordError(httpStatus, at)`, when `httpStatus == http.StatusTooManyRequests` (429), set `cooldownUntil = at.Add(RateLimitCooldown)` where `const RateLimitCooldown = 5 * time.Second` (short: long enough to break the hammer loop, short enough not to strand a minter). The existing state transitions (→ TransientFailing) are unchanged; the cool-down is an additional, orthogonal gate.
   - Add `Selectable(now time.Time) bool`: returns false if `now.Before(cooldownUntil)` OR the state is `AuthFailing`/`Missing` (i.e. the same selectability the current `State()==Healthy||TransientFailing` check expresses, PLUS the cool-down). Returns true for `Healthy`/`TransientFailing` once any cool-down has elapsed.
   - `RecordSuccess` clears `cooldownUntil` (a successful mint means the minter is usable again).

2. **`selectMinter` (all 10 plugins):** replace the three `ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing` checks with `ms.sm.Selectable(now)`, threading the `now` the read path already computes (`selectMinter` is called with a `now` available in `pathCredsRead`; pass it as a param if `selectMinter` doesn't already take one — confirm signature per plugin).

**Behavior:** a 429'd minter is skipped for 5s, so concurrent reads fall through to another healthy minter in the set (or `pool_exhausted` if none) rather than re-hammering. After 5s it's eligible again; a real success clears it immediately.

**Touch:** `pkg/recovery/state.go` (+ test) and each plugin's `selectMinter` (the 3 selectability checks → `Selectable(now)`).

## Testing

- **#4 classifier:** table test in `pkg/credenvelope` — each status → expected code (429→quota, 408/504→timeout, 401/403→auth_failed, 404→entity_unavailable, 500/502/503/0/200→internal).
- **#4/#5 per-plugin:** a representative test (DO) that a forced upstream error (via the fake's error knob) yields a client response whose `error_code` matches the classified status (e.g. fake returns 429 → response code is `upstream_quota_exceeded`) AND the response message does NOT contain the raw upstream body. The other 9 get a lighter assertion (the classified code surfaces; no raw body). Reuse the cloud-fakes' existing 401/403/429/500 knobs.
- **#8 cool-down:** deterministic state-machine test with explicit `now` — `RecordError(429, t)` then `Selectable(t+1s)==false`, `Selectable(t+RateLimitCooldown+1s)==true`; `RecordSuccess` clears it; a non-429 error does NOT set a cool-down (still `Selectable` per state). Plus a DO-level test that a 429'd minter is skipped by `selectMinter` within the window and a sibling healthy minter is chosen.

## Risk

- **#4/#5** touch ~20 issue/revoke sites across 10 plugins — mechanical; the per-plugin tests + behavior-preservation (existing tests unchanged) are the guard. The one subtlety: ensure no remaining `%v, err` in any *client-facing* envelope (grep after). Renew/revoke error sites get the same treatment where they currently leak.
- **#8** changes minter selection — but strictly *removes* a rate-limited minter from eligibility for a bounded window; it can only make the selector skip more, never select something previously rejected. `pool_exhausted` is the honest fallback if every minter is cooling down (rare; means the whole set is rate-limited, where backing off is correct). The injected-clock test guards the timing.
- No new error code (techrfc contract unchanged); no envelope `api_version` bump (the response *shape* is unchanged — only which existing `error_code` value appears).

## Success criteria

1. `pkg/credenvelope.ClassifyUpstream` exists, table-tested; maps statuses to the existing codes (no new code added).
2. All 10 plugins' issue (and leaking revoke) error sites return the classified code + a generic message; the raw upstream body/err appears ONLY in operator logs, never the client response. Verified: no client-facing envelope interpolates `err`.
3. `pkg/recovery` has `Selectable(now)` + a 429 `cooldownUntil`; `RateLimitCooldown = 5s`; `RecordSuccess` clears it. All 10 `selectMinter`s use `Selectable(now)`.
4. A 429'd minter is provably skipped for the cool-down window and a sibling is chosen; classifier + cool-down both deterministically tested.
5. Whole workspace `go build` / `go test -race` / `make lint` / `make smoke-test` green; all 20 modules 0 lint; no new `//nolint`.

## Out of scope
- Client-side retry-with-jitter inside the cloud HTTP clients (the cool-down handles the herd; per-client retry is heavier and closer to the deferred reconciler-throttle work — not needed for prerelease).
- Reconciler/health-check fan-out throttling (audit #8 mentions it; the minter cool-down + the existing `MaxDeletesPerPass` cap are the in-scope parts — a dedicated reconciler-rate-limit is deferred).
- The other audit-2 efforts (#1/#3 scale, #9 minter lifecycle) and the deferred #7.
