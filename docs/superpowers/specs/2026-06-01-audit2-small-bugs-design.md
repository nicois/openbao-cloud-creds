# Audit-2 Effort 1: Small Verified Bugs (#2, #6, #10) — Design Spec

**Status:** Approved (2026-06-01)
**Scope:** Three independent, verified bugs from `docs/audit-2026-06-01.md`: #2 (Akamai EdgeGrid body-hash), #6 (OCI overdue-slot TTL=0), #10 (worker `context.Background()` + missing `Clean` teardown). Each is small and high-confidence; grouped because they share no code and can land independently.

All three were re-verified against the code at HEAD `d71c8cd` during brainstorming (file:line below). Each fix is TDD: a test that fails against current code, then the fix.

## #2 — Akamai EdgeGrid body hash + signature-validating fake

**Bug (verified):** `plugins/credential-akamai/edgegrid.go:62-69` signs POST/PUT requests with the empty-body hash:
```go
bodyHash = hashBody(nil) // empty for simplicity; real impl would buffer
```
EG1-HMAC-SHA256 requires the SHA256 (base64) of the actual request body (first 131072 bytes) in the canonical request. The mint POST (`CreateClient`) sends a JSON body but signs the empty-body hash → real Akamai would reject it for signature mismatch. The cloud-fake does not validate signatures, so existing tests pass blind.

The empty **headers** field in the canonical request (`"%s\t%s\t%s\t%s\t%s\t%s\t"` with `""` for the headers segment) is NOT a bug — EdgeGrid signs only operator-designated headers, and none are designated here. Leave it.

**Fix:**
1. In `signRequest` (edgegrid.go), buffer the body without consuming it for the real send:
   ```go
   if req.Body != nil && (req.Method == http.MethodPost || req.Method == http.MethodPut) {
       buf, _ := io.ReadAll(req.Body)
       req.Body = io.NopCloser(bytes.NewReader(buf))   // restore for the actual send
       if len(buf) > maxBodyHashBytes {                // maxBodyHashBytes = 131072
           buf = buf[:maxBodyHashBytes]
       }
       bodyHash = hashBody(buf)
   }
   ```
   Add a `const maxBodyHashBytes = 131072` (EdgeGrid's documented cap). Confirm `hashBody` already does `sha256` → base64 (it's the existing helper); only the input changes from `nil` to the buffered bytes.
2. **Make the fake validate the signature** (`pkg/credenvelope/fakes/akamai.go`): on each request, recompute the EG1-HMAC-SHA256 signature from the received method/host/path/body + the `Authorization` auth-data fields, using the client secret the test configured, and return 401 if it doesn't match the presented `signature=`. This is the load-bearing verification — it proves the plugin's signing is correct, and would reject the old empty-body-hash signing.

**Tests:**
- In the akamai plugin test (or fakes test): a `CreateClient` mint with a non-empty body succeeds **because** the body hash is now correct; assert the fake accepted it (200/201). To prove red-then-green: a unit test in the akamai package that signs a body-bearing request and verifies the recomputed signature matches (independently of the fake), which fails with `hashBody(nil)`.
- A fakes-level test that a request with a deliberately wrong signature gets 401 (proves the fake actually validates).

## #6 — OCI overdue-slot TTL

**Bug (verified):** `plugins/credential-oci/path_creds.go:73-77` floors a lagging slot's TTL to 0 and still serves it:
```go
ttlSeconds := int(best.NextRotationAt.Sub(now).Seconds())
if ttlSeconds < 0 {
    ttlSeconds = 0   // overdue but still served
}
```
`freshestSlot` (slots.go) only filters `State == slotActive`, so an overdue slot can be returned with `resp.Secret.TTL = 0`, violating OCI's "TTL is always honest" invariant precisely when rotation lags.

**Phasing context (verified — makes skip-overdue safe):** slots are initialized staggered by `rotationInterval = RotationPeriod / SlotCount` (slots.go:119,131 — slot i rotates at `now + (i+1)*interval`), and `freshestSlot` picks the most-recently-rotated slot (the one *furthest* from its deadline). So for N=2 the freshest slot is rarely the overdue one, and at most one slot is past-deadline at a time. Skipping overdue slots leaves a fresh slot to serve in the normal case; `pool_exhausted` results only if *every* slot has lapsed (a degenerate rotation-far-behind state where serving a TTL=0 cred was already wrong).

**Fix:** skip overdue slots so they are never served. Add the check in `freshestSlot` (or at the call site before computing TTL): an active slot whose `NextRotationAt` is in the past (relative to `now`) is not eligible. If none remain eligible, return the existing `ErrPoolExhausted` response. Remove the `ttlSeconds < 0 → 0` branch (now unreachable for served slots, but keep a defensive guard if a served slot's remaining time is ≤0 due to clock skew — floor to a small positive `minLeaseTTLSeconds`, or treat as overdue and skip; pick skip for consistency). The "honest TTL" property holds: a served slot always has `NextRotationAt` in the future.

**Tests (credential-oci):**
- A role with one active slot whose `NextRotationAt` is in the past → read returns `pool_exhausted` (not a TTL=0 lease).
- A role with two slots, one overdue + one fresh → read returns the fresh slot with a positive TTL.
- Regression: the existing OCI creds tests (fresh slots) still pass unchanged.

## #10 — worker context + `Clean` teardown (all 10 plugins)

**Bug (verified):** every plugin launches `go b.startWorkers(context.Background(), req.Storage)` (`credential-do/path_config.go:102`, `path_minter_sets.go:95`, and the same in all 10), and `startWorkers` derives `workerCtx` from that `Background()` (workers.go). The `framework.Backend{}` (backend.go:46) sets no `Clean` hook, so on OpenBao backend unmount/reload nothing calls `stopWorkersLocked` → the worker goroutines (reconciler hitting cloud APIs, metrics flush) leak past backend life. (`framework.Backend` does expose a `Clean func(context.Context)` field — the SDK supports it; we just don't wire it.)

**Fix (two parts, applied to all 10 plugins):**
1. **`Clean` hook:** set `b.Backend.Clean = func(ctx context.Context) { b.stopWorkersLocked() }` in `Factory` (the existing `stopWorkersLocked` already drains via cancel + `wm.Wait()`, guarded by `workerLifecycleMu` — note `stopWorkersLocked` takes `b.mu`, so call it directly, not under an outer lock that would conflict; verify the lock order in `stopWorkersLocked` and call `Clean` outside `workerLifecycleMu` or make a small `b.stopWorkers()` wrapper that takes the lifecycle mutex like `startWorkers` does). Implementer to confirm the exact lock-safe call.
2. **Long-lived base context:** create a backend base context + cancel in `Factory` (`b.baseCtx, b.baseCancel = context.WithCancel(context.Background())`), have `startWorkers` derive `workerCtx` from `b.baseCtx` instead of the request `ctx`/`Background()`, and have `Clean` also call `b.baseCancel()`. This decouples worker lifetime from any single request and gives unmount a single cancellation root. (Using a stored base context rather than the request `ctx` is correct: workers outlive the config-write request that starts them by design; the bug is only that nothing ever cancels them on unmount.)

**Tests:** a `pkg/plugintest`-style or per-plugin test (DO representative, lighter assertion for the rest) that after constructing a backend, writing config (starting workers), and calling `b.Clean(ctx)`, `b.workerMgr` is drained — assert via the worker manager's `Running()` returning false (it already exposes `Running()`). Confirm no goroutine leak by checking `Running()` flips to false after `Clean`.

## Testing / risk / success criteria

- Each fix: red-then-green test; existing tests pass unchanged (behavior-preserving except the intended fix).
- **#2 risk:** signing correctness — mitigated by the signature-validating fake (the test now proves correctness, not just that a call happens). Cannot run real Akamai; the fake recomputing the same algorithm is the best available proof.
- **#6 risk:** skip-overdue must not spuriously empty a healthy pool — mitigated by the verified phasing (staggered rotation; freshest = furthest-from-deadline). Test the two-slot case explicitly.
- **#10 risk:** lock-ordering in `Clean`/`stopWorkers` (don't deadlock against `workerLifecycleMu`/`b.mu`) — implementer confirms the lock-safe call; the `-race` suite + the `Running()`-after-`Clean` test guard it. Applied to 10 plugins (mechanical; per-plugin tests are the guard).

**Success criteria:**
1. Akamai signs the real body hash; the fake validates EG1-HMAC-SHA256 and a body-bearing mint succeeds only with correct signing (red against `hashBody(nil)`).
2. OCI never serves a TTL=0 lease; overdue slots are skipped, honest-TTL invariant holds, two-slot phasing still serves the fresh slot.
3. All 10 plugins wire `Clean` → worker teardown and derive worker context from a backend base context; `Running()` is false after `Clean`.
4. Whole workspace `go build` / `go test -race` / `make lint` / `make smoke-test` green; all 20 modules 0 lint; no new `//nolint`.

## Out of scope
The other audit-2 efforts (#4/#5/#8 error handling; #1/#3 scale; #9 minter lifecycle); the deferred #7 (broad real-cloud testing) — though the #2 signature-validating fake is a down-payment on it for Akamai specifically.
