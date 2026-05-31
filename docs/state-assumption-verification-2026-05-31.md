# State-Assumption Findings — Verification Report (2026-05-31)

Each finding: verdict (REAL / REFUTED / DOCUMENTED-RISK), artifact (test path or static proof), action.

**Summary: 8 findings, all verified — 7 REAL (fixed), 1 DOCUMENTED-RISK (KI-003). Residual gaps (Exoscale/Vultr fail-closed orphan cleanup) tracked as KI-004.**

| # | Finding | Verdict | Artifact | Action |
|---|---------|---------|----------|--------|
| F1 | Reconciler ConfirmationHold guard dead (6 plugins) | REAL (fixed) | static: reconciler.go:62 gated on CreatedAt, no lister set it; Task 3 fail-closed + Task 4 populates CreatedAt (4 of 6 clouds; exoscale/vultr have no list timestamp → fail-closed) | fixed (Task 3,4) |
| F2 | GCP/OVH no HTTP client timeout | REAL (fixed) | static: http.DefaultClient at iam_client.go + token_client.go | fixed (Task 8) |
| F3 | OCI fakeOCIClient unsynchronized map | REAL (fixed) | test: TestFakeOCIClient_ConcurrentAccess (-race) | fixed (Task 5): mutex on fakeOCIClient |
| F4 | OCI rotation-vs-reconcile delete race | REAL (fixed) | test: TestRotationReconcileRace | fixed (Task 5): rotateReconcileMu serializes rotation vs reconcile |
| F5 | Reconciler DeleteEntity not 404-idempotent (5 plugins) | REAL (fixed) | test: TestDeleteEntity_404IsSuccess + TestRun_DeleteErrorDoesNotAbortPass | fixed (Task 6): treat upstream 404 as success in 5 listers + reconciler log-and-continue per entity |
| F6 | Create-then-track: untracked live cred on Put failure | REAL (fixed) | test: TestCredsIssue_TrackingWriteFailureCompensates (DO + Azure, -race) | fixed (Task 7): revoke-on-track-write-failure in 6 hard-revoke plugins; N/A for 3 no-revoke plugins |
| F7 | Azure addPassword Graph propagation lag | DOCUMENTED-RISK | docs/known-issues.md KI-003 | documented (Task 9) |
| F8 | pkg/worker tests sleep-based / flaky | REAL (fixed) | test: TestWorkerTicks + TestWorkerInitialDelay (testing/synctest) | fixed (Task 10): converted to synctest, exact assertions |

## Notes
(Subsequent tasks append per-finding detail here.)

### F1 — Reconciler ConfirmationHold guard is dead code
The guard lives at `pkg/reconciler/reconciler.go:62`: `if r.config.ConfirmationHold > 0 && !entity.CreatedAt.IsZero() {` (with the age comparison at line 63 `if now.Sub(entity.CreatedAt) < r.config.ConfirmationHold {`). `UpstreamEntity.CreatedAt` is declared at reconciler.go:11. All six listers construct `reconciler.UpstreamEntity{...}` setting ONLY `ID` and `Name`, never `CreatedAt`: credential-do reconciler_integration.go:26-29 (ID=t.ID, Name=t.Name), credential-azure:29-32 (ID=pw.KeyID, Name=pw.DisplayName), credential-vultr:26-29 (ID=u.ID, Name=u.Name), credential-exoscale:26-29 (ID=k.KeyID, Name=k.Name), credential-upcloud:26-29 (ID=t.ID, Name=t.Name), credential-akamai:26-29 (ID=c.ClientID, Name=c.ClientName). Since `CreatedAt` is always the zero value, `!entity.CreatedAt.IsZero()` is always false, so the ConfirmationHold branch is unreachable. Verdict: REAL.

**Fix landed (Task 3, fail-closed core).** `pkg/reconciler/reconciler.go` now treats unconfirmable age as a reason to SKIP the delete rather than proceed. The guard became:
```go
if r.config.ConfirmationHold > 0 {
    if entity.CreatedAt.IsZero() || now.Sub(entity.CreatedAt) < r.config.ConfirmationHold {
        continue
    }
}
```
Previously, a zero `CreatedAt` bypassed the hold entirely (delete allowed); now a zero `CreatedAt` means we cannot confirm the orphan is older than the hold, so we fail closed and skip it this pass. Proven by `TestRun_FailsClosedWhenAgeUnconfirmable` (`pkg/reconciler/reconciler_test.go`), which was RED against the old guard (`got 1` delete) and GREEN after the fix; the precision path is covered by `TestRun_DeletesConfirmablyOldOrphan` (old → deleted) and `TestRun_SkipsRecentConfirmableOrphan` (recent → skipped), both written to pass before and after.

**Interim consequence until Task 4.** No lister populates `CreatedAt` yet, so on the worker reconcile path (`ConfirmationHold = 1h`) EVERY orphan now has zero `CreatedAt` and is skipped — orphan cleanup is effectively PAUSED on the worker path. This is the intended safe interim state: better to leak orphans for one task than risk hard-deleting a live credential. Task 4 restores precise cleanup by populating `CreatedAt` in each lister, after which confirmably-old orphans are deleted again while just-issued credentials inside the create-then-track window remain protected.

**Fix landed (Task 4, precision layer).** Each hard-revoke lister now reads the cloud list response's creation timestamp into `UpstreamEntity.CreatedAt`, via the shared helper `reconciler.ParseCreatedAt` (RFC3339; empty/malformed → zero time, which the Task 3 guard treats as "unconfirmable" and skips — a bad upstream timestamp can never trigger a delete). The client list struct gained the timestamp field and `reconciler_integration.go` maps it.

Per-cloud list-response timestamp field used:

| Cloud | List endpoint | Timestamp field | Mapped to |
|-------|---------------|-----------------|-----------|
| DigitalOcean | `GET /v2/tokens` | `created_at` (RFC3339) | `tokenInfo.CreatedAt` → `UpstreamEntity.CreatedAt` |
| UpCloud | `GET /1.3/account/tokens` | `created` (RFC3339) | `tokenInfo.Created` |
| Azure | Graph `GET /applications/{id}` → `passwordCredentials[]` | `startDateTime` (RFC3339) | `passwordCredentialInfo.StartDateTime` |
| Akamai | `GET /identity-management/v3/api-clients` | `createdDate` (RFC3339) | `clientInfo.CreatedDate` |
| Exoscale | `GET /v2/api-key` | **none** — IAM API-key list returns only `key-id`, `name`, `role-id` | relies on fail-closed (worker never auto-deletes Exoscale orphans; explicit `reconcile` endpoint with `ConfirmationHold=0` still does) |
| Vultr | `GET /v2/users` | **none** — sub-user list returns only `id`, `name`, `email`, `api_enabled`, `acls` | relies on fail-closed (same as Exoscale) |

Cloud-fakes modified to emit the timestamp (real APIs already do; the fakes did not): `pkg/credenvelope/fakes/{do,upcloud,azure,akamai}.go` now stamp a deterministic `fakeCreatedAt = 2026-01-01T00:00:00Z` on the create path and surface it through the list handler, plus an `AddRaw*WithCreatedAt`/`WithCreatedDate`/`WithStartDateTime` helper to plant an orphan with a controlled age. Exoscale and Vultr fakes were NOT touched (their real APIs carry no list-creation timestamp).

Proof per cloud (each red→green): `TestReconcile_PopulatesCreatedAt` in `plugins/credential-{do,upcloud,azure,akamai}/created_at_test.go` (was RED — zero `CreatedAt` — before the lister mapped the field; GREEN after). End-to-end Task3+Task4 proof: `TestReconcile_CreatedAtDrivesDeleteVsSkip` drives the real lister through `reconciler.New(Config{ConfirmationHold: 1h}).Run` with an all-orphans registry — a fake entity stamped 2h old IS deleted, one stamped 5m old is SKIPPED (verified for all four timestamp-bearing clouds). Exoscale/Vultr have no such test because they have no list timestamp to populate; their worker-path orphans remain protected (uncleaned) by the fail-closed guard, an accepted residual gap documented in `docs/known-issues.md` (KI-004).

### F2 — GCP/OVH lack client-side HTTP timeout
GCP issues requests via `http.DefaultClient.Do(req)` at `plugins/credential-gcp/iam_client.go:156` and `:208`; OVH via `http.DefaultClient.Do(req)` at `plugins/credential-ovh/token_client.go:63`. `http.DefaultClient` has no `Timeout` set, so a hung upstream can block indefinitely. By contrast DO (representative of the other 7 plugins) builds its client with an explicit timeout: `plugins/credential-do/do_client.go:13-14` defines `const httpTimeout = 30 * time.Second` and lines 48-49 construct `&http.Client{ Timeout: httpTimeout }`. Verdict: REAL.

**Fix applied (Task 8):** Both packages now define a bounded HTTP client matching the DO pattern:
- `plugins/credential-gcp/iam_client.go`: added `const httpTimeout = 30 * time.Second` and `var httpClient = &http.Client{Timeout: httpTimeout}` after imports (lines 22-26), replaced `http.DefaultClient.Do(req)` → `httpClient.Do(req)` at the JWT-exchange site (line 162) and the generateAccessToken site (line 214).
- `plugins/credential-ovh/token_client.go`: added `const httpTimeout = 30 * time.Second` and `var httpClient = &http.Client{Timeout: httpTimeout}` after imports (lines 14-18), replaced `http.DefaultClient.Do(req)` → `httpClient.Do(req)` at the MintToken site (line 69).

Both packages already imported `time` and `net/http`, so no new imports were needed. Build clean, all tests pass (`go test -race`), lint clean (golangci-lint 0 issues). Existing tests remain green because real-client timeout behavior is not exercised — tests use injected fake clients with no network I/O. The fix hardens robustness against hung upstream APIs but does not alter test-exercised semantics.

### F3 — OCI fakeOCIClient unsynchronized map — REAL
`fakeOCIClient` (`plugins/credential-oci/oci_client.go:64`) holds `tokens map[string]map[string]*fakeToken`, `nextID int`, and `failNext error` with NO mutex, yet it is shared between the test/request goroutine and the background rotation + reconcile workers (which run as independent goroutines via `worker.Manager`). `CreateAuthToken` writes the map (oci_client.go:99,106), `ListAuthTokens` iterates it (oci_client.go:138), `DeleteAuthToken` deletes from it (oci_client.go:124), and `TokenCount` ranges over it (oci_client.go:161) — all unguarded.

Artifact: `TestFakeOCIClient_ConcurrentAccess` (8 goroutines × 100 iterations of CreateAuthToken+TokenCount+ListAuthTokens). Under `go test -race` it reports a data race and the runtime aborts with `fatal error: concurrent map writes`:

```
WARNING: DATA RACE
Read at 0x... by goroutine 12:
  (*fakeOCIClient).CreateAuthToken()  oci_client.go:99
Previous write at 0x... by goroutine 15:
  (*fakeOCIClient).CreateAuthToken()  oci_client.go:99
...
fatal error: concurrent map writes
  (*fakeOCIClient).ListAuthTokens(...)  oci_client.go:138
```

The test is currently `t.Skip`-guarded (RED until the Task 5 fix adds a mutex to the fake); Task 5 unskips it.

**Fix applied (Task 5):** added `mu sync.Mutex` to `fakeOCIClient` and guard every field-touching method (`SetNextError`, `CreateAuthToken`, `DeleteAuthToken`, `ListAuthTokens`, `GetUser`, `TokenCount`, `TokenCountForUser`, plus the test-only `hasToken`) with `f.mu.Lock(); defer f.mu.Unlock()`. All methods are leaves (none calls another fake method), so a plain per-method lock is re-entrancy-safe. `t.Skip` removed; `TestFakeOCIClient_ConcurrentAccess` now passes under `go test -race -count=3` with no data race.

### F4 — OCI rotation-vs-reconcile delete race — REAL
Reconcile (`reconcileWorker`, workers.go:131) first snapshots the known token IDs from slot storage via `collectKnownTokenIDs` (path_reconcile.go:61), THEN — inside `reconcileOrphans` (path_reconcile.go:100) — calls `client.ListAuthTokens` upstream and deletes every prefixed token NOT in that snapshot (`reconcileRoleTokens`, path_reconcile.go:126-143). Rotation (`rotateSlot`, slots.go:154) creates the replacement token upstream (CreateAuthToken, slots.go:171), persists it to slot storage (saveSlot, slots.go:192), then deletes the old token. There is no lock serializing the two paths.

Destructive interleaving constructed (deterministically, via a `gatingClient` wrapper whose `ListAuthTokens` blocks until rotation has created+persisted its new token):

```
reconcile: collectKnownTokenIDs() -> snapshot S (old token IDs only)
reconcile: ListAuthTokens()        -> BLOCKS on gate
rotation : CreateAuthToken()        -> new token T added upstream
rotation : saveSlot()               -> T persisted to slot storage (too late for S)
reconcile: ListAuthTokens() returns -> now includes T
reconcile: T has our prefix, T not in S -> DeleteAuthToken(T)   <-- live token destroyed
```

Artifact: `TestRotationReconcileRace`. Result: the freshly-rotated live token (`ocid1.credential.oc1..fake1003`) WAS deleted by the reconcile pass — `fake.hasToken(...)` returned false and the assertion fired (`freshly-rotated live token ... was deleted by reconcile (F4 REAL)`), reproducibly across repeated runs. The slot is left pointing at a token that no longer exists upstream — a wedged credential until the next rotation.

The test is currently `t.Skip`-guarded (RED until the Task 5 fix serializes reconcile against rotation, e.g. a shared mutex or a post-list re-check of slot storage before deleting); Task 5 unskips it.

**Fix applied (Task 5):** added a dedicated `rotateReconcileMu sync.Mutex` to `backend` (NOT the request-path `b.mu`, to avoid contending issuance). It is held for the whole of:
- a slot rotation's create+persist+delete (`rotateSlot`, slots.go), and
- a reconcile pass's snapshot+list+delete — a new `runReconcilePass` helper (path_reconcile.go) takes the lock, then does `collectKnownTokenIDs` → `reconcileOrphans` as one atomic span. Both the background `reconcileWorker` and the manual `pathReconcile` now route through `runReconcilePass`, so they share the same serialization.

The snapshot MUST be inside the lock (not just `reconcileOrphans`): otherwise a rotation landing between snapshot and list still leaves the new token absent from the stale snapshot. Holding the lock across snapshot+list+delete makes the destructive interleaving impossible — rotation and reconcile now run fully serially.

Lock-ordering: `rotateReconcileMu` is the OUTERMOST lock. `b.mu` is only ever acquired-and-released INSIDE helper calls (`selectMinterForSet`, `clientForSlot`, `maxDeletesForPass`) and is never held across a rotation or reconcile body, so it can never be held while acquiring `rotateReconcileMu`. No opposite-order nesting exists ⇒ no deadlock.

**Test adjustment:** the original test forced the bad interleaving by gating reconcile's `ListAuthTokens` until rotation had persisted. With serialization that gate would deadlock (reconcile holds `rotateReconcileMu` while blocked in `ListAuthTokens`; rotation can't acquire it to persist) — a deadlocking test is a poor regression test. The test was rewritten to run rotation (`rotateSlot`) and reconcile (`runReconcilePass`) concurrently through the LOCKED entry points over 50 trials with a shared start-gate so their locked regions race to acquire the mutex in arbitrary order, asserting the freshly-rotated live token survives every trial. Verified this still catches the bug: temporarily removing both `rotateReconcileMu` Lock/Unlock pairs makes the test FAIL (`freshly-rotated live token ... was deleted by reconcile (F4 regression)`); restored, it passes under `go test -race -count=3`.

### F5 — Reconciler DeleteEntity not 404-idempotent (5 plugins) — REAL

The 5 non-Azure listers (DO, Vultr, Exoscale, UpCloud, Akamai) implemented `DeleteEntity` as `_, err := l.client.DeleteX(ctx, id); return err`, discarding the HTTP status int. Each client's delete fn errors on any non-2xx status, **including 404**. The reconciler (`pkg/reconciler/reconciler.go`) returned on the first `DeleteEntity` error, aborting the whole pass. So a single already-gone (404) orphan — a token deleted upstream out-of-band, or a lease that revoked the credential between list and delete — wedged the entire reconcile pass, leaving every later orphan uncleaned.

Artifact (red→green): `TestDeleteEntity_404IsSuccess` (credential-do, internal package). It builds a real `doCloudLister` against the DO cloud-fake (`fakes.NewDOServer`) and calls `DeleteEntity` with an id the fake doesn't hold. The fake's shared `deleteByID` helper returns `http.StatusNotFound` for an unknown id (correct semantic — confirmed in `pkg/credenvelope/fakes/respond.go`), and `doClient.DeleteToken` errors on it (`DO API delete returned 404`). Pre-fix the test FAILED with exactly that error; post-fix it passes. **Verdict: REAL.**

**Fix applied (Task 6):**
- Each of the 5 listers' `DeleteEntity` now captures the status and treats 404 as success: `status, err := l.client.DeleteX(ctx, id); if err != nil && status != http.StatusNotFound { return err }; return nil` (added `net/http` import). Delete fns: DO `DeleteToken`, Vultr `DeleteUser`, Exoscale `DeleteAPIKey`, UpCloud `DeleteToken`, Akamai `DeleteClient`. **Azure was left as-is** — its `DeleteEntity` already returns nil when the password is not found (it iterates app object IDs and returns nil if no `RemovePassword` succeeds), i.e. already idempotent.
- Defense in depth in `pkg/reconciler/reconciler.go`: a per-entity delete failure no longer aborts the pass. The failing ID is appended to a new `Result.Errors []string` field and the loop `continue`s to the next entity. Added `TestRun_DeleteErrorDoesNotAbortPass`: with a 3-orphan list where the middle one's delete errors, the pass deletes the other 2, records the failing ID in `Result.Errors`, and returns no pass-level error. (The fake lister's `ListTaggedEntities` was also made to return a copy of its slice, matching real listers, so the fake's delete-time slice mutation can't corrupt the reconciler's iteration.)
- `Result.Errors` is additive, so existing `Run` callers are unaffected. The manual `/reconcile` response in the 6 affected plugins now surfaces a `delete_errors` count for visibility.

### F6 — Create-then-track: untracked live credential on tracking-write failure — REAL

During issuance every JIT plugin first mints the upstream credential, then `req.Storage.Put`s an `active-tokens/` (or `active-users/`/`active-clients/`) tracking record. On a Put failure the plugins previously only `b.Logger().Warn(...)` and still returned the credential. Result: a live upstream credential that is untracked — the reconciler's lister can't see it via the tracking store. With the Task 3/4 fail-closed reconciler this is less catastrophic (a zero-`CreatedAt` or recent orphan is skipped), but it is still a real gap: a credential is leased yet untracked.

Artifact (red→green): `TestCredsIssue_TrackingWriteFailureCompensates` in `plugins/credential-do` and `plugins/credential-azure`. The test wraps the test `logical.Storage` in a `putFailStorage` decorator that returns an error for any `Put` whose key has the `active-tokens/` prefix and delegates everything else, then issues a credential against the cloud-fake. Pre-fix it FAILED: the DO fake's token count went up by one and the read returned a non-error response with a valid token — a live-but-untracked credential. **Verdict: REAL.**

**Fix applied (Task 7):** at the tracking-record Put-failure site, the 6 **hard-revoke** plugins now best-effort revoke the just-minted upstream credential and return `ErrInternal` instead of handing out an untrackable credential:
- DO `DeleteToken`, Azure `RemovePassword`, Exoscale `DeleteAPIKey`, UpCloud `DeleteToken`, Vultr `DeleteUser`, Akamai `DeleteClient`.
- Exoscale's tracking block was extracted into a `trackActiveKey(trackArgs)` helper to stay under the funlen/argument-count lint limits. Akamai threads the minter `client` through its `credsResponseArgs` builder struct so the builder can compensate.

**N/A for the 3 no-revoke plugins (AWS, GCP, OVH):** their tracking record is metrics-only — the credential auto-expires upstream and their reconciler never deletes an upstream entity (it only prunes already-expired local tracking entries; confirmed in `plugins/credential-{aws,gcp,ovh}/path_reconcile.go` / `workers.go`). An untracked credential there is harmless: there is nothing to reconcile/revoke and it self-expires. Forcing a failed issuance of an otherwise-valid self-expiring credential would be a regression, so these keep Warn-and-continue, with the log message clarified to state the impact is metrics-only.

All touched tests pass under `go test -race`; lint clean (golangci-lint v2, 0 issues across all touched modules); full build clean.

### F8 — pkg/worker timing tests sleep-based / flaky — REAL

`TestWorkerTicks` slept a fixed 55ms then asserted the tick count was in the band `[4,6]`; `TestWorkerInitialDelay` slept 25ms then 30ms and asserted 0-then-≥1. Both depend on real wall-clock progress under load, so the tight band flakes on a busy CI runner. **Verdict: REAL.**

**Fix applied (Task 10):** both tests converted to `testing/synctest` (GA in Go 1.26.1). Inside `synctest.Test(t, ...)` the clock is fake and advances only when every bubble goroutine is durably blocked; `synctest.Wait()` blocks until that quiescent state is reached. This makes the assertions exact rather than banded.

Scheduling semantics that fix the exact counts (read from `pkg/worker/worker.go` `run()`):
- `run()` optionally blocks on `time.After(InitialDelay)` first, then creates `time.NewTicker(interval)`. A ticker fires at the END of each interval (`t=interval, 2*interval, …`), never at `t=0`.
- `invoke()` calls `fn` inline in the run goroutine (no separate goroutine), so once `synctest.Wait()` returns the count is fully settled.

Exact assertions:
- `TestWorkerTicks` (10ms interval, no delay): advancing 5 full intervals (`t=10,20,30,40,50ms`) fires exactly **5** ticks.
- `TestWorkerInitialDelay` (30ms delay, 10ms interval): at `t=25ms` (inside the delay) exactly **0** ticks; the delay ends at `t=30ms`, the ticker's first tick is one interval later at `t=40ms`, so at `t=40ms` exactly **1** tick.

`cancel()` + `wm.Wait()` inside the bubble drains the run goroutine (it returns on `ctx.Done()`), so no lingering bubble goroutines. Verified deterministic with `go test -race -count=10 -run 'TestWorkerTicks|TestWorkerInitialDelay'` (10/10 PASS). The other five worker tests (drain/error/error-handler/panic/concurrent-start) were left as-is — they assert loose lower bounds or use their own managers and do not flake.
