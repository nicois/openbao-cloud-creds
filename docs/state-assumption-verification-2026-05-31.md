# State-Assumption Findings — Verification Report (2026-05-31)

Each finding: verdict (REAL / REFUTED / DOCUMENTED-RISK), artifact (test path or static proof), action.

| # | Finding | Verdict | Artifact | Action |
|---|---------|---------|----------|--------|
| F1 | Reconciler ConfirmationHold guard dead (6 plugins) | REAL (fixed) | static: reconciler.go:62 gated on CreatedAt, no lister set it; Task 3 fail-closed + Task 4 populates CreatedAt (4 of 6 clouds; exoscale/vultr have no list timestamp → fail-closed) | fixed (Task 3,4) |
| F2 | GCP/OVH no HTTP client timeout | REAL | static: http.DefaultClient at iam_client.go + token_client.go | fix (Task 8) |
| F3 | OCI fakeOCIClient unsynchronized map | REAL | test: TestFakeOCIClient_ConcurrentAccess (-race) | fix (Task 5) |
| F4 | OCI rotation-vs-reconcile delete race | REAL | test: TestRotationReconcileRace | fix (Task 5) |
| F5 | Reconciler DeleteEntity not 404-idempotent (5 plugins) | TBD | Task 6 | — |
| F6 | Create-then-track: untracked live cred on Put failure | TBD | Task 7 | — |
| F7 | Azure addPassword Graph propagation lag | TBD | Task 9 | — |
| F8 | pkg/worker tests sleep-based / flaky | REAL | static: worker_test.go fixed sleeps + [4,6] band | fix (Task 10) |

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

Proof per cloud (each red→green): `TestReconcile_PopulatesCreatedAt` in `plugins/credential-{do,upcloud,azure,akamai}/created_at_test.go` (was RED — zero `CreatedAt` — before the lister mapped the field; GREEN after). End-to-end Task3+Task4 proof: `TestReconcile_CreatedAtDrivesDeleteVsSkip` drives the real lister through `reconciler.New(Config{ConfirmationHold: 1h}).Run` with an all-orphans registry — a fake entity stamped 2h old IS deleted, one stamped 5m old is SKIPPED (verified for all four timestamp-bearing clouds). Exoscale/Vultr have no such test because they have no list timestamp to populate; their worker-path orphans remain protected (uncleaned) by the fail-closed guard, an accepted residual gap recorded here.

### F2 — GCP/OVH lack client-side HTTP timeout
GCP issues requests via `http.DefaultClient.Do(req)` at `plugins/credential-gcp/iam_client.go:156` and `:208`; OVH via `http.DefaultClient.Do(req)` at `plugins/credential-ovh/token_client.go:63`. `http.DefaultClient` has no `Timeout` set, so a hung upstream can block indefinitely. By contrast DO (representative of the other 7 plugins) builds its client with an explicit timeout: `plugins/credential-do/do_client.go:13-14` defines `const httpTimeout = 30 * time.Second` and lines 48-49 construct `&http.Client{ Timeout: httpTimeout }`. Verdict: REAL.

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
