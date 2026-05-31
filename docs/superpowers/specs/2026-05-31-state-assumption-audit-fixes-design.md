# State-Assumption Audit Fixes — Design Spec

**Status:** Approved (2026-05-31)
**Goal:** Verify, then fix, a class of bugs where code assumes backend/upstream/goroutine state without confirming it — surfaced by an audit prompted by a CI smoke-test flake.

## Origin

A CI smoke-test failure ("mount is absent" right after a successful `enable`) was a read-after-write assumption about backend state. That motivated a three-front audit (test infrastructure, storage/internal state, upstream/cloud state) for the same bug class. The audit produced one statically-verified bug and several reported-but-unverified findings. This effort treats verification as a gate: only confirmed-real findings are fixed.

The CI flake itself is already addressed separately (commit `bdcb5a1`: golangci-lint install pinned to the release tag; smoke-test readiness gate that polls until the mount subsystem round-trips a write-then-read). This spec covers the deeper findings.

## Decisions taken (from brainstorming)

- **Verification policy:** verify-first, then scope. Each finding gets a verdict (REAL / REFUTED / DOCUMENTED-RISK) with a repro artifact or static proof *before* any fix is designed. Refuted findings are documented and dropped — no fixing phantom bugs, no relaying unverified claims as fact.
- **synctest role:** `testing/synctest` (stable since Go 1.25; repo is on 1.26.1) is the deterministic verification mechanism for concurrency findings, AND the sleep-based `pkg/worker` tests get converted to it as a durable improvement. It is NOT forced onto tests that aren't pure-Go internal-state (HTTP-fake-driven plugin tests stay as-is).
- **Fix appetite:** fix every verified-real finding, severity-ordered (credential-loss → correctness → robustness). The reconciler fix gets extra test scrutiny since it touches the load-bearing owner-tag delete-safety invariant.
- **DOCUMENTED-RISK is a valid verdict** for findings that cannot be reproduced without a real cloud (e.g. Azure Graph replication lag) — flagged honestly rather than given a synthetic test.

## Phase A — Verification (gates Phase B)

For each finding, produce: a reproducing test that fails against current code, OR a static proof, OR a refutation. Output is a verification report mapping finding → verdict → artifact → true severity. Only REAL findings flow to Phase B.

### A1. Static-provable
- **Dead `ConfirmationHold` guard** — `pkg/reconciler/reconciler.go:62` gates the orphan-grace window on `!entity.CreatedAt.IsZero()`, but all six hard-revoke listers (`plugins/credential-{do,azure,vultr,exoscale,upcloud,akamai}/reconciler_integration.go`) build `UpstreamEntity{ID, Name}` and never set `CreatedAt`. The guard is therefore unreachable; the `ConfirmationHold: 1*time.Hour` set in each `workers.go` is inert. **Verdict: REAL (statically confirmed this session).** Re-confirm at implementation time.
- **GCP/OVH no client-side HTTP timeout** — `plugins/credential-gcp/iam_client.go` and `plugins/credential-ovh/token_client.go` use `http.DefaultClient` (no `Timeout`), unlike the 30s timeout in the other eight clients. Static grep confirms.

### A2. synctest deterministic repro (concurrency)
- **OCI rotation-vs-reconcile race** — a `synctest` test starting both workers against the in-process OCI fake; drive the fake clock to force the interleaving (reconcile snapshots known-set → rotation persists new token → reconcile lists upstream and sees the new token absent from its snapshot). Assert whether the just-rotated token is deleted. Deleted → REAL; already-guarded → REFUTED.
- **OCI in-process fake unsynchronized map** (`plugins/credential-oci/oci_client.go` `fakeOCIClient.tokens` has no mutex) — confirm via `-race` whether a worker tick concurrent with `TokenCount()` trips the detector; synctest can force a tick inside the window.

### A3. Reproducing functional test (upstream consistency)
- **Reconciler `DeleteEntity` not 404-idempotent** — drive a reconcile pass via the cloud-fake with an entity that returns 404 on delete (already gone). Assert whether the pass aborts (`reconciler.go:78` returns on first error) → REAL, or continues → REFUTED. Affects DO, Vultr, Exoscale, UpCloud, Akamai (Azure's `DeleteEntity` already swallows errors — expected REFUTED for Azure).
- **Create-then-track Put-failure compensation** — inject a storage `Put` failure on the `active-tokens/` write; assert whether a live upstream credential is left untracked (REAL) and whether compensation exists.
- **Azure addPassword propagation** — Graph replication lag cannot be reproduced against the fake. **Expected verdict: DOCUMENTED-RISK**, not a synthetic test.

## Phase B — Fixes (severity-ordered, verified findings only)

Each fix lands with its Phase-A repro flipping red→green.

### B1. Credential-loss tier

**Reconciler `ConfirmationHold` — fail-closed core + per-cloud precision layer.** Two coordinated changes:

1. **Fail-closed guard (safety-critical core).** Invert the current fail-open behavior. When `ConfirmationHold > 0` and `entity.CreatedAt.IsZero()`, treat the entity as not-yet-confirmable and **skip the delete this pass** (do not classify it as a deletable orphan). Worst case becomes "an orphan survives one extra pass," never "a live credential is deleted." This strictly reduces deletion aggressiveness — it can never delete more than today, only less. This change alone closes the live-credential-deletion window.

2. **Populate `CreatedAt` from each cloud's list response** where the API provides it (DO/UpCloud token `created_at`, Azure passwordCredential `startDateTime`, Akamai `createdDate`, and Exoscale/Vultr where available) so the hold is precise and real orphans are still cleaned after it elapses. Where a list omits a timestamp, the fail-closed guard (#1) governs; optionally back it with a "seen in a prior pass" two-pass confirmation.

Invariant shift: **delete only what is both an orphan AND confirmably old enough; absent age info, do not delete.** Each plugin's existing `TestReconcile_NeverDeletesForeignEntity` stays green; add a test proving a fresh / within-hold / zero-`CreatedAt` entity is NOT deleted.

**OCI rotation/reconcile races** (if A2 confirms): serialize rotation and reconcile (shared mutex, or run them on one worker), and add the missing mutex to `fakeOCIClient`. synctest test flips red→green.

### B2. Correctness tier
- **`DeleteEntity` 404-idempotency:** each affected plugin's `DeleteEntity` ignores a 404 from the upstream delete (already gone = success), and the reconciler logs-and-continues per-entity rather than aborting the whole pass on first error (`reconciler.go`).
- **Create-then-track compensation:** on `active-tokens/` Put failure during issuance, best-effort delete the just-created upstream credential (and fail the issuance) rather than returning a live-but-untracked credential.
- **Azure propagation:** DOCUMENTED-RISK — document the Graph-replication caveat; optionally a short verify-with-backoff before returning the secret (decide at implementation time; documentation is the floor).

### B3. Robustness tier
- **GCP/OVH HTTP timeout:** give both clients `&http.Client{Timeout: 30s}`, matching the other eight, while still honoring ctx.

## Phase C — Test-discipline upgrade

Convert the sleep-based `pkg/worker` tests (`worker_test.go` — `TestWorkerTicks`' `[4,6]` tick-count band and the `time.Sleep`-then-assert patterns) to `testing/synctest`: fake-clock bubble, deterministic tick advancement, assertions that hold because time only advances when all goroutines are durably blocked. Kills the known CI flake risk with no real sleeps. Leave HTTP-fake-driven plugin tests as-is.

## Out of scope
- **Metrics cross-node merge being inert** (in-memory store + constant `nodeID="local"`): Phase A may confirm it, but it is a feature-gap/architecture question, not a credential-safety bug. Document it; do not fix here unless explicitly added.
- **Apache→MPL relicensing / OpenBao upstream conformance** — precluded by the AI-authorship ban (see `reference_openbao-upstream-ai-ban`); not part of this effort.
- The CI smoke-test / golangci-lint install fixes — already committed (`bdcb5a1`), pending push (read-only repo access).

## Success criteria
1. A verification report exists with a verdict + artifact for every audit finding; only REAL findings were fixed.
2. The dead `ConfirmationHold` guard is fixed fail-closed; a reconcile pass provably never deletes a fresh/unconfirmable entity, and the existing foreign-entity safety tests stay green.
3. Any verified OCI race has a deterministic synctest repro that is red before the fix and green after.
4. Verified 404-idempotency / compensation / timeout findings are fixed, each with a test.
5. `pkg/worker` timing tests run under synctest with no fixed sleeps.
6. Whole workspace: `go build`, `go test -race`, `make lint`, `make smoke-test` all green; all 17 modules still 0 lint issues.
