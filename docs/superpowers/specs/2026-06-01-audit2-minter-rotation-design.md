# Audit-2 Effort 4b: Minter Self-Rotation (#9, part 2) — Design Spec

**Status:** Approved (2026-06-01)
**Scope:** Operator-initiated rotation of the long-lived "minter" credentials, for the clouds whose API can mint a successor of the minter's own kind. The second of two sub-efforts from audit #9. **4a (done):** observability. **4b (this spec):** a `MinterRotator` capability + a manual `rotate` endpoint + grace-based retirement so a rotation never wedges cluster-wide issuance. Automatic (scheduled) rotation is explicitly deferred to a possible **Effort 4c**.

Verified against the code at HEAD `f2d253c` during brainstorming (file:line below). TDD; fake-based tests only (the repo has no real-cloud accounts — audit #7; this subsystem ships exercised against the cloud-fakes, a stated, documented limitation).

## Verified constraints that shaped this design

1. **Self-rotation = mint a _successor minter_** (a new long-lived credential of the minter's own privileged kind), distinct from the JIT mint path. DO's `CreateToken` (`do_client.go:55`) mints a *scoped JIT token*, NOT a successor PAT — so `RotateMinter` is genuinely new per-cloud client code, not a reuse. Minter IDs are operator-supplied (`path_minter_sets.go:54`), so the successor needs a **generated** ID.
2. **Per-cloud feasibility varies** (`docs/cloud-credential-research.md`):
   - **Feasible (clean overlap — both old + new valid simultaneously):** DigitalOcean, UpCloud (PAT mints PAT), Azure (`addPassword` adds a 2nd secret to the same app), GCP (`serviceAccountKeys.create`, ≤10 keys), Akamai (API client mints API client if granted), Exoscale (API key mints API key with the key-mgmt role).
   - **Not feasible:** OVH (its OAuth2 `client_credentials` grant mints short-lived *access tokens*, not new client credentials), Vultr (one account-wide API key; regenerating invalidates the old immediately — no overlap).
   - **Quota-constrained, deferred:** AWS (2 access keys/user hard limit), OCI (minter-user creds 2-token-tight; OCI already slot-rotates *issued* tokens).
   So the 6 feasible clouds implement rotation; OVH/Vultr/AWS/OCI reject the rotate request with a clear message.
3. **No periodic minter-set reload.** `b.minterSets` is loaded only at `Factory` and at minter-set write (`backend.go:81`, `path_minter_sets.go:94`); workers do NOT reload from storage. So on a raft cluster, a rotation performed on one node is invisible to other nodes' in-memory snapshots until they reload (restart/failover/minter-set write). **Immediately deleting the old upstream credential would wedge issuance on every other node** (KI-001 class). → retirement MUST be grace-separated.
4. **The reconciler must NOT delete operator-provided minters** (techrfc OBC-007 + the owner-tag safety invariant). The retired-minter deletion is therefore a SEPARATE path keyed off an explicit `RetiredAt` marker, never folded into the orphan reconciler's owner-tag logic. The 7-day grace + `retired_at` model mirrors OBC-007's existing "rotated-out credentials deleted after 7-day grace."

## Data model (`pkg/cloudconfig`)

```go
type Minter struct {
    // ... existing fields ...
    Retired   bool      `json:"retired,omitempty"`
    RetiredAt time.Time `json:"retired_at,omitempty"`
}
```
- `PluginConfig` gains `MinterRetireGrace time.Duration` (json `minter_retire_grace`), default `MinMinterGap` (7d) in `DefaultConfig`. Per-plugin `minter_retire_grace` config field (TypeDurationSecond), mirroring 4a's `minter_expiry_warn`.
- **`ValidateMinterSet` change:** retired minters are EXCLUDED from the `(≥1 never_expires) OR (≥2 with ≥7d gap)` rule — the rule must hold among the *active* (non-retired) minters. Consequence: a rotation that would retire a minter is REJECTED upfront if doing so leaves the set unable to validate (i.e. the set must have enough live capacity to lose one). This keeps the isolation/availability invariant intact during rotation.

## `MinterRotator` capability (per-plugin)

Each feasible plugin's minter client implements:
```go
// RotateMinter mints a successor credential of the same kind/privilege as `old`
// and returns the new Minter (with Token populated and a freshly generated ID).
// The successor must itself be able to mint (so the set stays rotatable).
RotateMinter(ctx context.Context, old cloudconfig.Minter) (cloudconfig.Minter, error)
```
- 6 feasible clouds implement it (new client method + the cloud API call).
- OVH/Vultr/AWS/OCI do NOT implement it; their rotate endpoint returns a clear rejection (reuse an EXISTING error code — `ErrUpstreamAuthFailed` is wrong; use `ErrInternal` is wrong too; **use `logical.ErrorResponse` with a plain 400-style message** "minter rotation is not supported for <cloud>; rotate this minter out-of-band" — NO new error_code constant, since the frozen 10-set has no "unsupported" code and adding one is a spec change. The response is a normal `logical.ErrorResponse`, not an envelope error_code).
- Successor ID generation: `fmt.Sprintf("%s-rot-%d", old.ID, <monotonic-ish suffix>)` — but since `Math.random`/wall-clock-in-suffix is fine here (real runtime, not a workflow), use a short random/time-based suffix; the implementer picks a collision-free scheme (e.g. old.ID + "-" + base36(unixnano)) and asserts uniqueness against the existing set.

## Manual endpoint

`POST cloud-creds/<cloud>/minter-sets/<set>/rotate` with field `minter_id` (required). Orchestration (a shared helper per plugin, structurally identical — mirrors OCI's `rotateSlot` create→persist→delete discipline, `slots.go:163`):

1. Load the set; find `minter_id` (404-style error if absent).
2. Compute the post-rotation active set (old marked retired, successor added) and run `ValidateMinterSet` on it — reject (400) if it would not validate.
3. Build a client from a healthy ACTIVE minter (or the one being rotated, if healthy); call `RotateMinter(old)` → successor. On error, return a rejection (no partial state written).
4. **Validate the successor**: build a client from the successor's token, call its health-check. If it fails, best-effort-delete the successor upstream and return an error (no set change).
5. Swap under the appropriate lock (mirror `rotateReconcileMu` discipline so a concurrent reconcile can't delete the fresh successor before it's persisted): append successor (active), mark `old.Retired=true, old.RetiredAt=now`; persist the set to storage; reload local in-memory (`loadMinterSet`).
6. Return success: `{successor_id, retired_minter_id, retired_at}`.

Endpoint exists on all 10 plugins for a uniform API surface, but on OVH/Vultr/AWS/OCI it returns the "not supported" rejection at step 3 (before any state change).

## Selection + retirement sweep

- **`selectMinter` / `selectMinterForSet` / `anyHealthyMinter*` (all 10):** skip `Retired` minters for NEW issuance. One-line guard (`if ms.minter.Retired { continue }`) added alongside the existing `Selectable(now)` check. Cheap, defensive, uniform — even on clouds that can't create retired minters (the field exists on the shared struct).
- **Retired-sweep worker (the 6 feasible clouds):** on the existing reconcile cadence, for each minter with `Retired && now > RetiredAt + MinterRetireGrace`: delete the UPSTREAM old credential (client built from a healthy active minter, or the retired token if still valid) and remove it from the set (persist + reload). Keyed STRICTLY off `RetiredAt` — a separate code path from the orphan reconciler, which keeps its conservative owner-tag-only deletion. If the upstream delete fails, leave the entry (retry next pass) and warn-log; never drop it from the set without confirming the upstream delete (or a 404 = already gone).

## Testing (fake-based)

- **`pkg/cloudconfig`:** `Retired` round-trips; `ValidateMinterSet` excludes retired minters (a set valid only because of a retired minter FAILS); `MinterRetireGrace` default = `MinMinterGap`.
- **Per feasible plugin (DO reference; replicas for the other 5):**
  - rotate happy-path: successor minted (fake returns a new token), validated, swapped in; old marked retired; `selectMinter` now skips the retired one and returns the successor/another active.
  - rotate rejected when retiring would break validation (e.g. a 2-minter set where retiring one leaves <2 active and none never_expires).
  - rotate rejected when `RotateMinter` errors (fake error knob) — no set change.
  - rotate rejected when the successor fails its post-mint health-check — successor best-effort-deleted, no set change.
  - retired-sweep: a retired minter past `RetiredAt + grace` is upstream-deleted + dropped (injected clock / synctest); one NOT past grace is left untouched (cross-node-safety: stays upstream-alive).
  - config round-trip of `minter_retire_grace`.
- **All 10:** `selectMinter` skips a `Retired` minter.
- **Unsupported (OVH/Vultr/AWS/OCI):** the rotate endpoint returns the "not supported" rejection without mutating the set.
- **Full gate:** 20 modules build / `go test -race` / golangci-lint v2.12.2 (binary at `/home/claude-aiven-2/code/qualcheck/bin/golangci-lint`) 0 issues / `make smoke-test` 10/10; no new `//nolint`.

## Risk

- **Highest of the four efforts** — mints AND deletes live crown-jewel credentials, fake-only tested. Mitigations: (1) grace-based retirement → no immediate upstream delete → no cross-node wedge; (2) successor validated before the swap; (3) retired-sweep keyed off explicit `RetiredAt`, separate from the conservative orphan reconciler (the owner-tag safety invariant is untouched); (4) rotation refused upfront if it would break set validation; (5) unsupported clouds fail closed with a clear message before any state change; (6) the create→persist→delete lock discipline mirrors the proven OCI `rotateSlot` (audit F4).
- **Known residual:** because there is no cross-node "reload now" signal, the grace must exceed the worst-case node-reload interval. Default 7d is generous; documented. A node that never reloads within the grace (no restart/failover/minter-set-write) would still select a retired-then-deleted minter after the sweep — but 7d without any reload across a raft cluster is operationally implausible, and the 4a `minter_age_seconds`/retired signals + the warn-log surface it. Documented in `decisions.md`.
- No envelope/error-contract change; no `api_version` bump; no new error_code constant (unsupported-cloud uses a plain `logical.ErrorResponse`).

## Success criteria

1. `cloudconfig.Minter` has `Retired`/`RetiredAt`; `ValidateMinterSet` excludes retired minters; `PluginConfig.MinterRetireGrace` defaults to 7d, round-trips via `minter_retire_grace`.
2. 6 feasible plugins implement `RotateMinter` + the `rotate` endpoint (mint successor → validate → swap → mark retired); OVH/Vultr/AWS/OCI reject with a clear message and no state change.
3. All 10 `selectMinter` paths skip retired minters for new issuance.
4. The 6 feasible plugins' retired-sweep deletes the upstream old credential + drops it from the set only after `RetiredAt + grace`; before the grace it stays upstream-alive (cross-node safe). The orphan reconciler's owner-tag deletion is unchanged.
5. Whole workspace build / `go test -race` / `make lint` / `make smoke-test` green; all 20 modules 0 lint; no new `//nolint`.

## Sequencing rationale (why build before real-cloud testing)

Building rotation now — rather than waiting for real-cloud test infrastructure — is deliberate: deferring it would force the rotation logic to be designed, reviewed, and merged later *and then* re-validated, repeating work. With the subsystem in place, the future real-cloud pass (audit #7, using **disposable accounts**) validates a finished feature in one go. That future pass should also add **record/replay instrumentation** so real-cloud API interactions can be captured once and replayed deterministically in e2e tests — turning the one-time disposable-account runs into durable regression fixtures. That instrumentation is out of scope for 4b (it belongs with the #7 real-cloud effort) but is the intended companion to it.

## Out of scope (→ Effort 4c, the #7 real-cloud effort, or never)

- **Automatic/scheduled rotation** (a worker that rotates within N days of expiry) — deferred to a possible 4c; 4b is operator-initiated only.
- Rotation for OVH/Vultr (API-impossible), AWS/OCI (quota-tight) — they stay operator-managed out-of-band; the 4a observability surfaces staleness.
- Real-cloud integration tests with disposable accounts + **record/replay instrumentation** for deterministic e2e replay (audit #7) — the intended next validation pass for this subsystem; deferred, not abandoned.
- Changing the `MinMinterGap` validation constant or the response envelope.
