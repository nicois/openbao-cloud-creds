# Project context for AI agents

## What this is

OpenBao plugins that issue short-lived, role-scoped cloud credentials with a uniform API across cloud providers. Open-source (Apache 2.0).

**Documents (note: the original RFC predates implementation and is partly stale):**
- [`docs/techrfc.md`](docs/techrfc.md) — original formal RFC (requirements, API, risks). Written before any code; its per-cloud strategy table and "follow-up RFC" status notes are STALE (all 10 plugins now exist; the native-wrapper strategy was abandoned). Still authoritative for the response-envelope contract and error-code model.
- [`docs/design.md`](docs/design.md) — companion with worked examples and detailed rationale (same caveat as the techrfc).
- [`docs/decisions.md`](docs/decisions.md) — short rationale notes for design choices.
- [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md) — what each cloud's API actually supports; authoritative for per-cloud strategy.
- [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md) — object-storage viability (out of scope, but analysed; DO Spaces section revised 2026-08-21).
- [`docs/do-api-verification-2026-08-21.md`](docs/do-api-verification-2026-08-21.md) — re-verification of the DO assumptions behind the reference plugin: `/v2/tokens` is undocumented, scopes are fine-grained, Spaces keys are now API-issuable.
- [`docs/minter-capability-verification.md`](docs/minter-capability-verification.md) — authoritative for the capability probe: why health ≠ capability, the three probe points, the per-cloud probe/cost table, why OCI is not probed, and what was deliberately excluded.
- [`docs/ttl-semantics.md`](docs/ttl-semantics.md) — authoritative per-cloud TTL matrix: what a lease TTL means on each cloud, which bounds are enforced at role write, and where a credential can outlive its lease.
- [`docs/openbao-integration-gaps.md`](docs/openbao-integration-gaps.md) — authoritative for what each test layer proves: which gaps `e2e/` closes, which remain (G1–G9), and where each is tracked.
- [`docs/free-account-viability.md`](docs/free-account-viability.md) — per-cloud free/trial account viability for a real-cloud pass (what privilege each minter needs, cost, confidence), plus the CI-secrets + record/replay design for validating the fakes. Akamai is the one cloud that cannot be obtained free.

For the *envelope/error contract*, the techrfc wins. For *what is built and which strategy each cloud uses*, this file and `docs/cloud-credential-research.md` win — the techrfc's implementation-status claims are outdated.

## Mental model

Two strategies, chosen per cloud based on whether the cloud's native API supports headless per-request short-lived token creation:

| Strategy | Used by | How it works |
|----------|---------|--------------|
| **JIT** (mint on read, revoke on lease end) | DigitalOcean, AWS, GCP, Azure, OVH, Exoscale, Vultr, Akamai, UpCloud | Plugin holds a long-lived "minter" credential; per-read it calls the cloud API to mint a short-lived credential and stores the upstream ID in lease `internal_data` for revoke. Clouds whose tokens expire naturally (AWS STS, GCP impersonation, OVH OAuth2 tokens) need no revoke call; the rest (DO, UpCloud, Azure, Exoscale, Vultr, Akamai) hard-revoke the upstream credential on lease end. |
| **Phased rotation** (N slots rotated on schedule with phase offsets) | Oracle (OCI) | Plugin pre-provisions N credentials per role; rotates one every T/N. Reads return the freshest. Lease TTL = time until that slot's next rotation, so TTL is always honest. Used where per-user credential quotas are too low for JIT (OCI caps at 2 auth tokens/user). |

DO was the reference implementation: it exercises every load-bearing piece (envelope, lease tracking, recovery state machine, reconciler, metrics). All other plugins follow its structure.

**The "Native engine wrapper" strategy described in the techrfc was abandoned.** Investigation (see `docs/cloud-credential-research.md`) found OpenBao has NO GCP or Azure secrets engine, and only partial AWS support (IAM-user `iam_tags` but no STS `session_tags`). So AWS/GCP/Azure are implemented as full JIT plugins calling the cloud APIs directly, not as thin wrappers. The techrfc's strategy table is stale on this point; this file and `docs/cloud-credential-research.md` are authoritative for what was actually built.

## Status of each plugin

All ten plugins are implemented, tested, lint-clean (golangci-lint v2), build as deployable binaries, and pass the OpenBao registration smoke test (`make smoke-test`). None are scaffolds or stubs.

| Plugin | Strategy | Notes |
|--------|----------|-------|
| `credential-do` | JIT | Reference implementation; `POST /v2/tokens` (**undocumented endpoint** — see note below); **hard revoke** (`DELETE /v2/tokens/{id}`) |
| `credential-aws` | JIT | STS AssumeRole (direct, not the OpenBao AWS engine); **no revoke** (STS expires) |
| `credential-gcp` | JIT | SA impersonation, `generateAccessToken`; **no revoke** (token expires) |
| `credential-azure` | JIT | Graph API `addPassword` on existing app registrations; **hard revoke** (`removePassword`) |
| `credential-ovh` | JIT | OAuth2 `client_credentials` token minting; **no revoke** (1h tokens) |
| `credential-upcloud` | JIT | `POST /1.3/account/tokens`, native `expires_in` TTL; **hard revoke** (`DELETE .../tokens/{id}`) |
| `credential-exoscale` | JIT | `POST /api-key` scoped to an IAM role; **hard revoke** (`DELETE /api-key/{id}`) |
| `credential-vultr` | JIT | sub-user creation, `POST /v2/users`; **hard revoke** (`DELETE /v2/users/{id}`) |
| `credential-akamai` | JIT | EdgeGrid-signed API-client creation (CDN/Identity API — NOT Linode Object Storage); **hard revoke** (delete API client) |
| `credential-oci` | Phased rotation | OCI auth tokens, N=2 slots; the only non-JIT plugin; **soft revoke** (slot lives until scheduled rotation) |

Revoke summary: **hard revoke** (deletes upstream on lease end) — DO, UpCloud, Azure, Exoscale, Vultr, Akamai. **No revoke** (credential expires naturally) — AWS, GCP, OVH. **Soft revoke** (phased rotation) — OCI.

**TTL semantics (`docs/ttl-semantics.md` is authoritative).** A TTL must be enforceable either by a mint-time lifetime (AWS `DurationSeconds`, GCP `lifetime`, Azure `endDateTime`, UpCloud `expires_in` — all set from the role TTL) or by hard revoke (DO, Exoscale, Vultr, Akamai — whose credentials have **no** upstream expiry, so revoke plus the owner-tag reconciler is the only bound). Unenforceable TTLs are rejected at role write: **AWS 900s–43200s**, **GCP ≤43200s**, **UpCloud ≤8760h**, **OVH exactly 3600s** (fixed 1h token, no revoke API — so neither longer nor shorter is honest). No floor is invented where the cloud documents none. Leases are non-renewable wherever the credential's expiry is fixed at mint (AWS, GCP, OVH, Azure, UpCloud, OCI); DO/Exoscale/Vultr/Akamai stay renewable because renewal just defers the revoke. OCI is the one deliberate "credential outlives lease" case (slot lives until its scheduled rotation); no plugin lets a lease outlive its credential (techrfc OBC-002).

**DO API facts (re-verified 2026-08-21 — `docs/do-api-verification-2026-08-21.md`):** `POST /v2/tokens` / `DELETE /v2/tokens/{id}` are **not in DigitalOcean's public OpenAPI spec**; DO documents PAT creation as control-panel-only, so the reference plugin depends on a control-panel-internal endpoint (accepted, documented risk — the OAuth alternative needs interactive auth and can't mint headlessly). Don't cite `/v2/tokens` as public API. DO scopes are **fine-grained** `<resource>:<verb>` (`droplet:create`, `spaces_key:create_credentials`, …), not coarse `read`/`write`; role `scopes` is an unvalidated pass-through string, so new scopes need no code change, but the minter must itself hold every scope it grants. There is still no PAT-management scope, so DO minter self-rotation remains infeasible.

Object-storage credentials (S3-style backup keys) are explicitly **out of scope** — see `docs/object-storage-credential-audit.md` for the viability analysis and why. Note that audit's DO Spaces section was revised 2026-08-21: `/v2/spaces/keys` **is** now public (full CRUD, per-bucket `grants`, secret-once-on-create, `created_at`), so the "no API" blocker is gone; object storage is simply not built here and DO's 200-keys/account cap rules out the long-lived per-customer case.

## Genealogy

This work originated inside an internal multi-cloud OpenBao raft cluster spike (6 clouds, Shamir seal on every node, WireGuard mesh). That infrastructure lives in a separate (private) repository. **This repo is the open-source extraction of just the credential-issuance plugins** — the cluster operations, terraform, CA, and seal management belong to the spike, not here.

If you find references in commit history or older notes to:
- "Aiven", "aiven-creds", "SRE-12109" — those are the upstream private project; ignore them.
- "the spike", "the multi-cloud raft cluster" — that's the infrastructure where these plugins were originally prototyped; not part of this repo.

## Build / test / lint

Go workspace (`go.work`) with per-module `go.mod`; use the full module path, not `./...` (which doesn't resolve across workspace modules):

```bash
go build github.com/nicois/openbao-cloud-creds/...
go test -race github.com/nicois/openbao-cloud-creds/...
make test-conformance  # the cloud × category matrix + the shared suites over all ten plugins
make test-e2e      # plugin binaries in a live OpenBao, driven over HTTP through the lease lifecycle (needs `bao`)
make lint          # golangci-lint v2 (pinned v2.12.2) across every module — config in .golangci.yml; plus a --build-tags=e2e pass over TAGGED_LINT_DIRS (a tagged module is invisible to plain lint)
make smoke-test    # build each plugin + register/enable in a live OpenBao dev server (needs `bao` on PATH)
```

The documented real-cloud test (`go test -tags=cloud_real ./plugins/credential-do/...`) currently runs **zero tests — no file carries that build tag**. Don't cite it as coverage. The plan (per-cloud free-account viability, CI secret/environment layout, and record-replay so real interactions become fixtures the fakes are checked against) is `docs/free-account-viability.md`; nine of ten clouds are exercisable for ~free, Akamai is not.

## Conventions

- Go 1.26.1 (workspace `go.work` + per-module `go.mod`)
- One plugin = one Go module under `plugins/<name>/`
- Shared code under `pkg/` — plugins import; never the other way around. Genuinely-identical helper bodies are extracted into focused `pkg/` packages with cloud identity passed as a parameter (e.g. `pkg/telemetry` for metric emitters, `pkg/metricspath` for the metrics query endpoints, `pkg/localexpiry` for no-revoke local-entry pruning), preserving per-plugin module isolation — never collapse the plugin modules themselves
- Each plugin keeps a `consts.go` defining its `cloudName`, `metricNamespace`, and field-name constants (`fieldCloud`/`fieldRole`/`fieldMinterSet`/…); HTTP status codes use `net/http` constants and TTL/duration values are named consts (no magic numbers/literals — enforced by lint)
- Mount path is always `cloud-creds/<cloud>/...`
- Owner-tag scheme always uses prefix `cloud-creds-<role>-` or label `owner=cloud-creds`
- Every error response includes a stable `error_code` (Go constants in `pkg/credenvelope/errors.go`); adding one is a spec change
- Clients pin to `metadata.api_version` in the response envelope (currently `"2"`)
- **Testing is conformance-first — read `AGENTS.md` before writing a test.** Every cloud-agnostic invariant lives once in `pkg/plugintest` as a suite over `plugintest.Harness`, and runs against all ten plugins from the `conformance/` module's single `registry` table. Six categories: `reload` (KI-001 class: config set in `pathConfigWrite` but not reloaded in `Factory`; also drives `InitializeFunc` twice — KI-007), `lease` (envelope↔lease agreement on renewability and TTL, `internal_data` JSON survival — KI-008; no cloud may opt out), `perturbation` + `revoke` (KI-002 class revoke-wedging), `capability` (probe rejects an incapable minter at write time), `reconciler-safety` (owner-tag invariant, `dry_run` deletes nothing). A new plugin is not complete until it is in that table — `TestEveryPluginIsRegistered` fails otherwise. A category that genuinely does not apply to a cloud is declared in `Harness.Skips` with a reason and printed by `TestConformanceMatrix`; **never** `t.Skip` a category inline. `Harness.Inject` is re-applied on reload, so AWS/GCP/OCI no longer skip the reload category (that residual gap is closed). Per-cloud vocabulary — mint shapes, deny knobs, unexported-symbol tests — stays in the plugin's own `*_test.go` and the fakes. Background: `docs/superpowers/specs/2026-05-30-resilience-test-taxonomy-design.md`.
- **Above conformance sits `e2e/`** (build tag `e2e`, own module): each plugin built as a binary, registered in a live `bao server -dev`, driven over HTTP through config → minter set → role → issue → lease lookup → renew → revoke → `plugin reload` → re-issue, with the cloud fake in the test process. It covers what in-process tests structurally cannot — the JSON-serialized plugin RPC boundary and OpenBao core (mount table, expiration manager, core-assigned `req.ID`) — and found KI-007/KI-008 within an hour of existing. 7 of 10 clouds; AWS/GCP/OCI are declared gaps in its registry (client injection, not an HTTP endpoint; OCI signing is a stub). **When e2e finds a bug, the regression guard ships in `pkg/plugintest`, not in `e2e/`** — that's how the `lease` category came to exist. Layer-by-layer coverage and the open gaps: `docs/openbao-integration-gaps.md`.
- **Workers start in `InitializeFunc`, never in `Factory`** (`b.initialize` loads config + minter sets then calls `startWorkers`). `Factory` also runs for config-less constructions that must not touch the network; `Initialize` is the hook core calls after mount setup, unseal and plugin reload. It must stay idempotent.
- **A non-renewable secret registers no `Renew` callback at all.** `framework.Secret.Renewable()` is `(Renew != nil)`, and OpenBao **revokes a lease whose renewal fails** — so a callback that only returns an error still advertises `renewable=true` and destroys the client's credential. Never "fix" that by assigning `resp.Secret.Renewable = false` (two sources of truth that can drift); remove the callback. Renewable: DO, Exoscale, Vultr, Akamai only.

## Minter sets

Minters are grouped into named **sets** at `cloud-creds/<cloud>/minter-sets/<name>` (write/read/delete/list), each independently validated by the `(≥1 never_expires) OR (≥2 with ≥7d gap)` rule — evaluated over the set's **active** (non-retired) minters. The bare `config` endpoint holds operational + cloud settings only (NO minters). Every role has a **required** `minter_set` field and mints only from that set — there is no cross-set failover for issuance, by design (it is the isolation boundary). The reconciler, by contrast, cleans orphans across all sets by owner-tag (`anyHealthyMinter`). The issuing set+minter are recorded in `metadata.minter_set`/`minter_id` (envelope api_version 2) and in lease internal_data. OCI (phased rotation) binds each rotation slot to the role's set and records the provisioning set+minter on the slot. For capability isolation, give each set's minters only the upstream rights its bound roles need (e.g. an Azure SP authorized for one app registration). Backend worker lifecycle is serialized by a per-backend `workerLifecycleMu` (start/stop never overlap).

**Minter lifecycle (audit-2, 2026-06-01).** Every minter carries `CreatedAt` and (since rotation) optional `Retired`/`RetiredAt`/`RotationParams` fields. Observability: `emitMinterMetrics` (health-check cadence) emits `cloud_creds_minter_age_seconds` for *every* minter incl. `never_expires`, and warn-logs within the configurable `minter_expiry_warn` (default `MinMinterGap`=7d) of an expiring minter's expiry. **Self-rotation:** `minter-sets/<name>/rotate` (field `minter_id`) is the uniform endpoint on all 10 plugins; the 6 feasible clouds (Azure ref, UpCloud, AWS, Akamai, GCP, Exoscale) implement `RotateMinter` (mint a mint-capable successor → validate-prospective-set-before-mint → health-check successor → swap in + mark old retired → a separate `rotateSweepMu`-guarded retired-sweep deletes the old upstream credential only after `minter_retire_grace` (default 7d), so other raft nodes' in-memory snapshots never wedge). DO/OVH/Vultr/OCI reject (verified infeasible). `selectMinter`/`anyHealthyMinter*`/`selectMinterForSet` skip `Retired` minters; the retired-sweep is keyed off `RetiredAt`, kept separate from the conservative owner-tag orphan reconciler. AWS/GCP minter key-management is hand-rolled signed REST (no new deps) and is fake-tested pending the deferred #7 real-cloud pass. See `docs/decisions.md` ("Why minter rotation retires with a grace period…").

## Capability verification (2026-08-21)

**Health ≠ capability.** A health check proves a minter credential is live, not that it may mint what its set's roles ask for (AWS `GetCallerIdentity` needs no policy at all; Akamai `GET /api-clients/self` answers for any live EdgeGrid credential; UpCloud's account endpoint doesn't report `can_create_tokens`; GCP's `TestConnection` only proves the minter SA's own key, while impersonation is a per-target-SA grant). So every plugin runs a **capability probe** — mint a throwaway credential with the real per-role mint shape, then delete it — via `pkg/capability` (`Check`/`Verify`/`Dedupe`/`Gate`/`ChecksPerMinter`/`ProbeName`/`RolesBoundTo`).

Each plugin has a `capability.go` with `capabilityChecks` (per-cloud mint shape + `probeMint`), `verifySetCapability`, `verifyRoleCapability`, `gate()`, and — on the 6 rotation-capable clouds — `verifySuccessorCapability`, hooked in as **step 3b** of `pathMinterSetRotate` (after the successor health check, before the commit; failure calls `cleanupSuccessor`). Probe points: **minter-set write** (all active minters × enabled bound roles), **role write** (the bound set's active minters × this role — this is what blocks a role whose minting key is unsuitable, and forces sets to exist and work before roles bind), **rotation pre-commit**. Probes dedupe on `(minter ID, mint shape)`; verification stops at the first failure. Gated by config field `verify_minter_capability` (**default on**, `cloudconfig.PluginConfig.CapabilityVerificationEnabled()`); every rejection message carries the "set `verify_minter_capability=false`" hint. Probe names use the owner prefix (`cloud-creds-<role>-probe-<uniq>`) so a failed delete is still reconciler-reclaimable; a failed *delete* never fails a probe. Disabled roles are skipped. **AWS/GCP/OVH cannot revoke what the probe mints**, so the requested lifetime is pinned to the minimum (AWS 900s floor, GCP 60s, OVH's fixed 1h). **OCI returns `capability.ErrUnsupported`** (counted as *skipped*, write proceeds): its 2-token cap means a probe would consume a rotation slot. Akamai rotation additionally copies the incumbent's full `apiAccess`/`groupAccess` onto the successor (`GetSelf` → `successorGrants`) and fails closed if `self` is unreadable. Every plugin has a `capability_test.go` (4 cases). Details: `docs/minter-capability-verification.md`.

## Don't

- Don't add a capability probe that cannot clean up without pinning the minted lifetime to the cloud's minimum, and don't let a plugin's *test* backend skip writing config/injecting a fake client — once probes exist, a config-less test backend calls the real cloud API
- Don't change the response envelope shape without bumping `api_version` and updating the techrfc
- Don't loosen the minter-validation rule (see RSK-005); silent infinite-expiry minters are explicitly rejected at config load
- Don't make the reconciler delete anything not matching the owner-tag scheme — that's the load-bearing safety invariant
- Don't mock cloud APIs in integration tests; use the cloud-fakes in `pkg/credenvelope/fakes/` (an `httptest.Server` with knobs for 401/403/429/500/timeout)
- Don't accept a role TTL the cloud can't enforce, and don't make a lease renewable when the credential's expiry is fixed at mint — reject at role write instead (`docs/ttl-semantics.md`). Equally, don't invent a TTL floor a cloud doesn't document.
