# Summary

A map of this repository: what each part is, where to read about it, and the current state of every feature.

`openbao-cloud-creds` is a set of ten OpenBao secrets-engine plugins that issue short-lived, role-scoped cloud credentials behind one uniform `bao read cloud-creds/<cloud>/creds/<role>` API. Open-source, Apache-2.0.

## Plugins

All ten are implemented, tested (fake-backed), lint-clean (golangci-lint v2), build as deployable binaries, and pass `make smoke-test`. None are scaffolds.

| Plugin | Strategy | Upstream mechanism | Revoke | Minter self-rotation |
|--------|----------|--------------------|--------|----------------------|
| `credential-do` | JIT | DigitalOcean API tokens (`POST /v2/tokens`⁴) — reference | hard | not supported¹ |
| `credential-aws` | JIT | STS AssumeRole (direct) | none (STS expires) | ✅ `CreateAccessKey` (2-key make-before-break) |
| `credential-gcp` | JIT | SA impersonation (`generateAccessToken`) | none (token expires) | ✅ `serviceAccounts.keys.create`² |
| `credential-azure` | JIT | Graph `addPassword` on app registrations | hard (`removePassword`) | ✅ `addPassword` (reference) |
| `credential-ovh` | JIT | OAuth2 `client_credentials` tokens | none (1h tokens) | not supported¹ |
| `credential-upcloud` | JIT | UpCloud API tokens (`POST /1.3/account/tokens`) | hard | ✅ `can_create_tokens` successor |
| `credential-exoscale` | JIT | Exoscale IAM API keys (`POST /api-key`) | hard | ✅ successor with minter's role-id³ |
| `credential-vultr` | JIT | Vultr sub-users (`POST /v2/users`) | hard | not supported¹ |
| `credential-akamai` | JIT | Akamai EdgeGrid API clients (Identity Mgmt API) | hard | ✅ per-account apiId + RW grant |
| `credential-oci` | Phased rotation | Oracle Cloud auth tokens (N=2 slots) | soft (slot lifecycle) | not supported¹ (already slot-rotates issued tokens) |

¹ The `minter-sets/<set>/rotate` endpoint exists on all 10 for a uniform API, but DO/OVH/Vultr/OCI reject it ("rotation not supported, rotate out-of-band") — verified infeasible: DO has no token-creation scope, OVH's OAuth2 grant mints only short-lived access tokens, Vultr has a single account-wide key, OCI is phased + quota-tight.
² GCP rotation is disabled by default in orgs created on/after 2024-05-03 (the `iam.disableServiceAccountKeyCreation` org policy); the endpoint returns a clear org-policy error rather than a generic failure.
³ Exoscale needs the minter's key-management `role-id` recorded in `rotation_params` so the successor stays mint-capable.
⁴ `POST /v2/tokens` / `DELETE /v2/tokens/{id}` are **not public documented DigitalOcean API** — the public OpenAPI spec has no `/v2/tokens` path and DO documents PAT creation as control-panel-only. The plugin uses the control-panel-internal endpoint (works, no stability contract; the documented OAuth alternative needs interactive authorization so cannot mint headlessly). Accepted, documented risk and the first target of the deferred real-cloud pass — see [`docs/do-api-verification-2026-08-21.md`](docs/do-api-verification-2026-08-21.md).

## Core concepts

- **Two strategies.** JIT (mint-on-read, revoke-on-lease-end) for nine clouds; phased rotation (N pre-provisioned slots, freshest served, honest TTL) for OCI. See [README](README.md) and [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md).
- **Minter sets.** Minters (the long-lived credentials the plugin uses to call the cloud) live in named, role-bound sets at `cloud-creds/<cloud>/minter-sets/<name>` — the least-privilege/audit isolation boundary. Each set independently satisfies the `(≥1 never_expires) OR (≥2 with ≥7d gap)` validation rule (over its **active**, non-retired minters).
- **Response envelope.** Every read returns a uniform envelope (`api_version` 2) recording the issuing `minter_set`/`minter_id`. Contract is authoritative in [`docs/techrfc.md`](docs/techrfc.md).
- **Honest TTLs.** A lease never claims more validity than the credential has. Each cloud enforces that by a mint-time lifetime (AWS/GCP/Azure/UpCloud) or a hard revoke at lease end (DO/Exoscale/Vultr/Akamai); TTLs a cloud can't honour are rejected at role write (**OVH exactly 3600s**, **AWS 900–43200s**, **GCP ≤43200s**, **UpCloud ≤8760h**), and leases are renewable only where the credential's expiry isn't fixed at mint. OCI's rotation slots are the one deliberate case of a credential outliving its lease. See [`docs/ttl-semantics.md`](docs/ttl-semantics.md).
- **Owner-tagged reconciler.** Auto-deletes only plugin-created upstream entities matching the owner-tag scheme, after a confirmation hold. Never touches operator-provided minters.
- **Recovery state machine.** Per-minter health tracking (Healthy / TransientFailing / AuthFailing / Missing) with a 429 cool-down; only `Selectable` non-retired minters are chosen for issuance.
- **Capability probes.** Health proves a minter is *live*, not that it may mint. So a throwaway probe mint (real per-role mint shape, then deleted) gates minter-set writes, role writes and rotation commits, on by default (`verify_minter_capability`). OCI is deliberately exempt. See [`docs/minter-capability-verification.md`](docs/minter-capability-verification.md).

## Feature state (post audit-2, 2026-06-01)

- **Upstream error classification** — issue-time failures now surface the right stable `error_code` (`upstream_quota_exceeded` 429, `upstream_timeout` 408/504, `upstream_auth_failed` 401/403, `entity_unavailable` 404, `internal` 5xx) instead of collapsing to `internal`; raw upstream bodies are logged operator-side, never returned to clients.
- **Storage-backed metrics** — access metrics persist in `logical.Storage` (recursive full-key store) and merge across nodes via a node-local ID (`$OPENBAO_CLOUD_CREDS_NODE_ID` → hostname → `unknown-node`).
- **O(N) fail-closed reconciler** — the known-lease registry lists once per pass (was O(N²)); a storage error aborts the pass with zero deletes.
- **Minter observability** — `cloud_creds_minter_age_seconds` gauge for every minter (incl. `never_expires`), plus a configurable near-expiry warn-log (`minter_expiry_warn`, default 7d).
- **Minter self-rotation** — operator-initiated, grace-based, cross-node-safe (see the rotation column above and [`docs/decisions.md`](docs/decisions.md)).
- **Minter capability verification (2026-08-21)** — every plugin has a `capability.go` driving `pkg/capability`: probes at minter-set write, role write, and rotation pre-commit (step 3b, `cleanupSuccessor` on failure), deduped per `(minter, mint shape)`, first failure wins, `verify_minter_capability=false` as the escape hatch. AWS/GCP/OVH probes pin the minted lifetime to the cloud minimum (900s / 60s / fixed 1h) because none can revoke; OCI returns `ErrUnsupported` (skipped, not failed) since a probe would consume one of its two auth-token slots. Akamai rotation now copies the incumbent's full `apiAccess`/`groupAccess` onto the successor and fails closed if the incumbent's own grants can't be read. Not done, deliberately: a runtime `minter_insufficient_privilege` error code (a spec change to the error-code model). See [`docs/minter-capability-verification.md`](docs/minter-capability-verification.md).
- **TTL honesty (2026-08-21)** — unenforceable role TTLs are now rejected at write time (OVH pinned to exactly 1h; AWS/GCP/UpCloud bounds symmetric and named), Azure/UpCloud leases are no longer renewable (their credential expiry is fixed at mint, so renewal outlived the credential), and the revoke-fallback log line no longer claims a native expiry the four no-expiry clouds don't have. KI-005 in [`docs/known-issues.md`](docs/known-issues.md).
- **End-to-end layer + three defects it exposed (2026-08-21)** — a new `e2e/` module (build tag `e2e`, `make test-e2e`) builds each plugin binary, registers it in a live `bao server -dev` and drives the full lease lifecycle over HTTP, so the plugin RPC boundary and OpenBao core's expiration manager are exercised for the first time (7 of 10 clouds; AWS/GCP/OCI declared gaps because they inject clients rather than call an HTTP endpoint). It immediately found: **KI-008** — six plugins advertised `renewable: true` while renewal always failed, and core *revokes* a lease whose renewal fails, so a well-behaved client destroyed its own credential (`framework.Secret.Renewable()` is `(Renew != nil)`, so refusing inside the callback was invisible); and **KI-007** — `startWorkers` was reachable only from config/minter-set writes, so a reloaded or failed-over backend silently ran no health checks, metrics flush, reconciler, expiry warnings, retired-sweep or OCI rotation. Fixes: the six drop their `Renew` callback entirely; all ten set `InitializeFunc`. A new **`lease` conformance category** fences the first for all ten plugins and caught a second divergence on the spot (AWS/GCP built the lease from the role TTL while publishing the cloud's real expiry, so the lease could outlive the credential — OBC-002). Auditing what e2e *cannot* reach also closed KI-001 on AWS/GCP/OCI, which had no `loadConfig` at all. See [`docs/openbao-integration-gaps.md`](docs/openbao-integration-gaps.md).

## Configuration

```bash
bao write cloud-creds/<cloud>/config <operational + cloud settings>      # NO minters here
bao write cloud-creds/<cloud>/minter-sets/<set> minters=...              # named minter set(s)
bao write cloud-creds/<cloud>/roles/<role> minter_set=<set> <fields>     # role bound to a set
bao read  cloud-creds/<cloud>/creds/<role>                               # issue a credential
bao write cloud-creds/<cloud>/minter-sets/<set>/rotate minter_id=<id>    # rotate a minter (feasible clouds)
```

`config` operational fields include `flush_interval`, `reconcile_cadence`, `max_deletes_per_pass`, `minter_expiry_warn` (near-expiry warn threshold), `minter_retire_grace` (how long a rotated-out minter stays upstream-alive before the retired-sweep deletes it — default 7d, cross-node-safe), and `verify_minter_capability` (capability probes, default true).

The three write steps are ordered by construction, not just convention: a role write capability-probes the set it binds to, so the minter set must exist and be demonstrably mint-capable first.

## Build / test / lint

```bash
go build github.com/nicois/openbao-cloud-creds/...        # Go workspace; full module path, not ./...
go test -race github.com/nicois/openbao-cloud-creds/...
make test-conformance  # shared test categories × all ten plugins + the cloud × category matrix
make test-e2e      # plugin binaries in a live OpenBao, full lease lifecycle over HTTP (needs `bao` on PATH)
make lint          # golangci-lint v2 (pinned v2.12.2) across every module, incl. a --build-tags=e2e pass
make smoke-test    # register/enable each plugin in a live OpenBao dev server (needs `bao` on PATH)
go test -tags=cloud_real ./plugins/credential-<cloud>/... # real-cloud integration — NO file carries this tag yet; see Testing status
```

## Documents

| Doc | What it is | Authoritative for |
|-----|------------|-------------------|
| [`README.md`](README.md) | Project overview, supported clouds, configuration, build/test | Getting started |
| [`AGENTS.md`](AGENTS.md) | How to change the repo: conformance-first testing rules | Where a test belongs; adding a plugin or a test category |
| [`docs/techrfc.md`](docs/techrfc.md) | Original RFC (predates code) | Response-envelope + error-code contract |
| [`docs/design.md`](docs/design.md) | Worked examples + rationale | Detailed behaviour (impl-status notes superseded) |
| [`docs/decisions.md`](docs/decisions.md) | Short rationale notes | Why non-obvious choices were made |
| [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md) | What each cloud's API supports | Per-cloud strategy + feasibility |
| [`docs/known-issues.md`](docs/known-issues.md) | Known issues (KI-001..) + status | Operational caveats |
| [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md) | Object-storage viability | Why S3-style keys are out of scope (DO Spaces section revised 2026-08-21) |
| [`docs/do-api-verification-2026-08-21.md`](docs/do-api-verification-2026-08-21.md) | DO API re-verification | Whether DO's endpoints/scopes are as documented (D1: `/v2/tokens` is undocumented) |
| [`docs/ttl-semantics.md`](docs/ttl-semantics.md) | Per-cloud TTL matrix | What a lease TTL means per cloud; enforced role-TTL bounds; renewability |
| [`docs/minter-capability-verification.md`](docs/minter-capability-verification.md) | Capability probes | Why health ≠ capability; per-cloud probe/cost table; why OCI is exempt; what was excluded |
| [`docs/openbao-integration-gaps.md`](docs/openbao-integration-gaps.md) | What each test layer proves | Which gaps `e2e/` closes, which stay open (G1–G9) and where they're tracked |
| [`docs/free-account-viability.md`](docs/free-account-viability.md) | Free-account viability per cloud + the CI design | Whether a cloud can be exercised for real, at what cost; how the fakes get validated against recordings |
| [`docs/audit-2026-05-31.md`](docs/audit-2026-05-31.md), [`docs/audit-2026-06-01.md`](docs/audit-2026-06-01.md) | Repository audits + resolutions | Audit history |

## Testing status

Tests are broad but **fake-backed** (cloud-fakes in `pkg/credenvelope/fakes/`, no real cloud calls), in three layers — what each proves, and what it can't, is tabulated in [`docs/openbao-integration-gaps.md`](docs/openbao-integration-gaps.md):

1. **Per-plugin** tests: the cloud's own vocabulary — mint payloads, URLs, error bodies, unexported helpers.
2. **Conformance table** (`conformance/`, suites in `pkg/plugintest`): six cloud-agnostic categories (`reload`, `lease`, `perturbation`, `revoke`, `capability`, `reconciler-safety`) written once and applied to all ten plugins, failing the build if a plugin is unregistered or a category is neither wired nor *declared* as a gap with a reason (five gaps declared today, all facts about the cloud). `lease` is the one category no cloud may opt out of. See [`AGENTS.md`](AGENTS.md).
3. **`e2e/`** (build tag `e2e`): plugin binaries in a live OpenBao, driven over HTTP — the plugin RPC boundary and core's expiration manager. 7 of 10 clouds; AWS/GCP/OCI declared (they inject clients, so a child process has nothing to point at a fake, and OCI's request signing is still a stub).

A fourth layer — **real clouds via CI secrets** — remains **unbuilt**, and the `cloud_real` build tag it would use is currently carried by **no file**, so it must not be cited as coverage. Its purpose is narrow and specific: prove the fakes resemble the APIs they stand in for, by recording real interactions and replaying them against the fakes in ordinary credential-free CI. Nine of ten clouds can be exercised on a free or near-free account (AWS/GCP/Azure/OCI at $0; Vultr needs a $10 deposit; **Akamai is not obtainable without a commercial contract**), and the rotation key-management paths on AWS/GCP/Akamai are the least-verified code in the repo. Per-cloud assessment, confidence levels, secret/environment layout and the record-replay design: [`docs/free-account-viability.md`](docs/free-account-viability.md).

## Genealogy

This repo is the open-source extraction of just the credential-issuance plugins from a larger internal multi-cloud OpenBao raft-cluster spike. Cluster ops, terraform, CA, and seal management belong to that (private) spike, not here. References to "Aiven", "SRE-12109", or "the spike" in history are the upstream private project — ignore them.
