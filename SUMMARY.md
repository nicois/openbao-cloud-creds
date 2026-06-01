# Summary

A map of this repository: what each part is, where to read about it, and the current state of every feature.

`openbao-cloud-creds` is a set of ten OpenBao secrets-engine plugins that issue short-lived, role-scoped cloud credentials behind one uniform `bao read cloud-creds/<cloud>/creds/<role>` API. Open-source, Apache-2.0.

## Plugins

All ten are implemented, tested (fake-backed), lint-clean (golangci-lint v2), build as deployable binaries, and pass `make smoke-test`. None are scaffolds.

| Plugin | Strategy | Upstream mechanism | Revoke | Minter self-rotation |
|--------|----------|--------------------|--------|----------------------|
| `credential-do` | JIT | DigitalOcean API tokens (`POST /v2/tokens`) — reference | hard | not supported¹ |
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

## Core concepts

- **Two strategies.** JIT (mint-on-read, revoke-on-lease-end) for nine clouds; phased rotation (N pre-provisioned slots, freshest served, honest TTL) for OCI. See [README](README.md) and [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md).
- **Minter sets.** Minters (the long-lived credentials the plugin uses to call the cloud) live in named, role-bound sets at `cloud-creds/<cloud>/minter-sets/<name>` — the least-privilege/audit isolation boundary. Each set independently satisfies the `(≥1 never_expires) OR (≥2 with ≥7d gap)` validation rule (over its **active**, non-retired minters).
- **Response envelope.** Every read returns a uniform envelope (`api_version` 2) recording the issuing `minter_set`/`minter_id`. Contract is authoritative in [`docs/techrfc.md`](docs/techrfc.md).
- **Owner-tagged reconciler.** Auto-deletes only plugin-created upstream entities matching the owner-tag scheme, after a confirmation hold. Never touches operator-provided minters.
- **Recovery state machine.** Per-minter health tracking (Healthy / TransientFailing / AuthFailing / Missing) with a 429 cool-down; only `Selectable` non-retired minters are chosen for issuance.

## Feature state (post audit-2, 2026-06-01)

- **Upstream error classification** — issue-time failures now surface the right stable `error_code` (`upstream_quota_exceeded` 429, `upstream_timeout` 408/504, `upstream_auth_failed` 401/403, `entity_unavailable` 404, `internal` 5xx) instead of collapsing to `internal`; raw upstream bodies are logged operator-side, never returned to clients.
- **Storage-backed metrics** — access metrics persist in `logical.Storage` (recursive full-key store) and merge across nodes via a node-local ID (`$OPENBAO_CLOUD_CREDS_NODE_ID` → hostname → `unknown-node`).
- **O(N) fail-closed reconciler** — the known-lease registry lists once per pass (was O(N²)); a storage error aborts the pass with zero deletes.
- **Minter observability** — `cloud_creds_minter_age_seconds` gauge for every minter (incl. `never_expires`), plus a configurable near-expiry warn-log (`minter_expiry_warn`, default 7d).
- **Minter self-rotation** — operator-initiated, grace-based, cross-node-safe (see the rotation column above and [`docs/decisions.md`](docs/decisions.md)).

## Configuration

```bash
bao write cloud-creds/<cloud>/config <operational + cloud settings>      # NO minters here
bao write cloud-creds/<cloud>/minter-sets/<set> minters=...              # named minter set(s)
bao write cloud-creds/<cloud>/roles/<role> minter_set=<set> <fields>     # role bound to a set
bao read  cloud-creds/<cloud>/creds/<role>                               # issue a credential
bao write cloud-creds/<cloud>/minter-sets/<set>/rotate minter_id=<id>    # rotate a minter (feasible clouds)
```

`config` operational fields include `flush_interval`, `reconcile_cadence`, `max_deletes_per_pass`, `minter_expiry_warn` (near-expiry warn threshold), and `minter_retire_grace` (how long a rotated-out minter stays upstream-alive before the retired-sweep deletes it — default 7d, cross-node-safe).

## Build / test / lint

```bash
go build github.com/nicois/openbao-cloud-creds/...        # Go workspace; full module path, not ./...
go test -race github.com/nicois/openbao-cloud-creds/...
make lint          # golangci-lint v2 (pinned v2.12.2) across every module
make smoke-test    # register/enable each plugin in a live OpenBao dev server (needs `bao` on PATH)
go test -tags=cloud_real ./plugins/credential-<cloud>/... # real-cloud integration (needs accounts) — see Testing status
```

## Documents

| Doc | What it is | Authoritative for |
|-----|------------|-------------------|
| [`README.md`](README.md) | Project overview, supported clouds, configuration, build/test | Getting started |
| [`docs/techrfc.md`](docs/techrfc.md) | Original RFC (predates code) | Response-envelope + error-code contract |
| [`docs/design.md`](docs/design.md) | Worked examples + rationale | Detailed behaviour (impl-status notes superseded) |
| [`docs/decisions.md`](docs/decisions.md) | Short rationale notes | Why non-obvious choices were made |
| [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md) | What each cloud's API supports | Per-cloud strategy + feasibility |
| [`docs/known-issues.md`](docs/known-issues.md) | Known issues (KI-001..) + status | Operational caveats |
| [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md) | Object-storage viability | Why S3-style keys are out of scope |
| [`docs/audit-2026-05-31.md`](docs/audit-2026-05-31.md), [`docs/audit-2026-06-01.md`](docs/audit-2026-06-01.md) | Repository audits + resolutions | Audit history |

## Testing status

Tests are broad but **fake-backed** (cloud-fakes in `pkg/credenvelope/fakes/`, no real cloud calls). Real-cloud integration coverage (the `cloud_real` build tag) is **deferred** (audit #7): it needs dedicated/disposable cloud accounts and CI secrets. It is the intended next validation pass — especially for the minter self-rotation subsystem (the AWS/GCP/Akamai key-management paths are exercised only against fakes) — and should add record/replay instrumentation so real API interactions become durable e2e fixtures.

## Genealogy

This repo is the open-source extraction of just the credential-issuance plugins from a larger internal multi-cloud OpenBao raft-cluster spike. Cluster ops, terraform, CA, and seal management belong to that (private) spike, not here. References to "Aiven", "SRE-12109", or "the spike" in history are the upstream private project — ignore them.
