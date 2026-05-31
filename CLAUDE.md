# Project context for AI agents

## What this is

OpenBao plugins that issue short-lived, role-scoped cloud credentials with a uniform API across cloud providers. Open-source (Apache 2.0).

**Documents (note: the original RFC predates implementation and is partly stale):**
- [`docs/techrfc.md`](docs/techrfc.md) — original formal RFC (requirements, API, risks). Written before any code; its per-cloud strategy table and "follow-up RFC" status notes are STALE (all 10 plugins now exist; the native-wrapper strategy was abandoned). Still authoritative for the response-envelope contract and error-code model.
- [`docs/design.md`](docs/design.md) — companion with worked examples and detailed rationale (same caveat as the techrfc).
- [`docs/decisions.md`](docs/decisions.md) — short rationale notes for design choices.
- [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md) — what each cloud's API actually supports; authoritative for per-cloud strategy.
- [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md) — object-storage viability (out of scope, but analysed).

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
| `credential-do` | JIT | Reference implementation; `POST /v2/tokens`; **hard revoke** (`DELETE /v2/tokens/{id}`) |
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

Object-storage credentials (S3-style backup keys) are explicitly **out of scope** — see `docs/object-storage-credential-audit.md` for the viability analysis and why.

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
make lint          # golangci-lint v2 (pinned v2.12.2) across every module — config in .golangci.yml
make smoke-test    # build each plugin + register/enable in a live OpenBao dev server (needs `bao` on PATH)
```

For a real-cloud integration test (calls actual cloud APIs, requires a dedicated test account):
```bash
go test -tags=cloud_real ./plugins/credential-do/...
```

## Conventions

- Go 1.26.1 (workspace `go.work` + per-module `go.mod`)
- One plugin = one Go module under `plugins/<name>/`
- Shared code under `pkg/` — plugins import; never the other way around. Genuinely-identical helper bodies are extracted into focused `pkg/` packages with cloud identity passed as a parameter (e.g. `pkg/telemetry` for metric emitters, `pkg/metricspath` for the metrics query endpoints, `pkg/localexpiry` for no-revoke local-entry pruning), preserving per-plugin module isolation — never collapse the plugin modules themselves
- Each plugin keeps a `consts.go` defining its `cloudName`, `metricNamespace`, and field-name constants (`fieldCloud`/`fieldRole`/`fieldMinterSet`/…); HTTP status codes use `net/http` constants and TTL/duration values are named consts (no magic numbers/literals — enforced by lint)
- Mount path is always `cloud-creds/<cloud>/...`
- Owner-tag scheme always uses prefix `cloud-creds-<role>-` or label `owner=cloud-creds`
- Every error response includes a stable `error_code` (Go constants in `pkg/credenvelope/errors.go`); adding one is a spec change
- Clients pin to `metadata.api_version` in the response envelope (currently `"2"`)
- Every plugin MUST have a `resilience_test.go` wiring `pkg/plugintest` (reload, mid-lease perturbation, revoke-resilience categories). A new plugin is not complete without it. The reload category catches "config field set only in `pathConfigWrite`, not reloaded in `Factory`" bugs (KI-001 class); the perturbation/revoke categories catch revoke-wedging bugs (KI-002 class). See `docs/superpowers/specs/2026-05-30-resilience-test-taxonomy-design.md`. Injected-client plugins (AWS/GCP/OCI) `t.Skip` the reload category — their config-reload path is not covered, a known residual gap.

## Minter sets

Minters are grouped into named **sets** at `cloud-creds/<cloud>/minter-sets/<name>` (write/read/delete/list), each independently validated by the `(≥1 never_expires) OR (≥2 with ≥7d gap)` rule. The bare `config` endpoint holds operational + cloud settings only (NO minters). Every role has a **required** `minter_set` field and mints only from that set — there is no cross-set failover for issuance, by design (it is the isolation boundary). The reconciler, by contrast, cleans orphans across all sets by owner-tag (`anyHealthyMinter`). The issuing set+minter are recorded in `metadata.minter_set`/`minter_id` (envelope api_version 2) and in lease internal_data. OCI (phased rotation) binds each rotation slot to the role's set and records the provisioning set+minter on the slot. For capability isolation, give each set's minters only the upstream rights its bound roles need (e.g. an Azure SP authorized for one app registration). Backend worker lifecycle is serialized by a per-backend `workerLifecycleMu` (start/stop never overlap).

## Don't

- Don't change the response envelope shape without bumping `api_version` and updating the techrfc
- Don't loosen the minter-validation rule (see RSK-005); silent infinite-expiry minters are explicitly rejected at config load
- Don't make the reconciler delete anything not matching the owner-tag scheme — that's the load-bearing safety invariant
- Don't mock cloud APIs in integration tests; use the cloud-fakes in `pkg/credenvelope/fakes/` (an `httptest.Server` with knobs for 401/403/429/500/timeout)
