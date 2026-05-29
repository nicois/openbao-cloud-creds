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
| **JIT** (mint on read, revoke on lease end) | DigitalOcean, AWS, GCP, Azure, OVH, Exoscale, Vultr, Akamai, UpCloud | Plugin holds a long-lived "minter" credential; per-read it calls the cloud API to mint a short-lived credential and stores the upstream ID in lease `internal_data` for revoke. Clouds whose tokens expire naturally (AWS STS, GCP impersonation, OVH/UpCloud tokens) need no revoke call. |
| **Phased rotation** (N slots rotated on schedule with phase offsets) | Oracle (OCI) | Plugin pre-provisions N credentials per role; rotates one every T/N. Reads return the freshest. Lease TTL = time until that slot's next rotation, so TTL is always honest. Used where per-user credential quotas are too low for JIT (OCI caps at 2 auth tokens/user). |

DO was the reference implementation: it exercises every load-bearing piece (envelope, lease tracking, recovery state machine, reconciler, metrics). All other plugins follow its structure.

**The "Native engine wrapper" strategy described in the techrfc was abandoned.** Investigation (see `docs/cloud-credential-research.md`) found OpenBao has NO GCP or Azure secrets engine, and only partial AWS support (IAM-user `iam_tags` but no STS `session_tags`). So AWS/GCP/Azure are implemented as full JIT plugins calling the cloud APIs directly, not as thin wrappers. The techrfc's strategy table is stale on this point; this file and `docs/cloud-credential-research.md` are authoritative for what was actually built.

## Status of each plugin

All ten plugins are implemented, tested, lint-clean (golangci-lint v2), build as deployable binaries, and pass the OpenBao registration smoke test (`make smoke-test`). None are scaffolds or stubs.

| Plugin | Strategy | Notes |
|--------|----------|-------|
| `credential-do` | JIT | Reference implementation; `POST /v2/tokens` |
| `credential-aws` | JIT | STS AssumeRole (direct, not the OpenBao AWS engine); no revoke (STS expires) |
| `credential-gcp` | JIT | SA impersonation, `generateAccessToken`; no revoke (token expires) |
| `credential-azure` | JIT | Graph API `addPassword` on existing app registrations; hard revoke |
| `credential-ovh` | JIT | OAuth2 `client_credentials` token minting; no revoke (1h tokens) |
| `credential-upcloud` | JIT | `POST /1.3/account/tokens`, native `expires_in` TTL |
| `credential-exoscale` | JIT | `POST /api-key` scoped to an IAM role |
| `credential-vultr` | JIT | sub-user creation, `POST /v2/users` |
| `credential-akamai` | JIT | EdgeGrid-signed API-client creation (CDN/Identity API — NOT Linode Object Storage) |
| `credential-oci` | Phased rotation | OCI auth tokens, N=2 slots; the only non-JIT plugin |

Object-storage credentials (S3-style backup keys) are explicitly **out of scope** — see `docs/object-storage-credential-audit.md` for the viability analysis and why.

## Genealogy

This work originated inside an internal multi-cloud OpenBao raft cluster spike (6 clouds, Shamir seal on every node, WireGuard mesh). That infrastructure lives in a separate (private) repository. **This repo is the open-source extraction of just the credential-issuance plugins** — the cluster operations, terraform, CA, and seal management belong to the spike, not here.

If you find references in commit history or older notes to:
- "Aiven", "aiven-creds", "SRE-12109" — those are the upstream private project; ignore them.
- "the spike", "the multi-cloud raft cluster" — that's the infrastructure where these plugins were originally prototyped; not part of this repo.

## Build / test / lint

No code exists yet. Once the Go module is initialized:

```bash
go build ./...
go test ./...
golangci-lint run
```

For a real-cloud integration test (calls actual cloud APIs, requires a dedicated test account):
```bash
go test -tags=cloud_real ./plugins/credential-do/...
```

## Conventions

- Go 1.22+ when initialized
- One plugin = one Go module under `plugins/<name>/`
- Shared code under `pkg/` — plugins import; never the other way around
- Mount path is always `cloud-creds/<cloud>/...`
- Owner-tag scheme always uses prefix `cloud-creds-<role>-` or label `owner=cloud-creds`
- Every error response includes a stable `error_code` (Go constants in `pkg/credenvelope/errors.go`); adding one is a spec change
- Clients pin to `metadata.api_version` in the response envelope

## Don't

- Don't change the response envelope shape without bumping `api_version` and updating the techrfc
- Don't loosen the minter-validation rule (see RSK-005); silent infinite-expiry minters are explicitly rejected at config load
- Don't make the reconciler delete anything not matching the owner-tag scheme — that's the load-bearing safety invariant
- Don't mock cloud APIs in integration tests; use the cloud-fakes in `pkg/credenvelope/fakes/` (an `httptest.Server` with knobs for 401/403/429/500/timeout)
