# Project context for AI agents

## What this is

OpenBao plugins that issue short-lived, role-scoped cloud credentials with a uniform API across cloud providers. Open-source (Apache 2.0).

**Authoritative specs:**
- [`docs/techrfc.md`](docs/techrfc.md) — formal RFC (requirements, API, risks). This is the contract.
- [`docs/design.md`](docs/design.md) — companion with worked examples and detailed rationale.
- [`docs/decisions.md`](docs/decisions.md) — short rationale notes for design choices that aren't obvious from the spec.

If anything in this file conflicts with the techrfc, the techrfc wins. Update it instead.

## Mental model

Two strategies, chosen per cloud based on whether the cloud's native API supports headless per-request short-lived token creation:

| Strategy | Used by | How it works |
|----------|---------|--------------|
| **Native** (thin envelope wrapper over upstream OpenBao engine) | AWS (STS), GCP (impersonation), Azure (dynamic SP) | OpenBao already does the right thing; this project just normalizes the response envelope. |
| **JIT** (mint on read, revoke on lease end) | DigitalOcean (reference impl) | Plugin holds a long-lived "minter" credential; per-read it calls `POST /v2/tokens` and stores the upstream ID in lease `internal_data` for revoke. |
| **Phased rotation** (N slots rotated on schedule with phase offsets) | UpCloud (planned) | Plugin pre-provisions N credentials per role; rotates one every T/N. Reads return the freshest. Lease TTL = time until that slot's next rotation, so TTL is always honest. |
| (deferred) | OVH | OVH's legacy auth requires human approval at a `validationUrl`. Deferred until OAuth2 service-account coverage is verified for the OVH APIs in scope. |

DO is intentionally the reference implementation: it exercises every load-bearing piece (envelope, lease tracking, recovery state machine, reconciler, metrics) without the complexity of native engine wrapping.

## Status of each plugin

| Plugin | State |
|--------|-------|
| `credential-do` | Reference implementation — to be built first |
| `credential-aws` | Spec'd, follow-up RFC |
| `credential-gcp` | Spec'd, follow-up RFC |
| `credential-azure` | Spec'd, follow-up RFC |
| `credential-upcloud` | Spec'd, follow-up RFC |
| `credential-ovh` | Deferred (see CON-002 in techrfc) |

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
