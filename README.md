# openbao-cloud-creds

Short-lived, role-based cloud credentials for [OpenBao](https://openbao.org/), with a uniform API across cloud providers.

**Status:** Implemented. Ten credential plugins, all tested and lint-clean, each building as a deployable OpenBao secrets-engine binary. Not yet exercised against live cloud accounts in CI (see Testing).

## What this is

Control-plane services and CI jobs need short-lived, role-scoped credentials for the cloud APIs they call. This project is a set of OpenBao plugins that present a single uniform `bao read cloud-creds/<cloud>/creds/<role>` API regardless of cloud, hiding per-cloud divergence behind one of two strategies:

- **JIT** (mint on read, revoke on lease end) — the strategy for nine of ten clouds. The plugin holds a long-lived "minter" credential and calls the cloud API per request to mint a short-lived credential. Clouds whose tokens expire naturally (AWS STS, GCP impersonation, OVH/UpCloud tokens) need no revoke call; others (DO, Azure, Exoscale, Vultr, Akamai) hard-revoke on lease end.
- **Phased rotation** — N pre-provisioned credential slots rotated on schedule with phase offsets, so the freshest slot's TTL is always honest. Used only by Oracle (OCI), whose 2-token-per-user quota rules out per-request minting.

Every issued lease's `expires_at` reflects actual remaining validity. Steady-state rotation is fully headless. Auto-deletion of expired or rotated-out credentials is bounded by an owner-tag scheme — the reconciler will only ever touch entities the plugin itself created.

## Supported clouds

| Plugin | Strategy | Upstream mechanism |
|--------|----------|--------------------|
| `credential-do` | JIT | DigitalOcean API tokens (`POST /v2/tokens`) — reference implementation |
| `credential-aws` | JIT | STS AssumeRole (called directly) |
| `credential-gcp` | JIT | Service-account impersonation (`generateAccessToken`) |
| `credential-azure` | JIT | Graph API client secrets on app registrations |
| `credential-ovh` | JIT | OAuth2 `client_credentials` access tokens |
| `credential-upcloud` | JIT | UpCloud API tokens (`POST /1.3/account/tokens`) |
| `credential-exoscale` | JIT | Exoscale IAM API keys (`POST /api-key`) |
| `credential-vultr` | JIT | Vultr sub-users (`POST /v2/users`) |
| `credential-akamai` | JIT | Akamai EdgeGrid API clients (Identity Management API) |
| `credential-oci` | Phased rotation | Oracle Cloud auth tokens (N=2 slots) |

Object-storage credentials (S3-style backup keys) are **out of scope** — see [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md). DigitalOcean Spaces is not supported because DO exposes no public API for managing Spaces access keys.

## Build and test

```bash
go build github.com/nicois/openbao-cloud-creds/...   # build all (Go workspace)
go test github.com/nicois/openbao-cloud-creds/...     # unit + fake-backed integration tests
make smoke-test                                        # register every plugin in a live OpenBao dev server
make lint                                              # golangci-lint v2 across all modules
```

`make smoke-test` and the `cloud_real` build tag (`go test -tags=cloud_real ...`) require, respectively, an OpenBao binary on PATH and real cloud credentials.

## Documents

- [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md) — what each cloud's API supports; authoritative for per-cloud strategy
- [`docs/techrfc.md`](docs/techrfc.md) — original RFC; authoritative for the response-envelope and error-code contract (its implementation-status notes are superseded — see the banner in that file)
- [`docs/design.md`](docs/design.md) — companion design doc (same caveat)
- [`docs/decisions.md`](docs/decisions.md) — non-obvious design choices and why
- [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md) — object-storage viability analysis (out of scope)

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
