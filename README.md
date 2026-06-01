# openbao-cloud-creds

Short-lived, role-based cloud credentials for [OpenBao](https://openbao.org/), with a uniform API across cloud providers.

**Status:** Implemented. Ten credential plugins, all tested and lint-clean, each building as a deployable OpenBao secrets-engine binary. Not yet exercised against live cloud accounts in CI (see Testing).

## What this is

Control-plane services and CI jobs need short-lived, role-scoped credentials for the cloud APIs they call. This project is a set of OpenBao plugins that present a single uniform `bao read cloud-creds/<cloud>/creds/<role>` API regardless of cloud, hiding per-cloud divergence behind one of two strategies:

- **JIT** (mint on read, revoke on lease end) — the strategy for nine of ten clouds. The plugin holds a long-lived "minter" credential and calls the cloud API per request to mint a short-lived credential. Clouds whose tokens expire naturally (AWS STS, GCP impersonation, OVH OAuth2 tokens) need no revoke call; the rest (DO, UpCloud, Azure, Exoscale, Vultr, Akamai) hard-revoke the upstream credential on lease end.
- **Phased rotation** — N pre-provisioned credential slots rotated on schedule with phase offsets, so the freshest slot's TTL is always honest. Used only by Oracle (OCI), whose 2-token-per-user quota rules out per-request minting.

Every issued lease's `expires_at` reflects actual remaining validity. Steady-state rotation is fully headless. Auto-deletion of expired or rotated-out credentials is bounded by an owner-tag scheme — the reconciler will only ever touch entities the plugin itself created. Issue-time upstream failures surface a stable `error_code` (`upstream_quota_exceeded`, `upstream_timeout`, `upstream_auth_failed`, `entity_unavailable`, or `internal`) so callers can distinguish retryable from fatal; raw upstream response bodies are logged operator-side, never returned to clients.

The long-lived **minter** credentials themselves are observable (an age gauge plus a configurable near-expiry warning) and, on the clouds whose API can mint a mint-capable successor, rotatable through a uniform operator-initiated endpoint — see [Minter lifecycle](#minter-lifecycle).

## Supported clouds

| Plugin | Strategy | Upstream mechanism | Minter self-rotation |
|--------|----------|--------------------|----------------------|
| `credential-do` | JIT | DigitalOcean API tokens (`POST /v2/tokens`) — reference implementation | — |
| `credential-aws` | JIT | STS AssumeRole (called directly) | ✅ `CreateAccessKey` |
| `credential-gcp` | JIT | Service-account impersonation (`generateAccessToken`) | ✅ `keys.create` (org-policy permitting) |
| `credential-azure` | JIT | Graph API client secrets on app registrations | ✅ `addPassword` (rotation reference) |
| `credential-ovh` | JIT | OAuth2 `client_credentials` access tokens | — |
| `credential-upcloud` | JIT | UpCloud API tokens (`POST /1.3/account/tokens`) | ✅ `can_create_tokens` successor |
| `credential-exoscale` | JIT | Exoscale IAM API keys (`POST /api-key`) | ✅ successor with minter's role-id |
| `credential-vultr` | JIT | Vultr sub-users (`POST /v2/users`) | — |
| `credential-akamai` | JIT | Akamai EdgeGrid API clients (Identity Management API) | ✅ per-account apiId + RW grant |
| `credential-oci` | Phased rotation | Oracle Cloud auth tokens (N=2 slots) | — (already slot-rotates issued tokens) |

The `minter-sets/<set>/rotate` endpoint exists on all ten plugins for a uniform API surface; the four marked **—** (DO, OVH, Vultr, OCI) reject it with "rotation not supported, rotate out-of-band" because their APIs cannot mint a mint-capable successor (verified — see [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md)).

Object-storage credentials (S3-style backup keys) are **out of scope** — see [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md). DigitalOcean Spaces is not supported because DO exposes no public API for managing Spaces access keys.

## Configuration flow

Each mount is configured in three steps:

```bash
bao write cloud-creds/<cloud>/config <operational + cloud settings>     # no minters here
bao write cloud-creds/<cloud>/minter-sets/<set> minters=...             # one or more named minter sets
bao write cloud-creds/<cloud>/roles/<role> minter_set=<set> <role fields>
```

Minters live in named **minter sets**, not in `config`. Every role is bound to a required `minter_set` and mints only from that set's credentials — the isolation boundary for least-privilege and audit provenance. Each issued credential records its `minter_set` and `minter_id` in the response envelope metadata (`api_version` 2). Each set must independently satisfy the minter-validation rule (at least one `never_expires` minter, or at least two with ≥7-day expiry separation) — evaluated over the set's **active** (non-retired) minters.

The `config` endpoint's operational fields include `flush_interval`, `reconcile_cadence`, `max_deletes_per_pass`, `minter_expiry_warn` (the near-expiry warning threshold, default 7 days), and `minter_retire_grace` (how long a rotated-out minter stays usable before deletion, default 7 days — see below).

## Minter lifecycle

The long-lived minter credentials are the highest-value secrets at rest, so the plugins make them observable and, where the cloud API allows, rotatable.

- **Observability.** On the health-check cadence each plugin emits `cloud_creds_minter_age_seconds` for **every** minter (including `never_expires` ones, which otherwise carry no lifetime signal), and logs a `minter nearing expiry` warning when an expiring minter is within `minter_expiry_warn` of its expiry.
- **Self-rotation.** `bao write cloud-creds/<cloud>/minter-sets/<set>/rotate minter_id=<id>` mints a successor minter (a new long-lived credential of the same kind, itself mint-capable), health-checks it, and only then swaps it into the set and marks the old minter *retired*. The old credential is **not** deleted immediately: it stays upstream-alive for `minter_retire_grace` (default 7 days) so other nodes in a raft cluster — which cache the minter set in memory until they reload — keep working; a background sweep deletes the old upstream credential once the grace elapses. A retired minter is excluded from new issuance and from set validation the moment it is retired. Rotation is refused up front if retiring the chosen minter would leave the set unable to validate. Supported on the clouds marked ✅ above; the rest reject with a clear message.

## Build and test

```bash
go build github.com/nicois/openbao-cloud-creds/...   # build all (Go workspace)
go test github.com/nicois/openbao-cloud-creds/...     # unit + fake-backed integration tests
make smoke-test                                        # register every plugin in a live OpenBao dev server
make lint                                              # golangci-lint v2 across all modules
```

`make smoke-test` and the `cloud_real` build tag (`go test -tags=cloud_real ...`) require, respectively, an OpenBao binary on PATH and real cloud credentials.

## Documents

- [`SUMMARY.md`](SUMMARY.md) — repository map: plugin/feature state, concepts, and a guide to every doc
- [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md) — what each cloud's API supports; authoritative for per-cloud strategy
- [`docs/techrfc.md`](docs/techrfc.md) — original RFC; authoritative for the response-envelope and error-code contract (its implementation-status notes are superseded — see the banner in that file)
- [`docs/design.md`](docs/design.md) — companion design doc (same caveat)
- [`docs/decisions.md`](docs/decisions.md) — non-obvious design choices and why
- [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md) — object-storage viability analysis (out of scope)

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
