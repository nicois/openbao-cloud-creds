# openbao-cloud-creds

Short-lived, role-based cloud credentials for [OpenBao](https://openbao.org/), with a uniform API across cloud providers.

**Status:** Implemented. Ten credential plugins, all tested and lint-clean, each building as a deployable OpenBao secrets-engine binary. Two have been probed against a real account, with opposite results: **AWS works** — the mint shape, session tags, credential usability and exact TTL honouring all confirmed against live STS — while **DigitalOcean refuses the mint call for every API token**, so `credential-do` cannot issue against the real cloud ([KI-009](docs/known-issues.md)) and is kept as the reference for the other nine plugins' structure. The remaining eight are unexercised against their live cloud (see Testing).

## What this is

Control-plane services and CI jobs need short-lived, role-scoped credentials for the cloud APIs they call. This project is a set of OpenBao plugins that present a single uniform `bao read cloud-creds/<cloud>/creds/<role>` API regardless of cloud, hiding per-cloud divergence behind one of two strategies:

- **JIT** (mint on read, revoke on lease end) — the strategy for nine of ten clouds. The plugin holds a long-lived "minter" credential and calls the cloud API per request to mint a short-lived credential. Clouds whose tokens expire naturally (AWS STS, GCP impersonation, OVH OAuth2 tokens) need no revoke call; the rest (DO, UpCloud, Azure, Exoscale, Vultr, Akamai) hard-revoke the upstream credential on lease end.
- **Phased rotation** — N pre-provisioned credential slots rotated on schedule with phase offsets, so the freshest slot's TTL is always honest. Used only by Oracle (OCI), whose 2-token-per-user quota rules out per-request minting.

Every issued lease's `expires_at` reflects actual remaining validity — never more
than the credential really has. Where a cloud can't be made to honour a requested
TTL, the *role* is rejected rather than the promise broken: OVH tokens are a fixed
1 hour with no revoke API, so OVH roles must declare exactly `3600s`; AWS roles are
held to STS's documented 900s–43200s range; GCP to ≤43200s; UpCloud to ≤8760h. And
a lease is renewable only where the credential's expiry isn't already fixed at mint
time. The full per-cloud matrix — who shortens at mint, who revokes at lease end,
and the one deliberate case where a credential outlives its lease (OCI's rotation
slots) — is in [`docs/ttl-semantics.md`](docs/ttl-semantics.md). Steady-state rotation is fully headless. Auto-deletion of expired or rotated-out credentials is bounded by an owner-tag scheme — the reconciler will only ever touch entities the plugin itself created. Every error response — on reads, revokes and the configuration write paths alike — carries a stable `error_code`, chosen so a caller knows what to *do*: retry with backoff (`upstream_unavailable`, `upstream_timeout`, `upstream_quota_exceeded`), fix configuration and don't retry (`config_invalid`, `upstream_request_invalid`, `role_not_found`, `role_disabled`, `unsupported`), fix credentials (`upstream_auth_failed`), or page someone (`internal`, `lease_revoke_failed`, `entity_unavailable`, `pool_exhausted`). Raw upstream response bodies are logged operator-side, never returned to clients. The vocabulary is **additive**: clients must treat an unrecognised code as `internal`, and new codes do not bump `api_version` — an error response carries no envelope, so `api_version` is absent from exactly the responses codes appear in.

The long-lived **minter** credentials themselves are observable (an age gauge plus a configurable near-expiry warning) and, on the clouds whose API can mint a mint-capable successor, rotatable through a uniform operator-initiated endpoint — see [Minter lifecycle](#minter-lifecycle).

## Supported clouds

| Plugin | Strategy | Upstream mechanism | Minter self-rotation |
|--------|----------|--------------------|----------------------|
| `credential-do` | JIT | DigitalOcean API tokens (`POST /v2/tokens`) — code-shape reference; **cannot issue against real DO**¹ | — |
| `credential-aws` | JIT | STS AssumeRole (called directly) | ✅ `CreateAccessKey` |
| `credential-gcp` | JIT | Service-account impersonation (`generateAccessToken`) | ✅ `keys.create` (org-policy permitting) |
| `credential-azure` | JIT | Graph API client secrets on app registrations | ✅ `addPassword` (rotation reference) |
| `credential-ovh` | JIT | OAuth2 `client_credentials` access tokens | — |
| `credential-upcloud` | JIT | UpCloud API tokens (`POST /1.3/account/tokens`) | ✅ `can_create_tokens` successor |
| `credential-exoscale` | JIT | Exoscale IAM API keys (`POST /api-key`) | ✅ successor with minter's role-id |
| `credential-vultr` | JIT | Vultr sub-users (`POST /v2/users`) | — |
| `credential-akamai` | JIT | Akamai EdgeGrid API clients (Identity Management API) | ✅ per-account apiId + RW grant |
| `credential-oci` | Phased rotation | Oracle Cloud auth tokens (N=2 slots) — **experimental**² | — (already slot-rotates issued tokens) |

The `minter-sets/<set>/rotate` endpoint exists on all ten plugins for a uniform API surface; the four marked **—** (DO, OVH, Vultr, OCI) reject it with "rotation not supported, rotate out-of-band" because their APIs cannot mint a mint-capable successor (verified — see [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md)).

² **`credential-oci` cannot talk to real OCI.** Its production client is four `NotImplemented` stubs — OCI request signing is unimplemented in this open-source extraction — so a role write fails with `unsupported`, and everything that passes for it exercises the in-process fake. Phased rotation, one of the two headline strategies, therefore has no working cloud. Tracked as A15 in [`docs/audit-2026-08-22.md`](docs/audit-2026-08-22.md).

¹ **`POST /v2/tokens` is neither public nor usable.** DO's public OpenAPI spec has no `/v2/tokens` path, and DO documents personal-access-token creation as a control-panel flow only. Worse, a real-account probe on 2026-08-21 found the endpoint **refused for every personal access token**: `GET`/`POST /v2/tokens` return 403 with `X-Response-From: Edge-Gateway` while eleven other endpoints on the *same* full-access token return 200 from `X-Response-From: service`. Token management is fenced off at DigitalOcean's edge as a matter of routing, not privilege — so `credential-do` cannot mint against real DigitalOcean, and there is no headless alternative (the OAuth flow needs interactive authorization; Spaces keys are a different credential type, out of scope). It is retained as the structure the other nine plugins follow and as the origin of the DO cloud fake, both of which the test layers depend on. Findings: [KI-009](docs/known-issues.md), [`docs/do-api-verification-2026-08-21.md`](docs/do-api-verification-2026-08-21.md), rationale in [`docs/decisions.md`](docs/decisions.md).

DO roles take DigitalOcean's fine-grained scopes (`<resource>:<verb>`) verbatim, so a role can be narrowed to exactly the operations it needs — e.g. `scopes=droplet:create,droplet:read` for a role that may only launch and list Droplets. Scope strings are passed through unvalidated, and the minter must itself hold every scope it grants. (Academic against real DO, per the footnote above — but this is the scope-pass-through pattern the other plugins' role fields follow.)

Object-storage credentials (S3-style backup keys) are **out of scope** — see [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md). (DigitalOcean Spaces keys appear in DO's public spec at `/v2/spaces/keys`, but DO's product docs say they are control-panel-only and a real-account probe returned 404, so API issuance is **unconfirmed** — see the audit's Revision 2. Object storage as a whole is simply not built here; DO's caps bind at 100 buckets per account; and the long-lived per-customer use case that motivated the audit needs credentials that survive an OpenBao outage, which short-lived issuance cannot provide on any cloud.)

## Configuration flow

Each mount is configured in three steps:

```bash
bao write cloud-creds/<cloud>/config <operational + cloud settings>     # no minters here
bao write cloud-creds/<cloud>/minter-sets/<set> minters=...             # one or more named minter sets
bao write cloud-creds/<cloud>/roles/<role> minter_set=<set> <role fields>
```

Minters live in named **minter sets**, not in `config`. Every role is bound to a required `minter_set` and mints only from that set's credentials — the isolation boundary for least-privilege and audit provenance. Each issued credential records its `minter_set` and `minter_id` in the response envelope metadata (`api_version` 2). Each set must independently satisfy the minter-validation rule (at least one `never_expires` minter, or at least two with ≥7-day expiry separation) — evaluated over the set's **active** (non-retired) minters.

The `config` endpoint's operational fields include `flush_interval`, `reconcile_cadence`, `max_deletes_per_pass`, `minter_expiry_warn` (the near-expiry warning threshold, default 7 days), `minter_retire_grace` (how long a rotated-out minter stays usable before deletion, default 7 days — see below), and `verify_minter_capability` (default **true** — see below).

### Minter capability is verified, not assumed

A health check proves a minter credential is *live*; it does not prove the credential may **mint** what the roles bound to its set ask for. AWS answers `GetCallerIdentity` without any policy permitting it; an Akamai api client can always read itself; UpCloud's account endpoint doesn't report `can_create_tokens`; GCP impersonation is a grant on each *target* service account. So an under-privileged minter is reported healthy indefinitely and fails at the first credential read — as an upstream 403 delivered to an unrelated caller, long after the operator who caused it got a `200 OK`.

Instead each plugin runs a **capability probe**: mint a throwaway credential using the same request shape a real issuance would use, then delete it. Probes run when a minter set is written, when a role is bound to a set, and before a minter rotation commits — so an incapable minter is rejected at configuration time, naming the minter and the roles it cannot serve:

```
minter capability verification failed: minter "minter-1" cannot mint the
credential role(s) purge-only require: probe api-client creation returned 403 …
(set verify_minter_capability=false on the config endpoint to skip this check)
```

Verifying at role write is deliberate in both directions: it stops an operator defining a role whose minting key is unsuitable, and it means a minter set must exist and demonstrably work before roles can bind to it. On the three clouds that cannot revoke what the probe mints (AWS, GCP, OVH), the probe asks for the shortest lifetime the cloud accepts — a 900s STS session, a 60s GCP token, OVH's fixed 1h — and the credential is never returned to anyone. OCI is deliberately not probed: its two-auth-tokens-per-user cap means a probe would consume one of the rotation slots it exists to protect. Full per-cloud table, costs, and the escape hatch: [`docs/minter-capability-verification.md`](docs/minter-capability-verification.md).

## Minter lifecycle

The long-lived minter credentials are the highest-value secrets at rest, so the plugins make them observable and, where the cloud API allows, rotatable.

- **Observability.** On the health-check cadence each plugin emits `cloud_creds_minter_age_seconds` for **every** minter (including `never_expires` ones, which otherwise carry no lifetime signal), and logs a `minter nearing expiry` warning when an expiring minter is within `minter_expiry_warn` of its expiry.
- **Self-rotation.** `bao write cloud-creds/<cloud>/minter-sets/<set>/rotate minter_id=<id>` mints a successor minter (a new long-lived credential of the same kind, itself mint-capable), health-checks it, **capability-probes it against every role bound to the set**, and only then swaps it into the set and marks the old minter *retired*. The old credential is **not** deleted immediately: it stays upstream-alive for `minter_retire_grace` (default 7 days) so other nodes in a raft cluster — which cache the minter set in memory until they reload — keep working; a background sweep deletes the old upstream credential once the grace elapses. A retired minter is excluded from new issuance and from set validation the moment it is retired. Rotation is refused up front if retiring the chosen minter would leave the set unable to validate. Supported on the clouds marked ✅ above; the rest reject with a clear message.

## Build and test

```bash
go build github.com/nicois/openbao-cloud-creds/...   # build all (Go workspace)
go test github.com/nicois/openbao-cloud-creds/...     # unit + fake-backed integration tests
make test-conformance                                  # every shared test category × every plugin, plus the coverage matrix
make test-e2e                                          # plugin binaries in a live OpenBao, driven over HTTP through the lease lifecycle
make smoke-test                                        # register every plugin in a live OpenBao dev server
make test-cloud-real-do                                # REAL DigitalOcean API: creates and deletes real PATs (opt-in)
make test-cloud-real-aws                               # REAL AWS STS: assume-role mints against a real account (opt-in, $0)
make lint                                              # golangci-lint v2 across all modules
```

`make test-e2e` and `make smoke-test` need an OpenBao binary on PATH (no cloud credentials — the cloud fakes stand in for the upstreams).

`make test-cloud-real-aws` calls real AWS STS with an IAM user's access key you supply (`CLOUDREAL_AWS_KEY=access_key_id:secret_access_key` plus `CLOUDREAL_AWS_ROLE_ARN`). It costs nothing (IAM and STS are unmetered) and creates nothing that needs deleting — STS sessions cannot be revoked, so every duration it asks for is the shortest the assertion allows and they expire on their own. The minter needs only `sts:AssumeRole` on the target role; the target role's trust policy must name that user and allow **both** `sts:AssumeRole` and `sts:TagSession`, and needs no permissions of its own. It confirmed what a fake cannot: the credential AWS returns actually authenticates, and STS grants exactly the duration asked for. It also found [KI-010](docs/known-issues.md).

`make test-cloud-real-do` calls DigitalOcean with a PAT you supply (`CLOUDREAL_DO_TOKEN`, or `.env.cloud-real`) and **creates and deletes real personal access tokens**, so use a dedicated, disposable account. It existed to probe the one assumption no fake can test — that the undocumented `POST /v2/tokens` works headlessly — and the answer is **no**: with a full-access PAT, token management is refused at DigitalOcean's edge gateway while eleven other endpoints on the same token succeed, so **no PAT can mint and `credential-do` cannot issue against real DigitalOcean** ([KI-009](docs/known-issues.md)). The plugin remains this repo's code-shape reference and the origin of the DO fake, and is not presented as production-viable; the test's job is now to pin that finding and fail loudly if DigitalOcean ever changes it. The other eight clouds have no real-cloud test; see [`docs/free-account-viability.md`](docs/free-account-viability.md) for the plan and what each would cost.

**Testing is conformance-first.** With ten near-identical plugins, a missing test looks exactly like a passing one, so every invariant that is about a plugin's own behaviour rather than a cloud's wire format is written once in `pkg/plugintest` and applied to all ten from a single table in the test-only [`conformance/`](conformance/) module: `reload`, `lease`, `perturbation`, `revoke`, `capability`, `reconciler-safety`. A plugin missing from that table fails the build; a category that genuinely does not apply to a cloud must be *declared* with a reason (`Harness.Skips`) and is printed by `make test-conformance` as one reviewable line, rather than hidden in a `t.Skip`. Per-cloud vocabulary — mint shapes, deny knobs, unexported internals — stays in each plugin's own tests.

Above that sits [`e2e/`](e2e/): each plugin built as a binary, registered in a live `bao server -dev` and driven over HTTP through config → minter set → role → issue → lease lookup → renew → revoke → `plugin reload` → re-issue. It exists for what an in-process test cannot see — the plugin's JSON-serialized RPC boundary and OpenBao core's own expiration manager — and it earned its place immediately, finding two live defects (background workers never starting on a reloaded backend, and six plugins advertising renewable leases whose renewal failure made core *revoke* the credential). Rationale in [`docs/decisions.md`](docs/decisions.md); what each layer does and does not prove in [`docs/openbao-integration-gaps.md`](docs/openbao-integration-gaps.md); the rules for contributors and agents in [`AGENTS.md`](AGENTS.md).

## Documents

- [`SUMMARY.md`](SUMMARY.md) — repository map: plugin/feature state, concepts, and a guide to every doc
- [`AGENTS.md`](AGENTS.md) — how to change this repo without eroding it; the conformance-first testing rules
- [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md) — what each cloud's API supports; authoritative for per-cloud strategy
- [`docs/techrfc.md`](docs/techrfc.md) — original RFC; authoritative for the response-envelope and error-code contract (its implementation-status notes are superseded — see the banner in that file)
- [`docs/design.md`](docs/design.md) — companion design doc (same caveat)
- [`docs/decisions.md`](docs/decisions.md) — non-obvious design choices and why
- [`docs/ttl-semantics.md`](docs/ttl-semantics.md) — what a lease TTL means per cloud; enforced role-TTL bounds
- [`docs/minter-capability-verification.md`](docs/minter-capability-verification.md) — why health ≠ capability, what each cloud's probe mints and costs, and what it deliberately doesn't cover
- [`docs/known-issues.md`](docs/known-issues.md) — known issues and operational caveats (KI-001…)
- [`docs/openbao-integration-gaps.md`](docs/openbao-integration-gaps.md) — what each test layer proves, and what testing the plugins in isolation from OpenBao does not cover
- [`docs/free-account-viability.md`](docs/free-account-viability.md) — whether each cloud can be exercised for real on a free account, and the CI design for validating the fakes against recordings
- [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md) — object-storage viability analysis (out of scope)

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
