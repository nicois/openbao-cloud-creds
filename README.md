# openbao-cloud-creds

Short-lived, role-based cloud credentials for [OpenBao](https://openbao.org/), with a uniform API across cloud providers.

**Status:** Implemented. Ten credential plugins, all tested and lint-clean, each building as a deployable OpenBao secrets-engine binary. Two have been probed against a real account, with opposite results: **AWS works** — the mint shape, session tags, credential usability and exact TTL honouring all confirmed against live STS — while **DigitalOcean refuses the mint call for every API token**, so `credential-do`'s token type cannot issue against the real cloud ([KI-009](docs/known-issues.md)) and is kept as the reference for the other nine plugins' structure. That is why the plugin also issues DO **Spaces access keys**, which are in DO's published spec and are the thing it can mint — in two lifecycles, one credential per lease or one shared by a whole role and rotated on a schedule. The remaining eight clouds are unexercised against their live cloud, and so is the Spaces probe itself (see Testing).

## What this is

Control-plane services and CI jobs need short-lived, role-scoped credentials for the cloud APIs they call. This project is a set of OpenBao plugins that present a single uniform `bao read cloud-creds/<cloud>/creds/<role>` API regardless of cloud, hiding per-cloud divergence behind one of three strategies:

- **JIT** (mint on read, revoke on lease end) — the strategy for nine of ten clouds. The plugin holds a long-lived "minter" credential and calls the cloud API per request to mint a short-lived credential. Clouds whose tokens expire naturally (AWS STS, GCP impersonation, OVH OAuth2 tokens) need no revoke call; the rest (DO, UpCloud, Azure, Exoscale, Vultr, Akamai) hard-revoke the upstream credential on lease end.
- **Phased rotation** — N pre-provisioned credential slots rotated on schedule with phase offsets, so the freshest slot's TTL is always honest. Used only by Oracle (OCI), whose 2-token-per-user quota rules out per-request minting.
- **Rotation with overlap** — one credential per *role*, shared by every reader, replaced when it reaches its `rotation_period` and the replaced one deleted `overlap_ttl` later. Chosen per role on DigitalOcean Spaces keys, whose API has no expiry field at all and whose grants cannot be edited, so replace-then-delete is the only rotation there is — see [below](#one-credential-a-whole-fleet-shares-replaced-on-a-schedule).

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
| `credential-do` | JIT, plus rotation-with-overlap on one type | **Three credential types, chosen per role.** DigitalOcean API tokens (`POST /v2/tokens`) — code-shape reference; **cannot issue against real DO**¹. Spaces access keys (`POST /v2/spaces/keys`), one per lease. The same Spaces keys shared by a whole fleet and rotated on a schedule — `credential_type=spaces_key_rotated`, below | — |
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

¹ **`POST /v2/tokens` is neither public nor usable.** DO's public OpenAPI spec has no `/v2/tokens` path, and DO documents personal-access-token creation as a control-panel flow only. Worse, a real-account probe on 2026-08-21 found the endpoint **refused for every personal access token**: `GET`/`POST /v2/tokens` return 403 with `X-Response-From: Edge-Gateway` while eleven other endpoints on the *same* full-access token return 200 from `X-Response-From: service`. Token management is fenced off at DigitalOcean's edge as a matter of routing, not privilege — so `credential-do` cannot mint against real DigitalOcean, and there is no headless alternative (the OAuth flow needs interactive authorization; Spaces keys are a different credential type on this same plugin — and the one it *can* mint, which is why it has two of them). It is retained as the structure the other nine plugins follow and as the origin of the DO cloud fake, both of which the test layers depend on. Findings: [KI-009](docs/known-issues.md), [`docs/do-api-verification-2026-08-21.md`](docs/do-api-verification-2026-08-21.md), rationale in [`docs/decisions.md`](docs/decisions.md).

DO roles take DigitalOcean's fine-grained scopes (`<resource>:<verb>`) verbatim, so a role can be narrowed to exactly the operations it needs — e.g. `scopes=droplet:create,droplet:read` for a role that may only launch and list Droplets. Scope strings are passed through unvalidated, and the minter must itself hold every scope it grants. (Academic against real DO, per the footnote above — but this is the scope-pass-through pattern the other plugins' role fields follow.)

Two questions about object storage have opposite answers, so they are kept apart.
**Can S3-style keys be issued through an API? On DigitalOcean, yes** — `POST /v2/spaces/keys` is in
DO's published spec, takes a plain bearer token, and is what `credential-do`'s two Spaces types are
built on (`credential_kind=s3_credentials`, per-bucket `grants`). DO's product docs claim the keys
are control-panel-only and a 2026-08-21 probe answered 404; both are wrong, and the evidence is in
[`docs/cloud-credential-research.md`](docs/cloud-credential-research.md). Note what is *not* proven:
this repo's own real-cloud probe has never been run, so treat the plugin's behaviour against real DO
as unverified. **Is object storage a viable per-customer product substrate? No, and that is
unchanged** — see [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md).
DO's caps are per account and bind at 100 buckets, and the use case that motivated the audit needs
credentials that survive an OpenBao outage. A Spaces key issued here is an operational credential for
a management plane, not a per-customer backup grant.

## Configuration flow

Each mount is configured in three steps:

```bash
bao write cloud-creds/<cloud>/config <operational + cloud settings>     # no minters here
bao write cloud-creds/<cloud>/minter-sets/<set> minters=...             # one or more named minter sets
bao write cloud-creds/<cloud>/roles/<role> minter_set=<set> <role fields>
```

Minters live in named **minter sets**, not in `config`. Every role is bound to a required `minter_set` and mints only from that set's credentials — the isolation boundary for least-privilege and audit provenance. Each issued credential records its `minter_set` and `minter_id` in the response envelope metadata (`api_version` 4). Each set must independently satisfy the minter-validation rule (at least one `never_expires` minter, or at least two with ≥7-day expiry separation) — evaluated over the set's **active** (non-retired) minters.

The `config` endpoint's operational fields include `reconcile_cadence`, `max_deletes_per_pass`, `minter_expiry_warn` (the near-expiry warning threshold, default 7 days), `minter_retire_grace` (how long a rotated-out minter stays usable before deletion, default 7 days — see below), `verify_minter_capability` (default **true** — see below), and `capability_cache_ttl` (how long a successful capability probe stands in for a fresh one, default 1h; 0 re-probes on every write). `minter_retire_grace` is **refused** on DO/OVH/Vultr/OCI, where minters cannot self-rotate and nothing is ever retired.

### The credential shape is named, and a client can pin it

The `credential` block is cloud-specific by nature — an AWS session is three fields, Akamai's EdgeGrid credential is four, a GCP token is two — so every response names its shape in `metadata.credential_kind` (`sigv4_session`, `oauth2_bearer`, `basic_auth`, `bearer_token`, `scoped_token`, `key_secret`, `s3_credentials`, `azure_client_secret`, `edgegrid`, `oci_auth_token`). A client may **pin** the shape it is able to parse:

```bash
bao read cloud-creds/aws/creds/deploy credential_kind=sigv4_session
```

If the role serves a different shape the read is refused with `credential_kind_unsupported`, naming both shapes, **before anything is loaded or minted** — so a caller that could not have used the credential never causes one to be created. Omitting the pin still works and still tells you the shape in the response.


### One credential a whole fleet shares, replaced on a schedule

Every other credential type here mints per read: the lease that read it owns it, and the lease's own
end is what bounds it. DigitalOcean Spaces keys also support the opposite arrangement, because they
have to — a Spaces key has **no expiry field** and none can be retrofitted, and `PUT`/`PATCH` change
only its name, so grants are immutable and the only way to replace one is to create the next and
delete the old. That leaves a window in which both work, and `credential_type=spaces_key_rotated`
makes the window a declared, bounded part of the role:

```bash
bao write cloud-creds/do/roles/backup-reader \
  minter_set=default credential_type=spaces_key_rotated \
  grants=backups:read region=nyc3 \
  rotation_period=2160h overlap_ttl=48h max_ttl=48h
```

One key exists per **role**, not per read. A read re-serves the key the role already holds, so a
client that re-reads on a timer keeps getting the same `access_key`/`secret_access_key` until the key
reaches its rotation age; the next read after that mints the replacement, serves it, and schedules the
replaced key's deletion for `overlap_ttl` later. Clients that have not re-read yet keep working
throughout that window and pick the new key up whenever they next ask. Nothing has to be coordinated
outside the mount: `rotation_period` is a **ceiling** (`rotation_jitter`, default a tenth of the
period, is subtracted from it — never added — and is rolled once when the key is minted, so the date
does not move under a client), and a background sweep deletes retired keys and rotates an overdue role
even if nobody reads it.

Two consequences are worth stating plainly. **The lease is not the disposal mechanism** — a lease
ending deletes nothing, since the credential belongs to the role — so leases are non-renewable and
`max_ttl` must be no greater than `overlap_ttl`, which is what keeps a lease from outliving the
credential in it even when it is issued the instant before a rotation. And **the mount stores the
secret**, which nothing else here does; it is the price of re-serving the same credential, and it is
in [`docs/decisions.md`](docs/decisions.md) with the rest of the trade.

`bao write cloud-creds/do/roles/backup-reader/rotate` does the same replacement on demand, keeping the
overlap — the right lever when a credential is merely stale. When it has *leaked*, the lever is
`revoke-upstream` below, which deletes it now and breaks every holder.

### Spreading a fleet across minters (`shard_key`)

A role's minter set exists for redundancy, but it can also multiply an upstream rate limit: the
upstream meters per **credential**, so each minter carries its own budget for the mint, list and
revoke calls — measured on DigitalOcean at 5000/hour per token, from a single account, so this needs
no multi-account estate. Selection is by rendezvous hash of a per-client key, so a client is pinned
to one minter and different clients spread across the set — and a heavy client exhausts its own
shard rather than everybody's. Note this multiplies *issuance*: a credential you have been issued is
metered on itself whichever minter made it.

`shard_key` is **optional**:

```bash
bao read cloud-creds/do/creds/reader shard_key=worker-7
```

Omit it and the caller's OpenBao token accessor is used, which is per-token and therefore usually
per-worker — so a fleet where each instance has its own token gets spreading with no client change.
Send it when several workers share one token (they would otherwise share a shard), or when a worker
re-authenticates often and you want its shard to survive that.

Affinity is a preference, not a constraint: an unhealthy or throttled minter falls through to the
next preference deterministically, so redundancy is unaffected.

Two caveats. It multiplies nothing if the set's minters live in the same upstream account. And on
**AWS, GCP and Azure** it does not multiply the client's quota at all — there the credential's
identity is a target named on the *role* (`iam_role_arn`, the impersonated service account,
`app_object_id`) and is the same whichever minter issued it; on those three it spreads only the
mint-time calls. The per-cloud table is in [`docs/decisions.md`](docs/decisions.md).

This is what makes adding a shape backwards-compatible. A cloud can serve more than one: AWS SES over SMTP needs `{username, password}`, and cannot use an STS session at all, because SMTP `AUTH` carries only two values and there is nowhere to put the session token. When that shape appears, a client pinning `sigv4_session` keeps getting exactly what it asked for. A kind names a payload rather than a cloud, so two clouds emitting the same keys share one — GCP and OVH are both `oauth2_bearer` — and a conformance test over the whole registry enforces that rather than trusting it.

### Minter capability is verified, not assumed

A health check proves a minter credential is *live*; it does not prove the credential may **mint** what the roles bound to its set ask for. AWS answers `GetCallerIdentity` without any policy permitting it; an Akamai api client can always read itself; UpCloud's account endpoint doesn't report `can_create_tokens`; GCP impersonation is a grant on each *target* service account. So an under-privileged minter is reported healthy indefinitely and fails at the first credential read — as an upstream 403 delivered to an unrelated caller, long after the operator who caused it got a `200 OK`.

Instead each plugin runs a **capability probe**: mint a throwaway credential using the same request shape a real issuance would use, then delete it. Probes run when a minter set is written, when a role is bound to a set, and before a minter rotation commits — so an incapable minter is rejected at configuration time, naming the minter and the roles it cannot serve:

```
minter capability verification failed: minter "minter-1" cannot mint the
credential role(s) purge-only require: probe api-client creation returned 403 …
(set verify_minter_capability=false on the config endpoint to skip this check)
```

Verifying at role write is deliberate in both directions: it stops an operator defining a role whose minting key is unsuitable, and it means a minter set must exist and demonstrably work before roles can bind to it. On the three clouds that cannot revoke what the probe mints (AWS, GCP, OVH), the probe asks for the shortest lifetime the cloud accepts — a 900s STS session, a 60s GCP token, OVH's fixed 1h — and the credential is never returned to anyone. OCI is deliberately not probed: its two-auth-tokens-per-user cap means a probe would consume one of the rotation slots it exists to protect. Full per-cloud table, costs, and the escape hatch: [`docs/minter-capability-verification.md`](docs/minter-capability-verification.md).

## Containing a leak: two levers

A credential this plugin issued is believed to be in the wrong hands. There are two things to
do, and **deleting the role is neither of them** — it stops nothing, because live leases stay
renewable and every credential already issued keeps working.

```bash
bao list  cloud-creds/<cloud>/issued                                      # what is outstanding, and whose?
bao write cloud-creds/<cloud>/roles/<role> disabled=true                  # stop issuing more
bao write cloud-creds/<cloud>/roles/<role>/revoke-upstream mode=dry_run   # how many are out?
bao write cloud-creds/<cloud>/roles/<role>/revoke-upstream                # delete them upstream
bao read  cloud-creds/<cloud>/roles/<role>/revoke-upstream                # progress
```

`issued/` comes first because an incident hands you a credential or a service name, not a lease id.
It lists every credential this mount has issued and not yet revoked, keyed by the id the cloud's own
console shows, and each entry names the role, the minter and **who obtained it** — the token accessor
and identity entity core resolved at issuance, which is how a leaked credential is traced to one unit
rather than to a mount. It pages (`after`/`limit`), it never contains credential material, and it is
an inventory rather than a log: an entry disappears when its credential is revoked. On OCI it refuses
with `unsupported`, because a credential there is a shared rotation slot and there is no
per-credential record — an empty list would read as "nothing is outstanding".

A role can also insist on being able to name its callers before it issues at all:
`require_caller_identity=any` refuses a request core resolved no caller for, and `token_accessor`
additionally refuses a batch token, whose accessor is absent and whose identity entity belongs to the
service token that created it.

The levers are independent on purpose. `disabled=true` needs nothing but the flag — not the
role's other fields, and not a healthy cloud — so an operator who does not have the role
definition to hand can still close the tap. `revoke-upstream` works on a role that is already
disabled, so the natural order (close the tap, then empty the bucket) never requires briefly
re-enabling issuance. And it deliberately leaves the role issuing, so a responder can destroy
what leaked without also taking the consumers down.

Scope is **what the role had issued when the call was made**: credentials issued afterwards are
untouched, including the ones the responder mints to run the response with. A purge of a role
holding thousands of credentials is thousands of upstream API calls against the same quota the
mount issues from, so the call arms a durable intent, runs one bounded pass inline and returns
progress; a background worker on the active node continues in equally bounded passes, across a
restart or a failover. Both operations answer in one schema on every cloud — `role`, `armed`,
`cutoff`, `tracked`, `deleted`, `remaining`, `failed`, `complete`, plus the `mode` a write ran
in — so a runbook is written once and automation can watch for `complete`.

**What lever you have depends on the cloud, and on three of them there is none:**

| Cloud | Lever for a credential already issued |
|---|---|
| DigitalOcean (tokens and per-lease Spaces keys), UpCloud, Azure, Exoscale, Vultr, Akamai | `revoke-upstream` deletes it |
| DigitalOcean (`credential_type=spaces_key_rotated`) | **two, and they are not interchangeable.** `roles/<role>/rotate` replaces the shared key now and lets the replaced one live out its `overlap_ttl`, so clients pick the new one up on their next read — right when the credential is merely stale. `revoke-upstream` deletes it now and breaks every holder — right when it has leaked |
| AWS, GCP, OVH | **none.** The credential cannot be deleted — an STS session, an impersonation token and an OVH OAuth2 token only expire — so the role's `max_ttl` is the blast radius (AWS/GCP ≤12h, OVH exactly 1h). Disabling the role stops the next one; the ones out have to run down |
| OCI | `rotate-slot/<role>/<slot_index>` replaces that slot's credential now, which invalidates it for every holder |

On AWS, GCP, OVH and OCI the endpoint exists and **refuses** with `unsupported`, naming the
reason and the lever above. That is deliberate: a success response listing zero deletions would
tell a responder mid-incident that they had contained something they had not.

## Minter lifecycle

The long-lived minter credentials are the highest-value secrets at rest, so the plugins make them observable and, where the cloud API allows, rotatable.

- **Observability.** On the health-check cadence each plugin emits `cloud_creds_minter_age_seconds` for **every** minter (including `never_expires` ones, which otherwise carry no lifetime signal), and logs a `minter nearing expiry` warning when an expiring minter is within `minter_expiry_warn` of its expiry.
- **Self-rotation.** `bao write cloud-creds/<cloud>/minter-sets/<set>/rotate minter_id=<id>` mints a successor minter (a new long-lived credential of the same kind, itself mint-capable), health-checks it, **capability-probes it against every role bound to the set**, and only then swaps it into the set and marks the old minter *retired*. The old credential is **not** deleted immediately: it stays upstream-alive for `minter_retire_grace` (default 7 days) so other nodes in a raft cluster — which cache the minter set in memory until they reload — keep working; a background sweep deletes the old upstream credential once the grace elapses. A retired minter is excluded from new issuance and from set validation the moment it is retired. Rotation is refused up front if retiring the chosen minter would leave the set unable to validate. Supported on the clouds marked ✅ above; the rest reject with a clear message.

## Installing

Build verifiable artifacts and the hashes to check them against:

```bash
make dist            # builds every plugin into dist/ with -trimpath, plus SHA256SUMS
```

Then register each plugin with its hash. OpenBao refuses to run a plugin whose hash
does not match, which is what makes the rest of the security model meaningful:

```bash
cp dist/credential-aws "$BAO_PLUGIN_DIR/"
bao plugin register -sha256=$(grep credential-aws dist/SHA256SUMS | cut -d' ' -f1) \
    -command=credential-aws secret cloud-creds-aws
bao secrets enable -path=cloud-creds/aws cloud-creds-aws
```

Every module also builds without the Go workspace (`make build-standalone`), so a
single plugin can be built or scanned in isolation — `go install` of one plugin's
`cmd` works, and a per-module SBOM or licence scan sees a complete dependency set.

Reporting security issues: [`SECURITY.md`](SECURITY.md). Third-party licences:
[`NOTICE`](NOTICE).

## Build and test

```bash
go build github.com/nicois/openbao-cloud-creds/...   # build all (Go workspace)
go test github.com/nicois/openbao-cloud-creds/...     # unit + fake-backed integration tests
make test-conformance                                  # every shared test category × every plugin, plus the coverage matrix
make test-e2e                                          # plugin binaries in a live OpenBao, driven over HTTP through the lease lifecycle
make smoke-test                                        # register every plugin in a live OpenBao dev server
make test-cloud-real-do                                # REAL DigitalOcean API: real PATs and one real Spaces key (opt-in)
make test-cloud-real-do-spaces                         # REAL DO Spaces-key API only: creates and deletes a real access key (opt-in, never run)
make test-cloud-real-aws                               # REAL AWS STS: assume-role mints against a real account (opt-in, $0)
make build-standalone                                  # every module builds without the workspace
make dist                                              # release artifacts + SHA256SUMS
make lint                                              # golangci-lint v2 across all modules
```

`make test-e2e` and `make smoke-test` need an OpenBao binary on PATH (no cloud credentials — the cloud fakes stand in for the upstreams).

`make test-cloud-real-aws` calls real AWS STS with an IAM user's access key you supply (`CLOUDREAL_AWS_KEY=access_key_id:secret_access_key` plus `CLOUDREAL_AWS_ROLE_ARN`). It costs nothing (IAM and STS are unmetered) and creates nothing that needs deleting — STS sessions cannot be revoked, so every duration it asks for is the shortest the assertion allows and they expire on their own. The minter needs only `sts:AssumeRole` on the target role; the target role's trust policy must name that user and allow **both** `sts:AssumeRole` and `sts:TagSession`, and needs no permissions of its own. It confirmed what a fake cannot: the credential AWS returns actually authenticates, and STS grants exactly the duration asked for. It also found [KI-010](docs/known-issues.md).

`make test-cloud-real-do` calls DigitalOcean with a PAT you supply (`CLOUDREAL_DO_TOKEN`, or `.env.cloud-real`) and **creates and deletes real credentials**, so use a dedicated, disposable account: its `-run TestRealDO` matches both DO probes, so it exercises personal access tokens *and* mints one real Spaces key. It existed to probe the one assumption no fake can test — that the undocumented `POST /v2/tokens` works headlessly — and the answer is **no**: with a full-access PAT, token management is refused at DigitalOcean's edge gateway while eleven other endpoints on the same token succeed, so **no PAT can mint and the `token` credential type cannot issue against real DigitalOcean** ([KI-009](docs/known-issues.md)). That type remains this repo's code-shape reference and the origin of the DO fake, and is not presented as production-viable; the test's job is now to pin that finding and fail loudly if DigitalOcean ever changes it. **The Spaces probe (`make test-cloud-real-do-spaces`) has never been run**, because no DO token has been reachable from the development environment — so both Spaces credential types are green at every layer below the real cloud and unverified against it, which is a weaker claim than the token type's and should not be read as a stronger one. The other eight clouds have no real-cloud test; see [`docs/free-account-viability.md`](docs/free-account-viability.md) for the plan and what each would cost.

**Testing is conformance-first.** With ten near-identical plugins, a missing test looks exactly like a passing one, so every invariant that is about a plugin's own behaviour rather than a cloud's wire format is written once in `pkg/plugintest` and applied to every plugin from a single table in the test-only [`conformance/`](conformance/) module: `reload`, `lease`, `perturbation`, `revoke`, `capability`, `minter-visibility`, `reconciler-safety`, `error-taxonomy`, `containment`, `rotation`. A table entry is a **subject** rather than a cloud — `credential-do` registers three, one per credential type — because a harness declares one credential shape, one secret type and one tracking prefix, which is exactly what a client and the lease core see. A plugin missing from that table fails the build; a category that genuinely does not apply to a cloud must be *declared* with a reason (`Harness.Skips`) and is printed by `make test-conformance` as one reviewable line, rather than hidden in a `t.Skip`. Per-cloud vocabulary — mint shapes, deny knobs, unexported internals — stays in each plugin's own tests.

Above that sits [`e2e/`](e2e/): each plugin built as a binary, registered in a live `bao server -dev` and driven over HTTP through config → minter set → role → issue → lease lookup → renew → revoke → `plugin reload` → re-issue. It exists for what an in-process test cannot see — the plugin's JSON-serialized RPC boundary and OpenBao core's own expiration manager — and it earned its place immediately, finding two live defects (background workers never starting on a reloaded backend, and six plugins advertising renewable leases whose renewal failure made core *revoke* the credential). Rationale in [`docs/decisions.md`](docs/decisions.md); what each layer does and does not prove in [`docs/openbao-integration-gaps.md`](docs/openbao-integration-gaps.md); the rules for contributors and agents in [`AGENTS.md`](AGENTS.md).

## Documents

- [`SUMMARY.md`](SUMMARY.md) — repository map: plugin/feature state, concepts, and a guide to every doc
- [`AGENTS.md`](AGENTS.md) — how to change this repo without eroding it; the conformance-first testing rules
- [`docs/cloud-credential-research.md`](docs/cloud-credential-research.md) — what each cloud's API supports; authoritative for per-cloud strategy
- [`docs/techrfc.md`](docs/techrfc.md) — original RFC; authoritative for the response-envelope and error-code contract (its implementation-status notes are superseded — see the banner in that file)
- [`docs/design.md`](docs/design.md) — companion design doc (same caveat)
- [`docs/decisions.md`](docs/decisions.md) — non-obvious design choices and why
- [`docs/ttl-semantics.md`](docs/ttl-semantics.md) — what a lease TTL means per cloud; enforced role-TTL bounds; and where the TTL is also the containment bound
- [`docs/minter-capability-verification.md`](docs/minter-capability-verification.md) — why health ≠ capability, what each cloud's probe mints and costs, and what it deliberately doesn't cover
- [`docs/known-issues.md`](docs/known-issues.md) — known issues and operational caveats (KI-001…); **KI-011 is the incident-response entry**, including which clouds have no lever beyond the role's `max_ttl`
- [`docs/openbao-integration-gaps.md`](docs/openbao-integration-gaps.md) — what each test layer proves, and what testing the plugins in isolation from OpenBao does not cover
- [`docs/free-account-viability.md`](docs/free-account-viability.md) — whether each cloud can be exercised for real on a free account, and the CI design for validating the fakes against recordings
- [`docs/object-storage-credential-audit.md`](docs/object-storage-credential-audit.md) — object-storage viability analysis (out of scope)

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
