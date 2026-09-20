# OpenBao Short-Lived Cloud Credentials — Design

> **⚠️ STATUS (2026-05-30):** This is the original design doc, written for the DO reference round. It is retained for its envelope / lease-lifecycle / metrics / reconciler rationale, which remain accurate. Three things are STALE: (1) it lists only six clouds — ten are now implemented (adds Exoscale, Vultr, Akamai, Oracle/OCI); (2) the "Native (STS/GCP/Azure engine wrapper)" strategy was abandoned — OpenBao has no GCP/Azure engine, so those are full JIT plugins; (3) minters no longer live in `config` and roles no longer draw from a shared minter list — minters are now in named **minter sets** (`minter-sets/<name>`) and every role binds to a required `minter_set` (envelope api_version is now 2 with `minter_set`/`minter_id` provenance); (4) minters now have a lifecycle beyond this doc — an age gauge + configurable near-expiry warning, and operator-initiated **self-rotation** (`minter-sets/<name>/rotate`, grace-based and cross-node-safe) on the six clouds whose API can mint a mint-capable successor. See `docs/cloud-credential-research.md`, `CLAUDE.md` (Minter sets section), and `docs/decisions.md` for the current cloud list, per-cloud strategy, minter-set rationale, and minter-lifecycle design. **Further correction (2026-08-21):** (5) the DO strategy row below presents `POST /v2/tokens` / `DELETE /v2/tokens/{id}` as public API — they are **not** in DigitalOcean's public OpenAPI spec (PAT creation is documented as control-panel-only), so the reference plugin depends on a control-panel-internal endpoint; and DO scopes are fine-grained `<resource>:<verb>` (e.g. `droplet:create`), not `read`/`write`. See [`docs/do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md). (6) goal 2 below ("honest TTL semantics") is now backed by validation as well as by strategy: role TTLs a cloud cannot honour are rejected at write time and leases are non-renewable wherever the credential's expiry is fixed at mint — per-cloud matrix in [`docs/ttl-semantics.md`](ttl-semantics.md). **Further correction (2026-09-15):** (7) every DO row below describes one credential type, and there are now three. A `credential-do` role selects `credential_type=token` (the `/v2/tokens` PAT described here, which cannot be minted against real DigitalOcean — KI-009), `credential_type=spaces_key` (an S3-compatible Spaces access key via `POST /v2/spaces/keys`, one per lease, which is what the plugin can actually issue) or, since 2026-09-16, `credential_type=spaces_key_rotated` (the same key held by the *role* and shared by every reader, replaced every `rotation_period` with the replaced one deleted `overlap_ttl` later). So the role fields, the `credential` block, the scope kind, the secret type, the tracking prefix and what a lease ending does all depend on the role's type — and on the third type a lease ending does nothing, because the credential is not the lease's; see [`docs/cloud-credential-research.md`](cloud-credential-research.md) and the 2026-09-15 entries in [`docs/decisions.md`](decisions.md).

**Status:** Draft (2026-05-29) — partly superseded, see banner
**Scope of this round:** API contract + DO reference implementation

## Problem

Control-plane services and CI jobs need short-lived, role-based credentials for the cloud APIs they call (AWS, GCP, Azure, DO, UpCloud, OVH). Some clouds support short-lived tokens natively (STS, GCP impersonation, Azure SP creation); others do not. We want a single uniform OpenBao API that hides this divergence so callers don't branch per-cloud.

## Goals

1. Uniform OpenBao API: `bao read cloud-creds/<cloud>/creds/<role>` returns a credential plus a normalized envelope, regardless of cloud.
2. Honest TTL semantics: every issued lease's `expires_at` reflects the actual time the credential is valid for the caller. No lying about lifetime. (Enforcement, added 2026-08-21: TTLs the cloud cannot honour are rejected at role write — OVH exactly 3600s, AWS 900–43200s, GCP ≤43200s, UpCloud ≤8760h — and renewal is refused where the credential's expiry is fixed at mint. See [`ttl-semantics.md`](ttl-semantics.md).)
3. No human in the rotation loop: bootstrap MAY require a one-time human action; steady-state rotation MUST be fully headless.
4. Resilience to upstream flakiness: transient cloud failures are absorbed; auth failures self-heal once upstream recovers.
5. Auto-deletion of expired credentials so cloud quotas don't fill with abandoned entities.
6. Per-cloud quota safety: every auto-delete only touches entities the plugin itself created, identified by an owner-tagged/prefix scheme.

## Non-goals

- Cloud-side usage tracking (only OpenBao-side issuance and renewal).
- Auto-deletion of long-lived target entities (IAM roles, parent SAs, parent apps); only ephemeral and rotated-out artefacts auto-delete.
- OVH support in this round; deferred until OAuth2 service-account coverage is verified for the OVH APIs in scope.
- End-customer / BYOC credential flows; this spec serves operator-side control-plane services and CI only.
- Token-format translation or cloud-API proxying; clients use cloud SDKs with native creds.

## Architecture

One OpenBao plugin per cloud, registered as a credential or secret backend depending on cloud:

```
plugins/
  credential-aws/        # native wrapper over OpenBao aws engine
  credential-gcp/        # native wrapper over OpenBao gcp engine
  credential-azure/      # native wrapper over OpenBao azure engine
  credential-do/         # JIT — REFERENCE IMPLEMENTATION
  credential-upcloud/    # phased rotation — follow-up spec
  pkg/
    credenvelope/        # envelope types, error codes, lease tag helpers
    cloudconfig/         # config/<cloud>, roles/<name> CRUD boilerplate
    rotator/             # phased-rotation slot manager
    recovery/            # upstream recovery state machine
    metrics/             # per-node access metrics + Prometheus emission
    reconciler/          # auto-deletion / orphan reclamation worker
```

### Why per-cloud plugins (not one super-plugin)

- Plugin failures are isolated by OS-level process boundary.
- Cloud SDK bloat doesn't compound (each binary links only its own SDK).
- Matches existing `plugins/credential-do/` skeleton in the spike.

### Shared envelope contract

All cloud-specific behavior is implemented behind a uniform response shape (see API Contract). Shared Go packages enforce the envelope invariants so plugins can't drift.

## API Contract

### Read path

```
bao read cloud-creds/<cloud>/creds/<role>
```

Response `data` block:
```json
{
  "cloud": "do",
  "role": "snapshot-rw",
  "credential": { /* cloud-native fields, schema fixed per cloud */ },
  "expires_at": "2026-05-29T14:30:00Z",
  "ttl_seconds": 900,
  "renewable": true,
  "credential_id": "do-tok-7a3f...",
  "metadata": {
    "scope": "read write",
    "issued_by": "cloud-creds-do/v0.1",
    "api_version": "1"
  }
}
```

OpenBao wraps the response with standard `lease_id`, `lease_duration`, `renewable` at the top level. Clients use those for lease ops.

### Per-cloud `credential` schema (frozen contract)

| Cloud   | Fields |
|---------|--------|
| `aws`   | `access_key_id`, `secret_access_key`, `session_token` |
| `gcp`   | `access_token`, `token_type` (always `Bearer`) |
| `azure` | `client_id`, `client_secret`, `tenant_id`, `subscription_id` |
| `do`    | `token`, `scopes[]` |
| `upcloud` | `username`, `password` |
| `ovh`   | `application_key`, `application_secret`, `consumer_key` (deferred) |

### Role configuration

```
bao write cloud-creds/<cloud>/roles/<name> \
  default_ttl=15m max_ttl=1h \
  <cloud-specific fields>
```

Cloud-specific fields (not exhaustive):
- AWS: `iam_role_arn`, `policy_arns[]`, `inline_policy`
- GCP: `service_account_email`, `scopes[]`
- DO: `scopes[]` (fine-grained `<resource>:<verb>`, e.g. `droplet:create droplet:read`; `api:read`/`api:write` are all-read/all-write aliases — corrected 2026-08-21)
- UpCloud: `permissions` (per UpCloud's API)

### Error model

Standard OpenBao 4xx/5xx + JSON body with stable `error_code`. Codes are exported as Go constants in `pkg/credenvelope/errors.go`; adding a code is a spec change. Clients pin to `metadata.api_version`.

Configuration-time rejections (an invalid role TTL, a failed capability probe) are
plain OpenBao error responses on the *write* that caused them, not envelope
errors: they never reach a credential-reading client, so they carry no
`error_code`. This is why capability verification added none — and why the
runtime `minter_insufficient_privilege` idea was deliberately not pursued (see
[`decisions.md`](decisions.md)).

| Code | HTTP | Meaning | Client retry |
|------|------|---------|--------------|
| `role_not_found` | 404 | Role doesn't exist | No |
| `role_disabled` | 403 | Operator-disabled | No |
| `entity_unavailable` | 503 | Upstream entity rotating/retiring | Yes, backoff |
| `upstream_quota_exceeded` | 429 | Cloud rate limit/quota | Yes, exp backoff + jitter |
| `upstream_auth_failed` | 502 | Plugin's bootstrap creds rejected | No (operator) — plugin self-heals if transient |
| `upstream_timeout` | 504 | Upstream API didn't respond, or the client-side deadline fired | Yes, backoff |
| `upstream_unavailable` | 503 | Cloud unreachable, or answered 5xx | Yes, backoff |
| `upstream_request_invalid` | 400 | Cloud rejected the request's content (400/409/422) | No — fix config |
| `config_invalid` | 400 | Operator input is missing, malformed, or names something that does not exist; also a failed capability probe | No — fix config |
| `unsupported` | 501 | This cloud cannot do it and never will (minter rotation on DO/OVH/Vultr/OCI; `revoke-upstream` on AWS/GCP/OVH/OCI, where the message names the containment the operator does have) | No — never |
| `credential_kind_unsupported` | 400 | The caller pinned a `credential_kind` this role does not serve, or one this binary does not know | **Yes, asking for a different shape** — the one refusal a client can resolve without an operator |
| `caller_unidentified` | 403 | The role sets `require_caller_identity` and core resolved no acceptable caller from the presented token | **Yes, under a different token** — a batch token has no accessor, so re-present under a service token |
| `pool_exhausted` | 503 | All slots simultaneously unavailable | Yes, short backoff |
| `lease_revoke_failed` | 500 | Couldn't revoke upstream cleanly | Operator alert |
| `internal` | 500 | Plugin bug, or a failure none of the above describes | No |

> **Revised 2026-09-20.** `caller_unidentified` added with the role field
> `require_caller_identity`. It earns a code because the action is the *caller's* and is
> specific: every other `do not retry` code needs an operator, while this one is resolved by
> presenting the request under a token core can name. Additive, so no `api_version` bump.
>
> **Revised 2026-08-23.** `credential_kind_unsupported` added with `metadata.credential_kind`
> (api_version 4). It passes the "a client would act differently" test in a way no other
> code does: a library that can parse two shapes retries asking for the other one, where
> every other `do not retry, fix config` code needs a human. Adding it is additive and needs
> no version bump — the bump is for the *envelope* field, not the code.
>
> **Revised 2026-08-22.** `consent_required` is **removed**: it was specified here and never emitted by any code path, so no client can have seen it. The five codes above it are new, and `upstream_timeout` is newly *reachable* — it previously required the cloud to answer 408/504, while every plugin's own 30s client timeout produced no status at all and was reported as `internal`. See [`known-issues.md`](known-issues.md) KI-010 and the audit in [`decisions.md`](decisions.md).

## Per-cloud strategies

Two underlying strategies; choice per cloud depends on whether the cloud API supports headless per-request token creation.

| Cloud | Strategy | Honest TTL? | Notes |
|-------|----------|-------------|-------|
| AWS | Native (STS) | Yes | Thin envelope wrapper over OpenBao `aws` engine |
| GCP | Native (impersonation) | Yes | Wrapper over OpenBao `gcp` engine |
| Azure | Native (dynamic SP) | Yes | Wrapper; SP creation slow (~10s); document |
| DO | JIT | Yes | `POST /v2/tokens` mints; revoke `DELETE /v2/tokens/{id}`. **Reference impl in this round.** |
| UpCloud | Phased rotation (default N=2, T=7d) | Yes (≥ T/2) | Follow-up spec. If UpCloud's API supports JIT cleanly, implementation MAY switch to JIT; envelope unchanged |
| OVH | Deferred | n/a | Pending OAuth2 service-account coverage verification |

### JIT strategy (DO)

- Plugin holds ≥1 minter credential (the long-lived bootstrap PAT) in config.
- Read handler: calls upstream API to mint a scoped credential; wraps in envelope.
- Revoke handler: calls upstream API to delete the minted credential.
- `internal_data` carries the upstream `cred_id` so revoke is deterministic.

### Phased rotation (UpCloud, future)

- N upstream credential slots per role; each has an upstream cred + `rotated_at`.
- Background rotator replaces one slot at a time, spaced T/N apart, so slot ages stagger across [0, T) at all times.
- Read handler: hands out the freshest slot; lease's `expires_at` = that slot's next-rotation time.
- Revoke handler: best-effort. Lease vanishes from OpenBao; upstream cred lives until its scheduled rotation. Documented limitation.
- Emergency rotation: `bao write cloud-creds/<cloud>/rotate-slot/<role>/<slot_id>` forces immediate replacement.
- Default `(N=2, T=7d)`; tunable per role.

### OVH (deferred)

OVH ships in a follow-up spec after research verifies one of:
- OAuth2 service accounts cover the OVH APIs in scope (preferred — fully headless, slots into phased-rotation unchanged), or
- Headless browser automation for legacy consumer-key validation (separate design — sidecar process, browser binary, UI-scrape stability concerns).

## Lease lifecycle

Standard OpenBao leases:
- `default_ttl` and `max_ttl` per role; `bao lease renew` extends within `max_ttl`.
- Auto-revoke on expiry (OpenBao calls plugin's revoke handler).
- Explicit `bao lease revoke` calls plugin's revoke handler synchronously.

Revoke semantics differ by strategy:
- **JIT**: plugin actively deletes the upstream credential. Hard revoke.
- **Phased rotation**: plugin forgets the lease internally; upstream credential persists until its scheduled rotation. Soft revoke. Documented in role help text.
- **Native (STS/GCP/Azure)**: as upstream OpenBao engine implements it (typically hard revoke).

## Upstream credential lifecycle

Every credential the plugin relies on (minters, slot creds, native bootstrap) is a tracked entity in plugin storage:

```
upstream_creds/<cloud>/<cred_id> → {
  role: "minter" | "slot:<slot_id>" | "bootstrap",
  expires_at: <iso8601 | null>,
  expires_at_source: "cloud_api" | "operator_provided" | "never_expires",
  created_at: <iso8601>,
  last_success_at: <iso8601>,
  state: "healthy" | "transient_failing" | "auth_failing" | "missing",
  consecutive_failures: <int>,
  consecutive_auth_failures: <int>
}
```

`consecutive_failures` counts every failure against the minter; `consecutive_auth_failures` counts
only the ones where the credential itself was REJECTED, since its last success. The second is what a
cloud's account lockout counts, so it is the field to act on: nonzero means the next login spends
another of the few tries remaining before the account is unusable by anything, including the write
that would repair it. A 5xx or a timeout raises the first and not the second, and only a success
clears either.

Nonzero is already the signal — do not wait for `state` to reach `auth_failing`, which needs two
rejections at least the auth-fail threshold apart and therefore stays `transient_failing` while two
tries are already gone. `Gate.VerifyRole` refuses a role write on nonzero, and an external reconciler
may read it here for the same purpose.

### Expiry tracking — required

Every minter MUST have either an `expires_at` (preferably fetched from the cloud API; otherwise operator-provided) OR an explicit `never_expires=true`. Silent infinity is rejected.

| Cloud | Source |
|-------|--------|
| AWS IAM access key | `operator_provided` or `never_expires` |
| GCP SA key | `cloud_api` (when `validBeforeTime` is set) |
| Azure client secret | `cloud_api` (`endDateTime`) |
| DO PAT | `cloud_api` if API exposes it; else `operator_provided` |
| UpCloud token | `operator_provided` (verify in implementation) |

### Minter config validation (hard config-load failure if violated)

A minter set is valid iff at least one holds:
- Contains ≥1 minter with `never_expires=true` (permanent fallback exists), OR
- Contains ≥2 minters with `expires_at`, and pairwise expiry separation ≥ 7d among them.

Implications:
- `[never_expires]` → OK
- `[never_expires, expiring]` → OK
- `[expiring_a, expiring_b]` with ≥7d gap → OK
- `[expiring_a]` alone → REJECTED
- Two expiring minters with <7d gap → REJECTED (defeats seamless rotation)

Plugin selects whichever minter is healthy + freshest for new requests. To rotate: operator adds another minter, waits for traffic to drift onto it, removes the oldest.

**Validation is metadata-only, so it is not sufficient (added 2026-08-21).** The
rule above inspects `never_expires`/`expires_at`/`Retired` and nothing else — it
cannot tell a mint-capable minter from one that merely authenticates. Since a
health check cannot tell them apart either (AWS `GetCallerIdentity` needs no
policy; GCP's health call proves only the minter SA's own key; UpCloud's account
endpoint does not report `can_create_tokens`), each set/role write additionally
runs a **capability probe**: mint a throwaway credential with the real per-role
mint shape, then delete it. It runs at minter-set write, at role write (so a role
cannot bind to a set that has not been shown to mint what it asks for) and before
a rotation commits; it is gated by `verify_minter_capability` (default true) and
skipped on OCI, whose 2-token cap a probe would consume. Full detail:
[`minter-capability-verification.md`](minter-capability-verification.md).

### Recovery state machine

Each upstream credential transitions:
- `healthy` → `transient_failing` on any error (plugin retries inline, exp backoff, ~5s budget).
- `transient_failing` → `auth_failing` if 401/403 sustained >30s; plugin emits `upstream_auth_failed` to clients AND fires alarm metrics.
- `auth_failing` → `healthy` automatically when a background health-check (every 5min) succeeds. **No operator action required if the upstream issue resolved itself.**

If multiple minters are healthy, traffic is steered to them; if all minters are `auth_failing`, plugin returns `upstream_auth_failed` for new reads. **In-flight leases issued earlier are unaffected** — those credentials remain valid client-side until their own TTL.

## Auto-deletion

The plugin actively reclaims expired or rotated-out credentials so cloud quotas don't fill.

### What auto-deletes

| Class | Auto-delete? | Mechanism |
|-------|--------------|-----------|
| Per-lease JIT credentials | Yes | Lease expiry/revoke calls upstream delete |
| Rotated-out slot credentials | Yes | Reconciler sweeps after grace period |
| Orphaned per-lease creds (revoke failed, plugin storage cleared) | Yes | Reconciler reclaims |
| Azure ephemeral SPs from dynamic-SP engine | Already handled by upstream | n/a |
| Operator-provided minters | **No** — never auto-delete | Operator-managed |
| Long-lived target entities (IAM roles, parent SAs, parent apps) | **No** | Pointed-at, not rotated |
| "Stale" entities from access-metrics report | **No** — operator review only | Section "Access metrics" |

### Tag scheme — the safety boundary

The reconciler only deletes entities matching an owner-tagged/prefix scheme set at creation time:

| Cloud | Scheme |
|-------|--------|
| AWS | Tags `Owner=cloud-creds, ManagedBy=<plugin>, RoleName=<role>` where supported; `cloud-creds-` name prefix where tags aren't allowed |
| GCP | SA emails prefixed `cloud-creds-`; labels `owner=cloud-creds` |
| DO | Token names prefixed `cloud-creds-<role>-<lease_id>` |
| UpCloud | Name prefix as scope permits |

For native-engine wrappers (AWS/GCP/Azure), the upstream OpenBao engine MUST be configured to apply the tag scheme to anything it creates. Verification of this configurability is a per-cloud implementation task.

### Reconciliation worker

Every plugin runs a reconciliation worker:
- Default cadence: every 6h.
- Lists upstream entities matching the owner-tag scheme; compares to `upstream_creds/` registry + active leases.
- Orphans (matching the owner-tag scheme but with no plugin-side reference): logged loudly, `cloud_creds_orphans_found` metric emitted, deleted after 1h confirmation hold (so a flapping plugin can't sweep its own state).
- Registry entries whose upstream entity disappeared: marked `state=missing`, alarmed, NOT auto-recreated.
- Rotated-out slot creds: deleted after 7d grace from `retired_at` (configurable per-role).

### Safeguards (defense in depth)

1. ~~**`disable_auto_delete` per role** — emergency operator switch; halts upstream deletes for that role; metrics still emit.~~ **Withdrawn 2026-09-16, never implemented.** It was declared as a struct field read by nothing (audit A6) and is now removed. Halting the reconciler is the opposite of what an incident needs — the reconciler is what reclaims a leaked credential no lease points at any more — and what was actually missing was a way to delete credentials *sooner*. That is served by the two containment levers below.
2. **Dry-run mode** — `bao write cloud-creds/<cloud>/reconcile mode=dry_run` runs the worker but only logs/metrics; no deletes.
3. **Rate limit** — max 10 deletes per reconciliation pass per cloud (configurable). Worker stops + alerts if more should be deleted; operator must investigate.
4. **Bootstrap delay** — 24h after plugin start before reconciler runs (avoids "plugin upgrade with empty registry" deleting everything); configurable.
5. **Audit log** — every auto-delete writes a structured log line and emits `cloud_creds_auto_deleted_total{cloud, role, reason}`.

### Containment: a credential we issued has leaked

The reconciler is housekeeping, on a cadence of hours, and it only ever touches what nothing points at. Containment is a separate pair of levers, both taking the one identifier an incident supplies — the role name — and **deleting the role is not one of them**: it leaves live leases renewable and every issued credential working, which is the same as doing nothing except that it looks decisive.

```bash
# 1. Close the tap. Nothing but the flag is needed, and it works while the cloud is down.
bao write cloud-creds/exoscale/roles/deploy disabled=true

# 2. Ask how big the incident is. This changes nothing and arms nothing.
bao write cloud-creds/exoscale/roles/deploy/revoke-upstream mode=dry_run
```

```json
{ "role": "deploy", "mode": "dry_run", "armed": false, "cutoff": "2026-09-16T09:12:04Z",
  "tracked": 1840, "deleted": 0, "remaining": 1840, "failed": 0, "complete": false }
```

```bash
# 3. Empty the bucket. One bounded pass runs inline; the rest continues in the background.
bao write cloud-creds/exoscale/roles/deploy/revoke-upstream
```

```json
{ "role": "deploy", "mode": "normal", "armed": true, "cutoff": "2026-09-16T09:13:41Z",
  "tracked": 1840, "deleted": 50, "remaining": 1790, "failed": 0, "complete": false }
```

```bash
# 4. Watch it finish. Same keys, so automation waits on one field.
bao read cloud-creds/exoscale/roles/deploy/revoke-upstream
```

```json
{ "role": "deploy", "armed": false, "cutoff": "2026-09-16T09:13:41Z",
  "tracked": 1840, "deleted": 1840, "remaining": 0, "failed": 0, "complete": true }
```

Four properties are worth stating because each has a tempting wrong alternative:

- **The purge is armed, not done synchronously.** 1840 credentials is 1840 upstream API calls against the quota the mount issues from; doing them in the request would either exceed the deadline or take issuance down for the credentials that did *not* leak.
- **The cutoff is the arm time.** The role goes on issuing (step 1 is a separate decision), and credentials issued after the call — including the ones the responder mints to run the response with — are out of scope. Without that, a busy mount's purge never terminates.
- **Step 3 works even though step 1 already ran.** The purge reads the stored role directly rather than through the issuance loader, which refuses a disabled role; otherwise the sequence above would demand re-enabling issuance mid-incident.
- **Step 2 or 3 on AWS, GCP, OVH or OCI is refused**, with `unsupported` and that cloud's own remedy: on the first three the credential cannot be deleted at all and the role's `max_ttl` is the blast radius, while on OCI the credential belongs to a rotation slot and `rotate-slot/<role>/<slot_index>` replaces it for every holder.

## Access metrics (per-node, eventually consistent)

Each plugin instance accumulates access events in memory and flushes periodically to a per-node-tagged location in raft. Conflict-free merge: each node owns its own keyspace.

### Storage layout

```
metrics/<cloud>/<entity_id>/<node_id> → {
  roles: { <role_name>: { last_access_at, access_count } },
  flushed_at: <iso8601>,
  flush_seq: <monotonic int>,
  retired_at: <iso8601 | null>
}
```

`<entity_id>` is the cloud entity backing the credential (the thing an operator might want to delete), not the OpenBao role name:

| Cloud | `entity_id` |
|-------|-------------|
| AWS | IAM role ARN being assumed |
| GCP | SA email being impersonated |
| Azure | Parent app registration (NOT per-lease ephemeral SP) |
| DO (JIT) | The minter PAT (NOT per-lease minted token) |
| UpCloud (phased) | Current slot's upstream token ID |

### Flush mechanics

- In-memory map per plugin instance: `{(entity_id, role) → {last_access, count}}`.
- Background goroutine flushes every `flush_interval` (default 15min, configurable per role).
- Single raft transaction per flush (one write per node).
- Memory bound: evict from the in-memory map when leases referencing the entity are revoked or expire.

### Counting

A "client request" includes both initial `bao read .../creds/<role>` and every `bao lease renew`. A renewing lease is a credible signal that the cloud entity is still in use.

### Query API

```
bao read cloud-creds/<cloud>/metrics/entity/<entity_id>

> **Removed 2026-08-22 (A23).** The access-metrics endpoints (`metrics/entity`, `metrics/stale`) and the `flush_interval` config field are **gone**, along with `pkg/metrics` and `pkg/metricspath`. Their whole purpose was deciding whether an upstream entity was still in use before deleting it — and a minting credential handed to this plugin is not used anywhere else, so it can be rotated and deleted without that check. What an escalation actually needs is the identifier the *cloud* knows: minter metrics and the near-expiry warning now carry `cloud_key_id`. See [`audit-2026-08-22.md`](audit-2026-08-22.md) A23.

→ {
    last_access_at: "2026-05-29T13:42:11Z",
    access_count: 47,
    staleness_seconds: 312,
    source: "merged_with_local_active" | "merged_only"
  }

bao list cloud-creds/<cloud>/metrics/stale?older_than=7d
→ [ <entity_ids that haven't been accessed in N days, sorted by staleness> ]
```

`staleness_seconds` is machine-readable; clients needing strong bounds retry or fail explicitly.

### Retention

Retired entries (rotated-out slots, deleted entities) persist 7d after `retired_at`, configurable per-role, then are pruned. Metrics rows and the upstream cred registry delete together.

## Auth and policy

This plugin does not implement caller authentication or authorization. Operators configure OpenBao auth mounts (TLS client cert, OIDC, AppRole, etc.) and write policies that grant `read` on the relevant `cloud-creds/<cloud>/creds/<role>` paths. The plugin trusts whatever caller identity OpenBao hands it; policy is the gate.

## Prometheus metrics surface

> **Metrics require a builtin build (2026-08-22).** Everything below describes
> emitters that exist and are correct, but in the **documented deployment** — each
> plugin registered as an external plugin process — they reach nothing. `pkg/telemetry`
> emits through go-metrics' package-level globals, whose default sink is
> `BlackholeSink` until something calls `NewGlobal`; the plugin runs in its own OS
> process, `logical.BackendConfig` carries no sink, and `sdk/v2/plugin` has no metrics
> plumbing. OpenBao instruments plugins from the **core** side, around the RPC
> (`sdk/database/dbplugin/middleware.go` is the pattern), so a secrets-engine plugin
> cannot publish to `/v1/sys/metrics` at all. If these `Factory`s are compiled into a
> custom OpenBao build as builtins, core's global sink applies and the metrics work.
>
> Consequently the operator-facing signals that must work regardless — reconciler
> deletions, issuance failures, rate-limit state — are **structured log lines**, which
> do reach core over the plugin RPC. Do not write an alert against a metric named here
> without first confirming your deployment can see it. A12 in
> [`audit-2026-08-22.md`](audit-2026-08-22.md).

Emitted via OpenBao's telemetry stanza:

```
cloud_creds_upstream_expires_in_seconds{cloud, plugin, cred_id, role}
cloud_creds_upstream_state{cloud, plugin, cred_id, state="healthy|transient_failing|auth_failing|missing"}
cloud_creds_upstream_last_success_seconds_ago{cloud, plugin, cred_id}
cloud_creds_upstream_consecutive_failures{cloud, plugin, cred_id}
cloud_creds_lease_issued_total{cloud, role}
cloud_creds_lease_revoke_failures_total{cloud, role}
cloud_creds_auto_deleted_total{cloud, role, reason="rotated_grace_expired|orphan_reclaim"}
cloud_creds_orphans_found{cloud, plugin}
cloud_creds_reconcile_last_run_seconds_ago{cloud, plugin}
cloud_creds_reconcile_disabled{cloud, role}
```

Suggested alert thresholds (runbook, not enforced by plugin):
- `expires_in_seconds < 14d` → warning
- `expires_in_seconds < 3d` → critical
- `state == "auth_failing"` for >5min → critical
- Missing `cloud_creds_upstream_expires_in_seconds` for a known cred_id → warning

## Reference implementation scope (this round)

The DO reference implementation exercises every load-bearing piece of the API contract:

1. Envelope wrapping (uniform response shape).
2. Role config CRUD (`roles/<name>` paths).
3. JIT issuance + revoke (`POST/DELETE /v2/tokens`).
4. Lease tracking (`internal_data` carries upstream cred_id).
5. Per-node access metrics (in-memory + 15min flush).
6. Upstream cred registry (≥2 minters or 1 `never_expires`).
7. Recovery state machine (transient → auth_failing → recovered).
8. Reconciliation worker (orphan reclamation; bootstrap delay; dry-run; rate limit).
9. Auto-delete with tag-scheme safety boundary.
10. Prometheus metrics emission.

Native wrappers (AWS/GCP/Azure) and UpCloud are spec'd here so the API is sanity-checked against them, but their plugins ship in follow-up specs/PRs.

## Testing approach

Each plugin gets:
- **Unit tests** on storage, role config, envelope wrapping, recovery state machine, minter selection, metrics flush, reconciler safeguards. Uses `logical.TestBackendConfig` + in-memory storage.
- **Cloud-fake integration tests** — `pkg/credenvelope/fakes/` provides a mock cloud HTTP server (`httptest.Server`) with knobs for 401/403/429/500/timeout responses, expiry simulation, rate limit windows. Each plugin's tests run against its fake.
- **Cluster smoke test** — against a single-node OpenBao dev cluster: register the plugin, configure a role, issue a credential, exercise the cloud API with it, revoke, re-fetch.
- **Real-cloud integration test** — guarded by env var + build tag (`go test -tags=cloud_real`), uses real DO API with a dedicated test account. Run on demand, not in standard CI.

## Open questions / follow-ups

- UpCloud API capability for headless token creation/deletion (verify in UpCloud follow-up spec).
- OVH OAuth2 service-account API coverage (separate research task before OVH spec).
- AWS/GCP/Azure native engines: confirm tag/label/prefix configurability so the reconciliation safety boundary works.
- Operator-side auth-mount and policy provisioning (out of scope for this design — operator concern).
