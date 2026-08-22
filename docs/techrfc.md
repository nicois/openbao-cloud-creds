# OpenBao Short-Lived Cloud Credentials — TECHRFC

> **⚠️ IMPLEMENTATION STATUS (2026-05-30, addendum 2026-06-01):** This RFC was written before implementation and is partly superseded. All ten plugins (DO, AWS, GCP, Azure, OVH, UpCloud, Exoscale, Vultr, Akamai, OCI) are now built and tested. Two things in this document are STALE: (1) the **native-engine-wrapper strategy** for AWS/GCP/Azure was abandoned — OpenBao has no GCP/Azure secrets engine and only partial AWS support, so those clouds use full JIT plugins calling cloud APIs directly; (2) the **per-plugin "Spec'd / follow-up RFC / Deferred" status** is obsolete — everything is implemented. The **response-envelope shape and error-code model below remain authoritative.** **Additions beyond this RFC (2026-06-01, audit-2):** all five upstream-failure `error_code`s are now emitted at the issue path (not collapsed to `internal`); per-minter observability (`cloud_creds_minter_age_seconds` for every minter incl. `never_expires`, plus a configurable near-expiry warn-log); and **operator-initiated minter self-rotation** via `cloud-creds/<cloud>/minter-sets/<name>/rotate` (extends OBC-007's rotated-out-credential grace model to minters — mint-capable successor → grace-based retirement → swept after `minter_retire_grace`; implemented for Azure/UpCloud/AWS/Akamai/GCP/Exoscale, rejected as unsupported for DO/OVH/Vultr/OCI). See `CLAUDE.md`, `docs/cloud-credential-research.md`, and `docs/decisions.md` for current strategy-per-cloud and the rotation feasibility findings. **Envelope bumped to api_version `"4"` (2026-08-23):** `metadata.credential_kind` names the shape of the `credential` block and is pinnable on a read; see the envelope row below. It is intended to be the last breaking envelope change of this sort — once a client can state the shape it parses, a new shape is additive. **Envelope bumped to api_version `"3"` (2026-08-22, A28):** `metadata.scope_kind` was added because `metadata.scope` was a single field name carrying ten different meanings, and OVH's `scope` changed from the literal `"all"` to empty with `scope_kind: "account"` — an absence stated as an absence. The `/reconcile` response also became ONE schema across all ten plugins (`mode, dry_run, target, scanned, found, deleted, remaining, delete_errors, hit_limit, confirmation_hold`), with the genuine per-cloud difference moved into the `target` field. **Further correction (2026-08-21):** the DO row below describes `POST /v2/tokens` / `DELETE /v2/tokens/{id}` as though they were public API — they are **not** in DigitalOcean's public OpenAPI spec (PAT creation is documented as control-panel-only), so the reference plugin depends on a control-panel-internal endpoint; and DO's scopes are fine-grained `<resource>:<verb>` (e.g. `droplet:create`), not coarse `read`/`write`. See [`docs/do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md). **OBC-002 (honest TTLs) clarified 2026-08-21:** the requirement holds in the direction it states — no lease's TTL exceeds the credential's remaining validity — and is now enforced by rejecting role TTLs a cloud cannot honour (OVH exactly 3600s, AWS 900–43200s, GCP ≤43200s, UpCloud ≤8760h) and by refusing renewal wherever the credential's expiry is fixed at mint (previously Azure and UpCloud renewals could outlive their credential). The RFC does not say anything about the converse direction — a credential outliving its lease — which is closed by hard revoke on DO/Exoscale/Vultr/Akamai (plus the owner-tag reconciler as backstop, since those credentials have no native expiry) and left deliberately open, bounded by the rotation period, on OCI. Full matrix: [`docs/ttl-semantics.md`](ttl-semantics.md). **Addition beyond this RFC (2026-08-21):** minter **capability verification** — a throwaway probe mint (real per-role mint shape, then deleted) gates minter-set writes, role writes and rotation commits on all ten plugins, gated by the config field `verify_minter_capability` (default true; OCI exempt). It adds **no new `error_code` and does not touch the envelope** — probe failures are configuration-time error responses on the write that triggered them, never credential-read responses, so `api_version` was unaffected by it. A distinct runtime `minter_insufficient_privilege` code was considered and deliberately **not** added, precisely because it would be a change to the error-code model below. See [`docs/minter-capability-verification.md`](minter-capability-verification.md).

| Author(s) | Nick Farrell |
| :---- | :---- |
| **Status** | draft (partly superseded — see banner above) |
| **Creation Date** | 2026-05-29 |
| **Updates** | 2026-05-30 — implementation status banner added |
| **Updated By** | — |
| **History** | 2026-05-29 — Initial revision |

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

# Summary

Control-plane services and CI jobs need short-lived, role-based credentials for the cloud APIs they call (AWS, GCP, Azure, DigitalOcean, UpCloud, OVH). Some clouds support short-lived tokens natively (AWS STS, GCP impersonation, Azure dynamic SP); others do not. This RFC proposes a uniform OpenBao API that issues credentials in a single envelope shape regardless of cloud, hiding the per-cloud divergence behind one of two strategies — JIT (per-request creation) or phased rotation (N pre-provisioned slots rotated on schedule with phase offsets). Every issued lease's TTL is honest. Steady-state rotation is fully headless. Auto-deletion of expired credentials is in scope, gated by an owner-tagged scheme that bounds the blast radius.

The deliverable for this RFC's first round is the API contract plus a reference implementation for DigitalOcean (the chosen exemplar of a non-native cloud). Native-engine wrappers (AWS/GCP/Azure) and the UpCloud plugin are spec'd for sanity-checking but ship in follow-up RFCs.

# Assumptions

| ID | Description |
| :---- | :---- |
| ASM-001 | OpenBao 2.5+ is deployed and reachable from the calling services. Multi-cloud raft topologies are supported but not required. |
| ASM-002 | Operators configure OpenBao auth mounts and policies separately; the plugin trusts the caller identity OpenBao hands it. |
| ASM-003 | One-time human action is acceptable for bootstrap (e.g., minting the initial DO PAT, registering the AWS bootstrap user). Steady-state rotation MUST be headless. |
| ASM-004 | Operators have the IAM/permission grants required to create the bootstrap credentials each cloud needs. Where they do not, the affected cloud either falls back to a native engine that doesn't require those grants, or is deferred. |
| ASM-005 | OpenBao plugins can emit Prometheus metrics via the existing telemetry stanza; no new metrics infrastructure is required. |

# Constraints

| ID | Description |
| :---- | :---- |
| CON-001 | Some clouds have no native short-TTL primitive (DigitalOcean, UpCloud, OVH). The API MUST present uniform short-TTL semantics regardless. |
| CON-002 | OVH consumer-key issuance (legacy auth mechanism) requires a human to approve a `validationUrl`. No fully-headless flow exists for that path. OVH support is therefore deferred until OAuth2 service-account coverage is verified for the OVH APIs in scope. |
| CON-003 | OpenBao plugin storage writes go through raft consensus; in multi-cloud topologies this can be ~50–200ms per write. Per-read storage writes are too expensive for hot-path metrics. |
| CON-004 | Cloud APIs vary widely in rate limits, idempotency guarantees, and revocation semantics. The plugin design MUST tolerate transient upstream failures without leaking state. |
| CON-005 | Cloud quotas (token counts, IAM entity counts, API key counts) are finite. Expired credentials MUST be reclaimed; otherwise quotas fill silently and operations are blocked at exactly the wrong moment. |
| CON-006 | OpenBao's audit log records every credential read; this is the authoritative per-access record. Plugin-side metrics are aggregate only. |

# Requirements

| ID | Requirement | Acceptance Criteria | Satisfied By |
| :---- | :---- | :---- | :---- |
| OBC-001 | Uniform credential API across clouds. | A client calling `bao read cloud-creds/<cloud>/creds/<role>` SHALL receive a response in the envelope shape defined in [Required API], regardless of cloud. The `credential` block MAY differ per cloud; the envelope fields (`cloud`, `role`, `expires_at`, `ttl_seconds`, `renewable`, `credential_id`, `metadata`) SHALL be present and identically named for every cloud. | DO reference impl + native wrappers (follow-up) |
| OBC-002 | Honest TTLs. | The `expires_at` field on every issued lease SHALL reflect the time at which the underlying credential ceases to be valid for the issued caller. No cloud's strategy may produce a TTL longer than the credential's actual remaining validity. | Phased-rotation algorithm; JIT direct mapping; role-TTL bounds + non-renewability where the credential's expiry is fixed at mint (see [`ttl-semantics.md`](ttl-semantics.md)) |
| OBC-003 | Headless steady-state rotation. | Once bootstrapped, no human action SHALL be required for routine rotation of any credential the plugin issues or relies on. Bootstrap MAY require a one-time human action. | Recovery + rotator workers in DO reference impl |
| OBC-004 | Resilience to upstream transient failures. | A 401/403/429/5xx response from an upstream cloud API SHALL NOT cause the plugin to enter a stuck state. The plugin SHALL retry transient errors inline with exponential backoff, and SHALL self-heal from sustained auth failures once upstream recovers, without operator action. | Recovery state machine |
| OBC-005 | Mandatory expiry tracking on minting credentials. | Every minter (the long-lived credential the plugin uses to call the cloud API) SHALL have a recorded `expires_at`, sourced from the cloud API where possible, or explicitly marked `never_expires=true`. Configurations with implicit infinite expiry SHALL be rejected at config-load time. | Config validator |
| OBC-006 | Multiple minters with phased expiry. | A minter set SHALL be valid iff (a) it contains at least one `never_expires=true` minter, OR (b) it contains ≥2 minters with `expires_at` and pairwise expiry separation ≥ 7 days. Otherwise the configuration SHALL be rejected. | Config validator |
| OBC-007 | Auto-deletion of expired or rotated-out credentials. | The plugin SHALL automatically delete (a) per-lease JIT credentials on lease revoke/expiry, (b) rotated-out phased-rotation slot credentials after a 7-day grace from `retired_at`, and (c) orphaned plugin-tagged upstream entities matching no known lease, after a 1h confirmation hold. The reconciler SHALL NOT delete operator-provided minters or long-lived target entities (IAM roles, parent SAs, parent apps). | Reconciliation worker |
| OBC-008 | Tag-scheme safety boundary for auto-deletion. | The reconciler SHALL only consider for deletion upstream entities matching the owner-tagged/prefix scheme set by the plugin at creation time. Untagged entities SHALL NOT be touched under any circumstance. | Per-cloud tagger |
| OBC-009 | Per-entity access metrics with eventual consistency. | The plugin SHALL record `last_access_at` per (cloud entity, role, node) tuple, flushed to plugin storage every 15min (configurable). The query API SHALL return merged values across nodes with a machine-readable `staleness_seconds` field. Metrics SHALL count both initial issuance and lease renewals as access events. | Metrics flusher |
| OBC-010 | Prometheus visibility. | The plugin SHALL emit metrics for upstream credential expiry, recovery state, lease issuance/revoke counts, auto-delete counts, orphan detections, and reconciler health, with labels enabling per-cloud and per-role aggregation. | Telemetry emitter |
| OBC-011 | DigitalOcean reference implementation. | A `credential-do` plugin satisfying OBC-001 through OBC-010 SHALL be deployable to the multi-cloud spike cluster and pass the cluster smoke test (issue → exercise → revoke → re-issue). | `plugins/credential-do/` |

# High Level Design

## Component decomposition

```
plugins/
  credential-aws/        # native wrapper over OpenBao aws engine     (follow-up RFC)
  credential-gcp/        # native wrapper over OpenBao gcp engine     (follow-up RFC)
  credential-azure/      # native wrapper over OpenBao azure engine   (follow-up RFC)
  credential-do/         # JIT — REFERENCE IMPLEMENTATION
  credential-upcloud/    # phased rotation                            (follow-up RFC)
  pkg/
    credenvelope/        # envelope types, error codes, lease tag helpers
    cloudconfig/         # config/<cloud>, roles/<name> CRUD boilerplate
    rotator/             # phased-rotation slot manager
    recovery/            # upstream recovery state machine
    metrics/             # per-node access metrics + Prometheus emission
    reconciler/          # auto-deletion / orphan reclamation worker
```

One OpenBao plugin per cloud, registered as the appropriate backend type (auth or secret). Each plugin is a small Go binary linking only its own cloud's SDK. Shared logic lives in `pkg/`; plugins import the relevant subpackages so they cannot drift on contract.

## Strategy selection per cloud

Two underlying strategies. Choice per cloud depends on whether the cloud API supports headless per-request token creation.

| Cloud | Strategy | Honest TTL? | Notes |
|-------|----------|-------------|-------|
| AWS | Native (STS) | Yes | Thin envelope wrapper over OpenBao `aws` engine |
| GCP | Native (impersonation) | Yes | Wrapper over OpenBao `gcp` engine |
| Azure | Native (dynamic SP) | Yes | Wrapper; SP creation slow (~10s); document |
| DO | JIT | Yes | `POST /v2/tokens` mints; revoke `DELETE /v2/tokens/{id}`. **Reference impl this round.** |
| UpCloud | Phased rotation (default N=2, T=7d) | Yes (≥ T/2) | Follow-up. If UpCloud's API supports JIT cleanly, MAY switch to JIT; envelope unchanged |
| OVH | Deferred | n/a | See CON-002 |

### JIT (e.g. DigitalOcean)

The plugin holds a small set of long-lived "minter" credentials. On a credential request the read handler calls the upstream cloud API to mint a new scoped credential, stashes the upstream ID in OpenBao's lease `internal_data`, and returns the credential in the envelope. On lease expiry/revoke, OpenBao calls the plugin's revoke handler, which calls the upstream API to delete the minted credential. Hard revoke.

### Phased rotation (e.g. UpCloud)

The plugin pre-provisions N upstream credential slots per role, each with an upstream credential and a `rotated_at` timestamp. A background rotator replaces one slot at a time, spaced T/N apart, so slot ages stagger across [0, T) at all times. The read handler hands out the freshest slot; the lease's `expires_at` equals that slot's next-rotation time, so the TTL never lies. Revoke is best-effort: the lease is forgotten in OpenBao, but the upstream credential lives until its scheduled rotation. An emergency-rotate endpoint forces immediate replacement of one slot for incident response.

## Recovery state machine

Each minter and slot transitions through:

- `healthy` — calls succeed
- `transient_failing` — recent error; plugin retries inline (exp backoff, ~5s budget)
- `auth_failing` — sustained 401/403 >30s; plugin emits `upstream_auth_failed` to clients AND fires alarm metrics. Background health-check every 5min.
- `recovered` (→ `healthy`) — automatic transition when health-check succeeds. **No operator action required.**

If multiple minters are healthy, traffic is steered to them. If all minters are `auth_failing`, new reads return `upstream_auth_failed`; in-flight leases issued earlier remain valid client-side until their own TTL.

## Auto-deletion with tag-scheme safety boundary

The plugin tags every upstream entity it creates with an project-owned scheme:

| Cloud | Scheme |
|-------|--------|
| AWS | Tags `Owner=cloud-creds, ManagedBy=<plugin>, RoleName=<role>` where supported; `cloud-creds-` name prefix where tags aren't allowed |
| GCP | SA emails prefixed `cloud-creds-`; labels `owner=cloud-creds` |
| DO | Token names prefixed `cloud-creds-<role>-<lease_id>` |
| UpCloud | Name prefix as scope permits |

A reconciliation worker runs every 6h (configurable, with a 24h bootstrap delay after plugin start). It lists upstream entities matching the owner-tag scheme, compares against `upstream_creds/` registry + active leases, and:

- Deletes orphaned tagged entities (no plugin-side reference) after a 1h confirmation hold
- Deletes rotated-out slot creds 7d after `retired_at`
- Marks registry entries whose upstream entity disappeared as `state=missing` (alarmed; not auto-recreated)

Untagged upstream entities are never considered. This is the load-bearing safety invariant.

Safeguards: per-role `disable_auto_delete` switch, dry-run mode, max 10 deletes per pass per cloud, 24h bootstrap delay, audit logging.

## Per-node access metrics

Each plugin instance accumulates access events in memory and flushes to a per-node-tagged location in plugin storage every 15min. Each node owns its own keyspace, so writes are conflict-free. Reads merge across nodes and report a `staleness_seconds` value. Metrics are keyed on the cloud entity (IAM role ARN, SA email, minter PAT, slot token ID — whichever an operator might want to delete) rather than the OpenBao role name, because the same entity can back multiple roles. Both initial issuance and lease renewals count as access events. Retired entries persist 7d after `retired_at` then are pruned alongside the upstream cred registry.

# Detailed Design

## API surface

| Path | Operation | Purpose |
| :---- | :---- | :---- |
| `cloud-creds/<cloud>/config` | write | Configure plugin: operational + cloud settings (`flush_interval`, `reconcile_cadence`, `minter_expiry_warn`, `minter_retire_grace`, `verify_minter_capability`, region/endpoints). **Minters are NOT configured here** — see minter-sets. |
| `cloud-creds/<cloud>/minter-sets/<name>` | write/read/delete/list | CRUD on named minter sets. Each set independently validated by the OBC-006 rule (over active, non-retired minters). Roles bind to a set. |
| `cloud-creds/<cloud>/minter-sets/<name>/rotate` | write | Operator-initiated minter self-rotation (`minter_id=<id>`). Mints a mint-capable successor, health-checks it, capability-probes it against every role bound to the set, swaps it in, and marks the old minter retired (deleted by the sweep after `minter_retire_grace`). Implemented for Azure/UpCloud/AWS/Akamai/GCP/Exoscale; DO/OVH/Vultr/OCI reject (API cannot mint a mint-capable successor). |
| `cloud-creds/<cloud>/roles/<name>` | write/read/delete/list | CRUD on credential roles. Each role has a **required** `minter_set` field naming the set it mints from. |
| `cloud-creds/<cloud>/creds/<role>` | read | Issue a credential lease |
| `cloud-creds/<cloud>/rotate-slot/<role>/<slot_id>` | write | Force immediate rotation (phased-rotation only) |
| `cloud-creds/<cloud>/reconcile` | write | Trigger reconciliation; supports `mode=dry_run` |
| `cloud-creds/<cloud>/metrics/entity/<entity_id>` | read | Query access metrics for one entity |

> **Removed 2026-08-22 (A23).** The access-metrics endpoints (`metrics/entity`, `metrics/stale`) and the `flush_interval` config field are **gone**, along with `pkg/metrics` and `pkg/metricspath`. Their whole purpose was deciding whether an upstream entity was still in use before deleting it — and a minting credential handed to this plugin is not used anywhere else, so it can be rotated and deleted without that check. What an escalation actually needs is the identifier the *cloud* knows: minter metrics and the near-expiry warning now carry `cloud_key_id`. See [`audit-2026-08-22.md`](audit-2026-08-22.md) A23.

| `cloud-creds/<cloud>/metrics/stale` | list | List entities not accessed within `older_than` |

## Storage layouts

```
config                                                 # plugin config blob
roles/<name>                                           # role definitions
upstream_creds/<cloud>/<cred_id>                       # minter + slot registry (state, expiry)
metrics/<cloud>/<entity_id>/<node_id>                  # per-node flushed access counters
slots/<role>/<slot_id>                                 # phased-rotation slot state (where applicable)
```

## Recovery state machine — detailed transitions

```
[healthy] --error--> [transient_failing]
[transient_failing] --(success)--> [healthy]
[transient_failing] --(401/403 sustained >30s)--> [auth_failing]
[transient_failing] --(retries exhausted, non-auth error)--> [healthy]   # back off, retry next request
[auth_failing] --(background health-check succeeds)--> [healthy]
[*] --(upstream entity disappears)--> [missing]
```

# Required API

The OpenBao plugin endpoints are intended for internal control-plane services and CI jobs authenticated to OpenBao, not for direct end-customer use.

The following requirements apply unless specific deviations are called out:

| ID | Description |
| :---- | :---- |
| API-001 | Plugin paths follow OpenBao conventions (`cloud-creds/<cloud>/<resource>`). |
| API-002 | All error responses include `error_code` (stable, exported as Go constants in `pkg/credenvelope/errors.go`), on **every** path — credential reads, revoke, and the config / role / minter-set / reconcile / rotate write paths. Enforced by the build: `logical.ErrorResponse` is forbidden outside `pkg/credenvelope` (`forbidigo` in `.golangci.yml`), and the only alternative takes an `ErrorCode` as its first argument. **The vocabulary is additive and `api_version` does not version it** — an error response carries no envelope, so `metadata.api_version` (which lives only inside one) is absent from exactly the responses a code appears in. Clients MUST therefore treat an unrecognised code as `internal`; new codes ship in a documented spec revision without a version bump, while removing or redefining one is breaking and does need a bump. A code is added only if a client would **act** differently. |
| API-003 | All List operations return arrays without pagination at this stage (per-cloud entity counts are in the hundreds, not thousands). Pagination MAY be added in a follow-up RFC if any role's entity count grows. |

| ID | Description |
| :---- | :---- |
| API-004 | [Issue a credential lease](#issue-a-credential-lease) — Issue a short-lived credential for a configured role |
| API-005 | [Configure a role](#configure-a-role) — Create or update a credential role |
| API-006 | [Query entity access metrics](#query-entity-access-metrics) — Query last-access information for a cloud entity |

### Issue a credential lease {#issue-a-credential-lease}

Returns a short-lived credential plus a uniform envelope so clients dispatch on `cloud` for cloud-specific keys.

| Endpoint | GET /v1/cloud-creds/<cloud>/creds/<role> |
| :---- | :---- |
| **Request** | Empty. There MUST be no body included in the request. |
| **Responses** | On success: `200 OK` with body `{"data": <envelope>, "lease_id": ..., "lease_duration": ..., "renewable": ...}` (OpenBao standard wrapping). The envelope shape is shown below. On failure: `404 NOT FOUND` if the role does not exist (`error_code=role_not_found`); `403 FORBIDDEN` if the role is operator-disabled (`role_disabled`); `502 BAD GATEWAY` if all minters are auth-failing (`upstream_auth_failed`); `503 SERVICE UNAVAILABLE` if upstream is rate-limiting (`upstream_quota_exceeded`) or all phased-rotation slots are simultaneously unavailable (`pool_exhausted`); `504 GATEWAY TIMEOUT` if the upstream API does not respond (`upstream_timeout`); `400 BAD REQUEST` if the caller pinned a `credential_kind` this role does not serve (`credential_kind_unsupported`); `500 INTERNAL` for plugin bugs (`internal`). |
| **Additional Details** | Envelope shape: `{"cloud": str, "role": str, "credential": <cloud-specific>, "expires_at": iso8601, "ttl_seconds": int, "renewable": bool, "credential_id": str, "metadata": {"scope": str, "scope_kind": str, "credential_kind": str, "issued_by": str, "api_version": "4", "minter_set": str, "minter_id": str}}`. `metadata.minter_set` and `metadata.minter_id` identify the minting credential that issued this credential, for audit provenance (added in api_version 2). **`metadata.scope_kind` (added in api_version 3)** says how to read `metadata.scope`, from a closed vocabulary — `scopes` (a permission-scope list: DO, Akamai), `acl` (coarse categories: Vultr), `role` (an upstream role whose permissions the credential assumes: AWS's IAM role ARN, Exoscale's role id), `identity` (the principal whose credential this is: GCP service account, Azure app registration, OCI user), `account` (no per-credential scoping at all — `scope` is then EMPTY: UpCloud, OVH). Before v3, `scope` was one field name carrying all of those meanings with nothing to distinguish them, so a client had to hard-code an interpretation per cloud (A28). **`metadata.credential_kind` (added in api_version 4)** names the SHAPE of the `credential` block — `sigv4_session`, `oauth2_bearer`, `basic_auth`, `bearer_token`, `scoped_token`, `key_secret`, `azure_client_secret`, `edgegrid`, `oci_auth_token` — and a caller may **pin** it by passing `credential_kind=<kind>` on a credential read. A mismatch is refused with `credential_kind_unsupported` before anything is loaded or minted, rather than returning a payload the caller cannot parse. This is what makes a NEW shape additive: a cloud can grow a second one (AWS SES over SMTP needs `{username, password}` derived from a static key, because SMTP has nowhere to put a session token) and an older client keeps getting the shape it asked for, or an actionable error. A kind names a payload rather than a cloud, so two clouds emitting identical keys share one — GCP and OVH are both `oauth2_bearer` — and that is enforced by a conformance test over the registry, not merely intended. **Per-cloud `credential` schemas — all ten, and asserted exactly by the conformance `lease` category** (`Harness.CredentialKeys`, so this table cannot drift from the code again): AWS `{access_key_id, secret_access_key, session_token}`; GCP `{access_token, token_type}`; Azure `{client_id, client_secret, tenant_id}` plus `subscription_id` when the role names one; DO `{token, scopes[]}`; UpCloud `{username, password}`; OVH `{access_token, token_type}`; Exoscale `{key, secret}` — **both halves; the secret is returned only at creation and was previously dropped**; Vultr `{api_key}`; Akamai `{client_token, access_token, client_secret, host}`; OCI `{auth_token, user_id}`. |

### Configure a role {#configure-a-role}

Creates or updates a role definition. Role fields are per-cloud; common fields include `default_ttl`, `max_ttl`, and the required `minter_set`.

| Endpoint | POST /v1/cloud-creds/<cloud>/roles/<name> |
| :---- | :---- |
| **Request** | JSON body with `minter_set` (REQUIRED — name of the minter set this role mints from), `default_ttl` and `max_ttl`, and cloud-specific fields. **TTL defaults are uniform: `default_ttl` 15m, `max_ttl` 1h**, on every cloud that can honour them — only OVH (a fixed 1h token, so exactly 3600 either way) and OCI (lease TTL derived from the rotation period) differ, and both are forced by the cloud. **Every cloud's privilege field is REQUIRED**, because "no opinion about privilege" must not silently mean "all of it": AWS `iam_role_arn` (+ optional `policy_arns[]`, `inline_policy`); GCP `service_account_email` + `scopes[]`; Azure `client_id` + `app_object_id` (+ optional `subscription_id`); DO `scopes[]`; Exoscale `role_id`; Vultr `acls[]` (+ `email_domain`); Akamai `api_access` (+ `group_id`); OCI `user_ocid`. UpCloud has none — its token API takes no scope, ACL or role parameter, and the `scopes` field it used to accept was never sent (A29). **A list-valued field is a list everywhere** (`framework.TypeCommaStringSlice`: accepts a JSON array or a comma string, reads back as a list); `scopes` used to be a slice on GCP and a bare string elsewhere. |
| **Responses** | On success: `200 OK` with the stored role definition in the body. On failure: `400 BAD REQUEST` for invalid field values, a missing `minter_set`, or a `minter_set` that does not exist; `403 FORBIDDEN` if the caller's policy does not permit role configuration. |
| **Additional Details** | `minter_set` MUST name an existing set (write fails otherwise). The role mints only from that set; there is no cross-set failover at issuance (it is the isolation boundary). `default_ttl` MUST be ≤ `max_ttl`. For phased-rotation clouds, `default_ttl` MUST be ≤ `T/N` (the minimum slot freshness), or the plugin returns `400 BAD REQUEST`. |

### Query entity access metrics {#query-entity-access-metrics}

Returns last-access information for a specific cloud entity, merged across plugin instances.

| Endpoint | GET /v1/cloud-creds/<cloud>/metrics/entity/<entity_id> |
| :---- | :---- |
| **Request** | Empty. |
| **Responses** | On success: `200 OK` with body `{"last_access_at": iso8601, "access_count": int, "staleness_seconds": int, "source": "merged_with_local_active" \| "merged_only"}`. On failure: `404 NOT FOUND` if no metric records exist for `entity_id` (treated as "never accessed via this plugin"). |
| **Additional Details** | `staleness_seconds` reports time since the most recent flush across all plugin nodes. Default `flush_interval` is 15 minutes; clients needing a tighter bound MUST tune the plugin config or accept the staleness. List variant `GET /v1/cloud-creds/<cloud>/metrics/stale?older_than=7d` returns entities sorted by staleness (ascending freshness). |

# Risks

| ID | Description |
| :---- | :---- |
| RSK-001 | **Reconciler deletes a credential being legitimately used out-of-band.** Driver: an operator creates a plugin-tagged entity manually (e.g. for debugging) and the reconciler treats it as orphaned. Consequence: the entity is deleted; the operator's session breaks. Impact: minor operator inconvenience; mitigated by 24h bootstrap delay, 1h confirmation hold, dry-run mode, and the rate-limiting safeguard. |
| RSK-002 | **Tag-scheme misconfiguration on native engines.** Driver: the OpenBao `aws`/`gcp`/`azure` engines must be configured to apply the owner-tag scheme to anything they create; if misconfigured, untagged entities are created and never reclaimed. Consequence: cloud quota fills with untagged abandoned entities. Impact: moderate; mitigated by per-cloud verification task in OBC-008 acceptance, plus Prometheus metric on creation-tag coverage. |
| RSK-003 | **Phased-rotation pool exhaustion under load.** Driver: simultaneous incidents requiring emergency-rotate of all N slots leave a window where no slot is healthy. Consequence: clients receive `pool_exhausted`; outage window equal to upstream rotation latency (typically seconds). Impact: small; clients retry with backoff; documented in error model. |
| RSK-004 | **OVH OAuth2 coverage turns out insufficient.** Driver: research finds that the OVH APIs in scope don't accept OAuth2 service-account tokens. Consequence: OVH cannot ship without headless-browser automation, which is a substantial new component (sidecar process, browser binary, UI-scrape stability concerns). Impact: OVH support delayed by weeks/months; tracked as separate RFC. |
| RSK-005 | **Operator forgets to provide `expires_at` for AWS minters and ships with `never_expires=true`.** Driver: operator chooses the "lazy" path. Consequence: AWS minters never rotate; quietly long-lived. Impact: silent risk decay; mitigated by Prometheus alert on `expires_in_seconds < 14d` (does not fire for `never_expires`, but operator review during onboarding is part of the runbook). |
| RSK-006 | **Per-node metrics flush fails persistently.** Driver: raft is unreachable for a flushing node. Consequence: in-memory metrics grow unbounded; `last_access_at` reports become stale. Impact: bounded by lease eviction (in-memory map evicts when lease ends); worst case, one node's contribution is lost until raft recovers. |
| RSK-007 | **`upstream_auth_failed` masks a real auth issue because the plugin self-heals during a transient flap.** Driver: auth_failing → healthy transition happens between operator alarms, so the operator never sees a sustained signal. Consequence: a real degradation is invisible. Impact: low; the Prometheus state metric still records the transition; alerts can include a "flap detection" rule (state changed N times in M minutes). |

# Open Questions

| ID | Description |
| :---- | :---- |
| QN-001 | Does the AWS OpenBao secret engine support custom session tags so the auto-deletion safety boundary works? Verification needed before AWS wrapper RFC. |
| QN-002 | Does the GCP OpenBao secret engine apply labels to impersonation sessions or short-lived SA keys? Same verification need. |
| QN-003 | Does Azure's dynamic SP engine apply tags to SP creations? Same. |
| QN-004 | Does UpCloud's API support headless per-request token creation? If yes, UpCloud SHOULD switch to JIT; if no, phased-rotation is correct. Verification before the UpCloud follow-up RFC. |
| QN-005 | What level of OVH OAuth2 service-account coverage exists today for the OVH APIs in scope (cloud project, dedicated cloud, etc.)? Determines whether OVH ships via OAuth2 or requires browser automation. |
| QN-006 | Is the chosen 7d retention for retired metrics rows operator-acceptable, or do auditors require longer retention? |
| QN-007 | Should the reconciler's `disable_auto_delete` switch be per-role (current proposal) or also offer a per-cloud kill-switch for incident response? |

# Potential Future Work

| ID | Description |
| :---- | :---- |
| FW-001 | UpCloud `credential-upcloud` plugin (depends on QN-004 outcome). |
| FW-002 | Native-engine wrapper plugins for AWS, GCP, Azure (each depends on the corresponding QN-001/2/3). |
| FW-003 | OVH `credential-ovh` plugin (depends on QN-005 outcome; may require headless-browser-automation sub-RFC). |
| FW-004 | End-customer / BYOC credential flows (assumption of a customer-owned cloud account). |
| FW-005 | Cloud-side usage tracking (ingest cloud audit logs to attribute "the credential was *used* against the cloud" vs. just "issued"). Currently only OpenBao-side issuance/renewal is tracked. |
| FW-006 | Pagination for `metrics/stale` list endpoint if any cloud's entity count grows beyond ~hundreds. |
| FW-007 | Token-format translation / proxy mode for cloud APIs that don't accept caller-side credentials directly (currently out of scope). |

# Reviewers

The following individuals have reviewed this RFC and indicated their support (✅), opposition (❌), or neutrality (➖). The reviewer SHOULD provide a reason for their decision when the reviewer is not in support of the RFC.

| Reviewer | Decision | Reason (optional) |
| :---- | :---- | :---- |
|  |  |  |

# External Links

[BCP14] - https://www.rfc-editor.org/info/bcp14
[RFC2119] - https://datatracker.ietf.org/doc/html/rfc2119/
[RFC8174] - https://datatracker.ietf.org/doc/html/rfc8174/
[OpenBao] - https://openbao.org/
[Design spec (companion)] - `docs/design.md`
