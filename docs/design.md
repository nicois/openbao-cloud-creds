# OpenBao Short-Lived Cloud Credentials — Design

**Status:** Draft (2026-05-29)
**Scope of this round:** API contract + DO reference implementation

## Problem

Control-plane services and CI jobs need short-lived, role-based credentials for the cloud APIs they call (AWS, GCP, Azure, DO, UpCloud, OVH). Some clouds support short-lived tokens natively (STS, GCP impersonation, Azure SP creation); others do not. We want a single uniform OpenBao API that hides this divergence so callers don't branch per-cloud.

## Goals

1. Uniform OpenBao API: `bao read cloud-creds/<cloud>/creds/<role>` returns a credential plus a normalized envelope, regardless of cloud.
2. Honest TTL semantics: every issued lease's `expires_at` reflects the actual time the credential is valid for the caller. No lying about lifetime.
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
- DO: `scopes[]` (e.g. `read write`)
- UpCloud: `permissions` (per UpCloud's API)

### Error model

Standard OpenBao 4xx/5xx + JSON body with stable `error_code`. Codes are exported as Go constants in `pkg/credenvelope/errors.go`; adding a code is a spec change. Clients pin to `metadata.api_version`.

| Code | HTTP | Meaning | Client retry |
|------|------|---------|--------------|
| `role_not_found` | 404 | Role doesn't exist | No |
| `role_disabled` | 403 | Operator-disabled | No |
| `entity_unavailable` | 503 | Upstream entity rotating/retiring | Yes, backoff |
| `upstream_quota_exceeded` | 429 | Cloud rate limit/quota | Yes, exp backoff + jitter |
| `upstream_auth_failed` | 502 | Plugin's bootstrap creds rejected | No (operator) — plugin self-heals if transient |
| `upstream_timeout` | 504 | Upstream API didn't respond | Yes, backoff |
| `consent_required` | 501 | Cloud requires human consent (OVH legacy) | No |
| `pool_exhausted` | 503 | All slots simultaneously unavailable | Yes, short backoff |
| `lease_revoke_failed` | 500 | Couldn't revoke upstream cleanly | Operator alert |
| `internal` | 500 | Plugin bug | No |

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
  consecutive_failures: <int>
}
```

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

1. **`disable_auto_delete` per role** — emergency operator switch; halts upstream deletes for that role; metrics still emit.
2. **Dry-run mode** — `bao write cloud-creds/<cloud>/reconcile mode=dry_run` runs the worker but only logs/metrics; no deletes.
3. **Rate limit** — max 10 deletes per reconciliation pass per cloud (configurable). Worker stops + alerts if more should be deleted; operator must investigate.
4. **Bootstrap delay** — 24h after plugin start before reconciler runs (avoids "plugin upgrade with empty registry" deleting everything); configurable.
5. **Audit log** — every auto-delete writes a structured log line and emits `cloud_creds_auto_deleted_total{cloud, role, reason}`.

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
