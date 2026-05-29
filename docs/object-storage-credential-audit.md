# Object Storage Credential Audit

**Date:** 2026-05-30
**Question:** Can OpenBao serve as the source of long-lived object-storage credentials for droplet backups? Ideal target: 30-day validity, rotated every 7 days. Fallback: indefinite long-lived. Must be compatible with what Aiven services currently consume.

## TL;DR

| Cloud | Object storage | S3-compat? | API-issuable? | Native expiry? | Verdict |
|-------|---------------|-----------|---------------|----------------|---------|
| AWS | S3 | Yes | Yes (IAM access keys) | No | **Viable** — JIT/rotation, 2 keys/user |
| GCS | Cloud Storage | Yes (HMAC keys only) | Yes (`hmacKeys.create`) | No | **Viable** — HMAC keys, 5/SA |
| Azure | Blob | **No** (Azure-native) | N/A (SAS offline-signed) | Yes (SAS expiry) | **Viable but NOT S3-compatible** |
| OCI | Object Storage | Yes (Customer Secret Keys) | Yes (IAM API) | No | **Viable** — phased rotation, 2/user |
| Exoscale | SOS | Yes | Yes (`POST /api-key`) | No | **Best fit** — bucket-scopable |
| OVH | Object Storage (S3) | Yes | Yes (`s3Credentials`) | No | **Viable** — ~2/user cap |
| Vultr | Object Storage | Yes | Yes (`/v2/object-storage`) | No | **Viable but awkward** — 1 key/store, destructive rotation |
| Linode (Akamai) | Object Storage | Yes | Yes (`/object-storage/keys`) | No | **Strong fit** — bucket-scopable, NEW plugin needed |
| DigitalOcean | Spaces | Yes | **No public API** | No | **Blocked** — control-panel only |

## The Aiven Compatibility Contract (the linchpin)

Aiven services consume object-storage credentials as a **rohmu/pghoard config dict** (schema in `aiven-core/avn/schemas_pydantic_v1/object_storage_config/`). The S3 variant requires:

- `aws_access_key_id`, `aws_secret_access_key` — **the key pair**
- `aws_session_token` — **supported** (optional; used for STS-style temporary creds)
- `bucket_name`, `region`, `host`, `port`, `prefix`, `storage_type="s3"`, addressing style

**Critical findings:**

1. **The credential contract is an S3 access-key + secret pair (+ optional session token).** Not a bearer token, not a connection string. Any OpenBao plugin issuing backup creds MUST produce this shape.

2. **All S3-compatible clouds funnel through one code path** (`_prepare_pghoard_s3_config`, `storage_type="s3"` with custom `host`/`region`). DO, UpCloud, OVH, Exoscale, OCI all use this. Only **GCS** (service-account JSON) and **Azure** (account_key / sas_token) use native, non-S3 config shapes.

3. **Rotation is already supported natively.** Aiven has a live short-lived-credential refresh loop for BYOC (`aiven/acorn/storage_key_apis/`): nodes hold a `temporary_credentials_refresh_token` and POST to a refresh endpoint that does AWS `sts:AssumeRole` (12h `valid_until`, ~1h `refresh_at`) or GCS impersonation, returning `{aws_access_key_id, aws_secret_access_key, aws_session_token, valid_until, refresh_at}`. **Services tolerate rotation** by re-reading config.

4. **The long-lived requirement is real.** Non-BYOC clouds (e.g. DO) bake **static, non-expiring keys** into the node's pruned config so backups survive management-plane outages. The temporary-token path requires the management plane reachable every ~1h (breaks after 12h offline). **This is exactly the gap the 30d/7d model fills:** long enough to survive outages, short enough to limit blast radius.

### Two integration paths

- **Path A — Long-lived static keys (outage-resilient):** OpenBao issues a 30-day credential, baked into node config, rotated every 7 days by re-issuing and redeploying. Survives management-plane outages up to 30 days. This is the requested model.
- **Path B — Plug into existing refresh loop:** OpenBao becomes the backend for the `refresh-temporary-storage-credentials` endpoint. Shorter TTLs, but requires management-plane reachability. The node schema already accepts `aws_session_token`, so STS-style triplets drop in.

**Recommendation:** Path A for the 30d/7d requirement. Path B as an enhancement for clouds with native short-TTL support (AWS STS, GCS impersonation) where outage-resilience is less critical.

## Per-Cloud Detail

### AWS S3 — Viable
- **Credential:** IAM user access keys (only AWS type supporting 30-day/indefinite). STS is max 12h — too short for outage resilience.
- **API:** `iam:CreateAccessKey` / `DeleteAccessKey`. Standard SigV4, fully S3-compatible.
- **Quota:** **2 access keys per IAM user** (hard limit) → model is ~1 IAM user per droplet/role. 5,000 users/account default (raisable).
- **Rotation:** No native expiry; tracked plugin-side. 2-key cap = one in-flight rotation per user (fine for 7d cadence). Tag users `owner=cloud-creds` for reconciler safety.
- **Scoping:** Per-user IAM policy to `arn:aws:s3:::bucket/prefix/*`.

### GCS — Viable (HMAC keys)
- **Credential:** **HMAC keys** (S3-compatible). SA JSON keys are NOT S3-compatible — must use HMAC for S3 backup tooling.
- **API:** `storage.hmacKeys.create` (secret shown once) / `.delete` (must set INACTIVE first).
- **Quota:** **5 HMAC keys per service account** (binding), 100 SAs/project (raisable) → ~500 ceiling, scale via one SA per role.
- **Rotation:** No native expiry; plugin-tracked. 5/SA comfortably holds overlapping slots.
- **Scoping:** Per-SA IAM (HMAC keys inherit SA permissions), not per-key.
- **Note:** Aiven's GCS config path uses SA JSON (`credentials`), not S3/HMAC. Using HMAC would require routing GCS through the S3 config path (`storage.googleapis.com` endpoint) — verify Aiven supports this, or add HMAC support.

### Azure Blob — Viable but NOT S3-compatible
- **Credential:** **SAS tokens** — ideal technical primitive: arbitrary expiry (30d+ fine), generated **offline** (HMAC-signed with account key, no API call), unlimited (not server-stored).
- **Rotation:** 30d SAS reissued every 7d = perfect native fit. BUT: **no per-lease revocation** — only account-key rotation (invalidates ALL outstanding SAS).
- **S3 compatibility: NO.** Azure Blob uses query-string auth, not SigV4. Aiven's Azure path uses `account_key` or `sas_token` (native), so this is consistent with Aiven — but only if the backup target is Azure-native, not S3-shaped.
- **Quota:** SAS unlimited; account keys exactly 2.

### OCI Object Storage — Viable
- **Credential:** **Customer Secret Keys** (S3-compatible, against `<namespace>.compat.objectstorage.<region>.oraclecloud.com`).
- **API:** `CreateCustomerSecretKey` / `DeleteCustomerSecretKey`.
- **Quota:** **2 per IAM user** (binding) → N=2 phased rotation. **Identical machinery to the existing `credential-oci` auth-token plugin** — swap client calls only.
- **Rotation:** No native expiry; phased rotation delivers "30d validity" as continuous freshness, not a single 30d key.
- **Alternative:** Pre-Authenticated Requests (PARs) — time-limited URLs, NOT S3-credential-shaped. Fallback only.

### Exoscale SOS — Best fit
- **Credential:** IAM API keys (the same `POST /api-key` our `credential-exoscale` plugin already uses).
- **Scoping:** First-class — keys scopable to the `sos` service, even specific buckets, via IAM policy.
- **Quota:** No hard public ceiling (generous).
- **Rotation:** No native expiry; JIT or phased both work. Indefinite trivial.
- **S3:** `sos-<zone>.exo.io`. The IAM key IS the S3 key.

### OVH Object Storage — Viable
- **Credential:** S3 credentials via `POST /cloud/project/{serviceName}/user/{userId}/s3Credentials` (+ `GET .../secret`, `DELETE`). Works with existing OAuth2 service account.
- **Scoping:** Bound to a Public Cloud user (OpenStack roles), not per-bucket — coarser than Exoscale.
- **Quota:** ~2 S3 credentials per user (verify live); scale across users.
- **S3:** `s3.<region>.io.cloud.ovh.net` (verify exact form on live region).

### Vultr Object Storage — Viable but awkward
- **Credential:** One key set per subscription (`s3_access_key` / `s3_secret_key`), embedded in the subscription — **not a list**, cannot issue N keys.
- **Rotation:** `RegenerateKeys` rotates but **invalidates the prior key** — no overlap window, disruptive.
- **Verdict:** Fine for indefinite long-lived; **breaks clean 7d zero-downtime rotation**. Flag in design.
- **S3:** `<region>.vultrobjects.com`.

### Linode (Akamai) Object Storage — Strong fit, NEW plugin
- **IMPORTANT:** This is **Linode** Object Storage (techdocs.akamai.com/cloud-computing), a DIFFERENT product from the EdgeGrid CDN API our existing `credential-akamai` plugin targets. **The existing plugin cannot be reused.**
- **Credential:** `POST /object-storage/keys` (secret shown once); list/revoke via API. Supports per-bucket `bucket_access` (read_only/read_write).
- **Quota:** Soft per-account cap (raisable via support).
- **Rotation:** No native expiry; clean multi-key issuance enables true JIT and 30d/7d phased rotation.
- **S3:** `<region>.linodeobjects.com`.

### DigitalOcean Spaces — Blocked
- **Confirmed (April 2026 changelog):** Spaces access keys cannot be created via public API — control panel only. No `POST /v2/spaces/keys` public endpoint.
- **Aiven's existing use** of `POST /v2/spaces/keys` implies an undocumented/partner endpoint — no stability guarantee, unsuitable for an open-source plugin.
- **Quota:** 200 keys/account (control panel).
- **Verdict:** Deferred. Only viable via the undocumented endpoint (high risk) — would need explicit verification and ToS review.

## Cross-Cutting Findings

1. **No cloud offers native credential expiry on S3-style keys** (except Azure SAS, which isn't S3-compatible). Every plugin must drive 30d/7d rotation itself: mint-new → grace overlap → revoke-old. "Indefinite" = simply skip the revoke. This is the **phased-rotation** strategy, already built for OCI.

2. **Quota ceilings force a per-user/per-SA sharding model** on AWS (2/user), GCS (5/SA), OCI (2/user), OVH (~2/user). The plugin provisions one upstream identity (user/SA) per role and rotates keys within it. Exoscale and Linode have generous multi-key issuance — cleanest.

3. **Vultr is the rotation outlier** — single immutable key per store, destructive regeneration. No zero-downtime rotation.

4. **Two clouds aren't S3-shaped:** Azure (SAS, native) and GCS-via-SA-keys. GCS works via HMAC keys; Azure requires Azure-native backup tooling.

5. **Aiven already tolerates rotation** via the BYOC refresh loop, and the node config schema accepts `aws_session_token`. This means STS-style temporary triplets are drop-in — the integration risk is low for S3-compatible clouds.

## Recommended Strategy

A new credential type — **`object-storage` roles** — within the existing plugins, using the **phased-rotation** machinery (built for OCI). Each plugin gains:

- An object-storage role variant that provisions S3 keys instead of API tokens
- N=2 (or higher where quota allows) slots per role, rotated every 7d, each key living ~30d
- The credential envelope returns `{access_key_id, secret_access_key, [session_token], endpoint, region}` matching Aiven's S3 config contract
- Reconciler safety via owner-tag/name-prefix scheme

**Build priority (by fit):**
1. **Exoscale, Linode/Akamai** — generous multi-key, bucket-scopable, clean rotation
2. **AWS, GCS, OCI** — quota-constrained but well-understood phased rotation (OCI machinery reusable)
3. **OVH** — viable, coarser scoping, verify per-user cap
4. **Vultr** — indefinite-only realistically (no clean rotation)
5. **Azure** — only if Azure-native backup tooling is acceptable (not S3)
6. **DigitalOcean Spaces** — blocked; revisit only if the undocumented API is sanctioned

**Open items to verify on the live dev cluster:**
- Whether Aiven's GCS path can consume HMAC keys via the S3 config (vs. SA JSON)
- Exact OVH per-user S3 credential cap and S3 hostname format
- Linode and Vultr per-account key quotas
- Whether the 30d-validity requirement is satisfiable as "continuous freshness via N=2 rotation" or needs a single literal 30d key (matters for AWS/OCI 2-key clouds)
