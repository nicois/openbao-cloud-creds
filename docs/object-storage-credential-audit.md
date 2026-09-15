# Object Storage Credential Audit

**Date:** 2026-05-30 (DigitalOcean rows re-verified and corrected 2026-08-21 — see [`docs/do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md))
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
| DigitalOcean | Spaces | Yes | **Yes** (`POST /v2/spaces/keys`, `bearer_auth`, scope `spaces_key:create_credentials`; contested until 2026-09-15, now settled — see [handover](do-spaces-keys-handover.md)) | No | **Blocked for per-customer isolation** on the quota alone (200 keys / 100 buckets per account); API issuance is no longer an objection |

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

### DigitalOcean Spaces — Blocked on quota; API issuance now confirmed — **revised twice on 2026-08-21, again on 2026-09-15**

> **Revision 1 (spec pass).** This section originally read "Blocked," asserting (from the
> April 2026 changelog) that Spaces access keys could not be created via public API. DO's
> current public OpenAPI spec *does* carry a fully-specified, scope-gated **Spaces Keys**
> tag, so the section was rewritten to "Viable, quota-bounded."
>
> **Revision 2 (later the same day) — that rewrite over-read the spec, and is withdrawn.**
> Three sources disagree, and the spec is the minority:
> - DO's **product docs** say, three times, that access keys "can only be created and
>   managed through the DigitalOcean Control Panel" and "cannot currently be created,
>   edited, or deleted using the DigitalOcean API or CLI"
>   (`products/spaces/how-to/manage-access/`, `products/spaces/details/limits/`).
> - The **real-account probe** got **404** on `/v2/spaces/keys` (noted at the time as odd
>   and left unexplained — see `do-api-verification-2026-08-21.md`).
> - The **OpenAPI spec** lists the endpoints.
>
> This is the same lesson as KI-009, in the same direction: **presence in a spec is not
> permission, and absence from a spec is not absence from the API.** DO's `/v2/tokens`
> works for the control panel while being absent from the spec and fenced from PATs;
> `/v2/spaces/keys` is *in* the spec while the docs say it doesn't exist for API callers.
> On DO, credential management appears to be control-panel-only as a matter of policy for
> **both** credential types. Treat API issuance of Spaces keys as **unconfirmed** until a
> real-account probe says otherwise, and note that a 404 is consistent with either "not
> rolled out" or "entitlement-gated," which the probe did not distinguish.
>
> **Revision 3 (2026-09-15) — the API objection is cleared; Revision 2's caution was right to
> demand real-account evidence, and that evidence has now arrived from the opposite direction.**
> The Aiven management plane creates Spaces keys in production with an ordinary
> `Authorization: Bearer <PAT>` against `/v2/spaces/keys`, with unit tests pinning the create,
> list and delete requests. A running service is stronger evidence than a probe, so the spec was
> right and the product docs are stale. The 404 seen on 2026-08-21 was consistent with
> "entitlement-gated" and that is the reading that survives: an account with Spaces in use answers.
>
> Revision 2's *general* lesson still holds — presence in a spec is not permission — but its
> specific conclusion, that DO treats credential management as panel-only for **both** credential
> types, is wrong. It is panel-only for API tokens (KI-009) and API-issuable for Spaces keys, and
> the discriminator is visible in the spec: `/v2/tokens` is absent from it entirely, while
> `/v2/spaces/keys` is fully specified with `bearer_auth`.
>
> See [`docs/do-spaces-keys-handover.md`](do-spaces-keys-handover.md), which also notes why this
> matters beyond object storage: KI-009 leaves `credential-do` with no mintable credential at all,
> and a Spaces key is one.

- **Credential:** `POST /v2/spaces/keys` (secret returned once, in `key_create_response.secret_key`); list `GET /v2/spaces/keys`; get `GET /v2/spaces/keys/{access_key}`; modify `PUT`/`PATCH /v2/spaces/keys/{access_key}`; revoke `DELETE /v2/spaces/keys/{access_key}`. Tagged **Spaces Keys** in the public spec, and callable with a bearer PAT — confirmed against a production consumer, see Revision 3.
- **Scoping:** Per-bucket `grants: [{bucket, permission}]` with `read` / `readwrite` / `fullaccess`. `fullaccess` cannot be mixed with scoped grants and takes precedence if both are sent. Comparable granularity to Exoscale/Linode, better than OVH's per-user coarseness.
- **Minter privilege:** dedicated `spaces_key:{read,create_credentials,update,delete}` PAT scopes — so a Spaces minter can be genuinely least-privilege (unlike the `credential-do` PAT minter, whose token-creation capability is unscopable).
- **Native expiry:** None — consistent with cross-cutting finding #1; the plugin would own the TTL via JIT revoke or phased rotation.
- **Safety boundary:** settable `name` (so the `cloud-creds-<role>-` owner-prefix scheme works) and a returned `created_at` (so the reconciler's `ConfirmationHold` age check is satisfiable — cf. F1 in `docs/state-assumption-verification-2026-05-31.md`, where missing create timestamps forced Exoscale/Vultr fail-closed).
- **Quota:** 200 access keys **and 100 buckets** per *account* (both raisable via support; documented at `products/spaces/details/limits/`). The cap is **per account, not per team** — and buckets cannot be moved between accounts, so team sharding is not a lever for an existing estate. Per-customer isolation is therefore bounded by the *bucket* cap before the key cap, and both are orders of magnitude short of ~100k services.
- **Availability, not just quota — the disqualifier for the driving use case.** The requirement behind Path A is that *customer workloads keep reading their backups through an OpenBao outage*. Renewal is what needs OpenBao reachable, so a credential whose lifetime is shorter than the worst-case outage window cannot serve an availability-critical path at all. That rules out JIT for backup access on **every** cloud, independent of DO's quota: the only shapes that satisfy it are phased rotation (credential valid until its slot's next scheduled rotation, so an outage defers rotation rather than invalidating access — the OCI strategy) or credentials this repo does not manage at all. Rotation IS available on DO now that API management is confirmed (Revision 3), so unlike the earlier reading it is the quota rather than the API that bounds this.
- **Verdict:** Blocked for the *driving* use case — per-customer isolation at ~100k services — on the quota (100 buckets binding before 200 keys) and on the availability requirement, which rules out short-lived issuance on every cloud. The API objection is **cleared** (Revision 3). Object storage as a whole remains out of scope for this repo (see below). But note the narrower case that is not blocked at all: a handful of operational keys for the management plane, which is what [`docs/do-spaces-keys-handover.md`](do-spaces-keys-handover.md) is about.

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
6. **DigitalOcean Spaces** — ~~blocked; revisit only if the undocumented API is sanctioned~~ **(2026-08-21: the API is now public and per-bucket-scopable — ranks alongside Exoscale/Linode on fit for JIT/short-lived, but the 200-keys/account cap keeps it out for long-lived per-customer isolation)**

**Open items to verify on the live dev cluster:**
- Whether Aiven's GCS path can consume HMAC keys via the S3 config (vs. SA JSON)
- Exact OVH per-user S3 credential cap and S3 hostname format
- Linode and Vultr per-account key quotas
- Whether the 30d-validity requirement is satisfiable as "continuous freshness via N=2 rotation" or needs a single literal 30d key (matters for AWS/OCI 2-key clouds)
