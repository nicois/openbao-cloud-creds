# Cloud Credential API Research

**Date:** 2026-05-29
**Purpose:** Determine JIT feasibility, scoping model, and strategy per cloud for the OpenBao credential plugin.

## Summary Table

| Cloud | Strategy | Create API | Delete API | Native TTL | Scoping | Safety Boundary | Status |
|-------|----------|-----------|-----------|-----------|---------|-----------------|--------|
| DigitalOcean | JIT | `POST /v2/tokens` | `DELETE /v2/tokens/{id}` | No | Scope strings (coarse) | Name prefix `cloud-creds-` | **Done** (reference impl) |
| UpCloud | JIT | `POST /1.3/account/tokens` | `DELETE /1.3/account/tokens/{id}` | Yes (`expires_in`) | Sub-account permissions | Name/ID tracking | Ready |
| OVH | JIT (token minting) | Token endpoint (`client_credentials` grant) | N/A (tokens expire in 1h) | Yes (1h fixed) | IAM policies on service account | Service account identity | Ready (API in BETA) |
| Exoscale | JIT | `POST /api-key` | `DELETE /api-key/{id}` | No | IAM roles (per-op/resource) | Key ID tracking | Ready |
| Vultr | JIT | `POST /v2/users` | `DELETE /v2/users/{user-id}` | No | ACL categories (8 types) | User ID tracking | Ready |
| Akamai | JIT | `POST /identity-management/v3/api-clients` | `DELETE .../{clientId}` | No | Per-API, per-group, IP ACL | Client ID tracking | Ready |
| AWS | Native (partial) | OpenBao AWS engine (IAM users only) | OpenBao handles | Yes (STS) | IAM policies, `iam_tags` | `iam_tags` on users; no `session_tags` for STS | Partial — IAM user only |
| GCP | JIT (direct) | GCP IAM API | GCP IAM API | Yes (impersonation tokens) | IAM bindings | Post-creation label patch | No OpenBao engine exists |
| Azure | JIT (direct) | Azure AD API | Azure AD API | SP secrets have configurable expiry | RBAC | Tags on app registration | No OpenBao engine exists |
| Oracle (OCI) | **Phased rotation** | `POST /users/{id}/authTokens` | `DELETE .../{id}` | No | IAM policies on groups/compartments | User/credential ID | Ready (max 2 tokens/user) |
| DO Spaces | **Deferred** | No public API | No public API | N/A | N/A | N/A | Blocked — no API |

## Detailed Findings

### DigitalOcean (reference implementation — complete)

- **Strategy:** JIT via `POST /v2/tokens`
- **Scoping:** Token scope strings (`read`, `write`). Account-wide, not per-resource.
- **Revocation:** Hard delete via `DELETE /v2/tokens/{id}`
- **Safety boundary:** Name prefix `cloud-creds-<role>-<lease_id>`
- **Minter:** Long-lived PAT with token-creation privileges
- **DO Spaces keys:** No public API for create/delete. Only via web UI. Deferred.

### UpCloud

- **Strategy:** JIT via `POST /1.3/account/tokens`
- **Native TTL:** Yes — `expires_in` field (e.g. `"1h"`, `"30m"`). Max 365 days.
- **Scoping:** Tokens inherit creating account's permissions. For granular scoping, use a sub-account as the minter (`POST /1.3/account/sub` — heavyweight, requires billing fields).
- **Revocation:** `DELETE /1.3/account/tokens/{id}` (204)
- **Minter requirement:** Token must have `can_create_tokens: true`
- **Key difference from DO:** Native TTL means even if revocation fails, credential expires naturally.

### OVH

- **Strategy:** JIT token minting from a long-lived service account
- **Mechanism:** Store a service account (`client_id`/`client_secret`) as minter. On each read, call the OAuth2 token endpoint with `grant_type=client_credentials` to get a 1-hour access token.
- **Token lifetime:** Fixed at 1 hour (non-configurable). Lease TTL must be <= 1h.
- **Scoping:** IAM policies attached to the service account's identity URN.
- **Service account CRUD:** `POST /me/api/oauth2/client` (create), `DELETE /me/api/oauth2/client/{clientId}` (delete). Flow: `CLIENT_CREDENTIALS`.
- **Token endpoints:** EU: `https://www.ovh.com/auth/oauth2/token`, CA: `https://ca.ovh.com/auth/oauth2/token`, US: `https://us.ovhcloud.com/auth/oauth2/token`
- **Risk:** OAuth2 client API is in BETA status.
- **Legacy auth:** No longer required. OAuth2 covers the full OVHcloud API surface.

### Exoscale

- **Strategy:** JIT via `POST /api-key`
- **Base URL:** `https://api-ch-gva-2.exoscale.com/v2`
- **Create:** `POST /api-key` with `name` and `role-id`. Returns `key` + `secret`.
- **Delete:** `DELETE /api-key/{id}`
- **Scoping:** Keys bound to an IAM Role (by UUID). Roles have service policies with per-operation/per-resource rules. Granular.
- **Native TTL:** No. Plugin must revoke explicitly.
- **Minter:** Needs a key with permission to manage API keys, plus pre-configured IAM roles per vault role.

### Vultr

- **Strategy:** JIT via `POST /v2/users` (creates sub-user with API key)
- **Create:** `POST /v2/users` with `api_enabled=true`. Returns user with API key.
- **Delete:** `DELETE /v2/users/{user-id}` (implicitly invalidates the key)
- **Scoping:** ACL-based with 8 categories: `manage_users`, `subscriptions`, `provisioning`, `billing`, `support`, `abuse`, `dns`, `upgrade`. Coarse-grained.
- **Native TTL:** No. Plugin enforces lifetime.
- **Auth:** Bearer API key.

### Akamai

- **Strategy:** JIT via `POST /identity-management/v3/api-clients`
- **Create:** Creates an API client with credentials. `createCredential=true` auto-generates creds.
- **Delete:** `DELETE /identity-management/v3/api-clients/{clientId}` (204, immediate)
- **Scoping:** Rich — `apiAccess` (which APIs), `groupAccess` (which property groups), `ipAcl`, `authorizedUsers`, `purgeOptions`.
- **Native TTL:** No. Credentials live until deleted.
- **Auth:** EdgeGrid (HMAC-based request signing with client_token + access_token + client_secret). Not OAuth2.
- **Risk:** No expiry means leaked credentials with failed revocation live forever. Reconciler is critical.

### AWS

- **Strategy:** Native (partial) — OpenBao has an AWS secrets engine in `openbao/openbao-plugins`
- **OpenBao support:** IAM users with `iam_tags` — works. STS AssumeRole exists but WITHOUT `session_tags`.
- **Safety boundary:** `iam_tags` (e.g. `Owner=cloud-creds`) works for dynamic IAM user credentials. For assumed-role, no tag-based attribution exists in OpenBao.
- **Gap:** If STS assumed-role credentials are needed, would require upstream contribution to add `session_tags` or a custom wrapper calling STS directly.
- **Note:** The AWS engine is in a separate repo (`openbao/openbao-plugins`), not built into OpenBao core.

### GCP

- **Strategy:** JIT (direct GCP API calls) — NO OpenBao GCP engine exists
- **OpenBao support:** None. The GCP secrets engine was NOT ported from Vault. Not in core, not in plugins repo.
- **Direct approach:** Call GCP IAM APIs:
  - Impersonation tokens: `POST generateAccessToken` on a service account (short-lived, 1h max)
  - SA keys: `POST serviceAccounts/{sa}/keys` (long-lived, avoid)
- **Scoping:** IAM bindings on the target service account
- **Safety boundary:** Post-creation label patch (`serviceAccounts.patch` to apply `labels: {owner: "cloud-creds"}`), or name-prefix matching
- **Recommended:** Use impersonation tokens (native short TTL, no cleanup needed) rather than SA keys

### Azure

- **Strategy:** JIT (direct Azure AD API calls) — NO OpenBao Azure engine exists
- **OpenBao support:** None. The Azure secrets engine was NOT ported from Vault.
- **Direct approach:** Call Microsoft Graph API:
  - Create app registration + service principal
  - Add client secret (configurable expiry up to 2 years)
  - Or use federated credentials for workload identity
- **Scoping:** Azure RBAC role assignments on the service principal
- **Safety boundary:** `tags` on app registrations + naming convention (prefix)
- **Note:** SP creation is slow (~10s). Document this latency to callers.

### Oracle Cloud (OCI)

- **Strategy:** Phased rotation (N=2, T configurable)
- **Why not JIT:** Per-user credential limits are very low (max 2 auth tokens, max 3 API keys). Rapid create/delete would hit limits immediately.
- **Credential types:** Auth tokens (max 2/user), customer secret keys (max 2/user for S3-compat), API signing keys (max 3/user, RSA).
- **Native TTL:** None. All credentials persist until deleted.
- **Scoping:** IAM policies on groups/compartments. Credentials themselves are unscoped.
- **No STS equivalent:** No headless session token API. Instance principals are compute-bound only.
- **Rotation approach:** Pre-provision 2 auth tokens per role-user. Rotate one every T/2. Read returns the freshest. Lease TTL = time until that slot's next rotation.
- **`pkg/rotator/` needed:** Yes — OCI is the only cloud requiring phased rotation.

## Architecture Implications

### Major correction from techrfc

The techrfc assumed OpenBao has native AWS, GCP, and Azure secrets engines to wrap. In reality:
- **AWS:** Engine exists (in separate plugin repo) but with limited tag support
- **GCP:** Engine does NOT exist in OpenBao
- **Azure:** Engine does NOT exist in OpenBao

All clouds except AWS (IAM user type) need full JIT implementations calling cloud APIs directly.

### Strategy distribution

| Strategy | Clouds |
|----------|--------|
| JIT (create/delete) | DO, UpCloud, OVH, Exoscale, Vultr, Akamai, GCP (impersonation), Azure (SP creation), AWS (STS direct) |
| Native wrapper | AWS (IAM user only, via OpenBao plugin) |
| Phased rotation | Oracle (OCI) |
| Deferred | DO Spaces |

### Shared infrastructure needed

- `pkg/credenvelope/` — already built, works for all
- `pkg/recovery/` — already built, works for all
- `pkg/metrics/` — already built, works for all
- `pkg/reconciler/` — already built, works for all
- `pkg/worker/` — already built, works for all
- `pkg/rotator/` — needed ONLY for Oracle OCI

### Priority recommendation

1. **UpCloud** — native TTL makes it the safest JIT after DO. Validates that the shared packages work for a second cloud.
2. **Exoscale** — IAM-role-based scoping is interesting; validates granular permission model.
3. **AWS (STS direct)** — high value, skip the native engine, call STS directly with session tags.
4. **GCP** — impersonation tokens are natively short-lived; no revocation needed.
5. **OVH** — token minting from service account; validates OAuth2 flow pattern.
6. **Azure** — SP creation latency needs documentation; otherwise standard JIT.
7. **Vultr** — simple JIT, coarse scoping.
8. **Akamai** — EdgeGrid auth is non-standard; more implementation work.
9. **Oracle** — only cloud needing phased rotation; build `pkg/rotator/` for this.
