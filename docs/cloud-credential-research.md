# Cloud Credential API Research

**Date:** 2026-05-29 (research) — all clouds below were subsequently **built** (see Status column, updated 2026-05-30)
**Purpose:** Determine JIT feasibility, scoping model, and strategy per cloud for the OpenBao credential plugin.

This was the pre-build investigation. Every cloud below is now implemented as a working plugin, and DigitalOcean serves three credential types rather than one; the Status column reflects build state, the rest of the table reflects the API findings that drove each design. **DO findings were re-verified 2026-08-21** — see the note under the table and [`docs/do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md) — and the Spaces-key findings again on 2026-09-15.

## Summary Table

| Cloud | Strategy | Create API | Delete API | Native TTL | Scoping | Safety Boundary | Status |
|-------|----------|-----------|-----------|-----------|---------|-----------------|--------|
| DigitalOcean | JIT | `POST /v2/tokens` (**undocumented** — see note) | `DELETE /v2/tokens/{id}` (**undocumented**) | No | Fine-grained `<resource>:<verb>` scopes | Name prefix `cloud-creds-` | **Built** (reference impl) |
| UpCloud | JIT | `POST /1.3/account/tokens` | `DELETE /1.3/account/tokens/{id}` | Yes (`expires_in`) | Sub-account permissions | Name/ID tracking | **Built** |
| OVH | JIT (token minting) | Token endpoint (`client_credentials` grant) | N/A (tokens expire in 1h) | Yes (1h fixed) | IAM policies on service account | Service account identity | **Built** (API in BETA) |
| Exoscale | JIT | `POST /api-key` | `DELETE /api-key/{id}` | No | IAM roles (per-op/resource) | Key ID tracking | **Built** |
| Vultr | JIT | `POST /v2/users` | `DELETE /v2/users/{user-id}` | No | ACL categories (8 types) | User ID tracking | **Built** |
| Akamai | JIT | `POST /identity-management/v3/api-clients` | `DELETE .../{clientId}` | No | Per-API, per-group, IP ACL | Client ID tracking | **Built** (EdgeGrid/CDN, not Linode object storage) |
| AWS | JIT (direct STS) | `sts:AssumeRole` (called directly) | N/A (STS expires) | Yes (STS, ≤12h) | IAM policy + `session_tags` on the assumed session | Session tags / role ARN | **Built** (direct STS, not the OpenBao AWS engine) |
| GCP | JIT (direct) | SA impersonation `generateAccessToken` | N/A (token expires) | Yes (impersonation tokens) | IAM bindings | SA identity | **Built** (no OpenBao GCP engine exists) |
| Azure | JIT (direct) | Graph `addPassword` on app registration | Graph `removePassword` | SP secrets have configurable expiry | RBAC | Tags + name prefix on app registration | **Built** (no OpenBao Azure engine exists) |
| Oracle (OCI) | **Phased rotation** | `POST /users/{id}/authTokens` | `DELETE .../{id}` | No | IAM policies on groups/compartments | User/credential ID | **Built** (max 2 tokens/user → N=2 slots) |
| DigitalOcean (Spaces keys) | JIT | `POST /v2/spaces/keys` (in the public spec, `bearer_auth`) | `DELETE /v2/spaces/keys/{access_key}` | No | Per-bucket `grants` (read/readwrite/fullaccess) | Name prefix + `created_at` | **Built** as `credential_type=spaces_key` on `credential-do` — the type that cloud can actually mint (was "deferred, no API"; see the DO Spaces findings below) |
| DigitalOcean (Spaces keys, shared) | **Rotation with overlap** | same two endpoints as the row above | same | No | same `grants` | same | **Built** as `credential_type=spaces_key_rotated` on `credential-do` — one key per *role*, replaced every `rotation_period`, the replaced one deleted `overlap_ttl` later |

> **Note (2026-08-21, DO re-verification):** Two DO rows above were corrected against DigitalOcean's current public OpenAPI spec — full findings in [`docs/do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md). (1) `POST /v2/tokens` is **not** a public documented endpoint: the spec has no `/v2/tokens` path and DO documents PAT creation as control-panel-only, so the reference plugin rides a control-panel-internal endpoint. (2) DO scopes are fine-grained `<resource>:<verb>` (e.g. `droplet:create`), not the coarse `read`/`write` originally recorded. (3) DO Spaces keys **are** now API-issuable (`/v2/spaces/keys`, full CRUD, per-bucket grants) — the deferral's "no API" premise is void; the 200-keys/account cap is the remaining blocker for the long-lived per-customer use case.

> **Note (2026-05-30):** The AWS row originally read "Native (partial) — OpenBao AWS engine (IAM users only)." During implementation we chose to call STS directly instead of wrapping the OpenBao AWS engine, which gave full control over `session_tags` (the engine doesn't support them for AssumeRole). All AWS/GCP/Azure plugins are direct-API JIT, not engine wrappers.

> **Note (2026-08-21, TTL semantics):** the "Native TTL" column says whether the
> *cloud* expires the credential; it does not say what the *lease* guarantees. The
> per-cloud mapping between the two — which clouds shorten the credential at mint,
> which revoke at lease end, which TTL bounds are enforced at role write, and where
> a credential can outlive its lease — is in [`ttl-semantics.md`](ttl-semantics.md).

## Capability-probe feasibility (added 2026-08-21)

Two questions the original research did not ask, and which capability
verification turned out to depend on: *can the cloud's health call reveal a
privilege problem?* (universally no) and *what does a throwaway probe mint cost
here?* Authoritative detail in [`minter-capability-verification.md`](minter-capability-verification.md);
the feasibility findings belong with the rest of the per-cloud API facts:

| Cloud | Health call | Can health reveal a privilege gap? | Probe mint | Probe cleanup | Probe residue |
|-------|-------------|-----------------------------------|-----------|---------------|---------------|
| DigitalOcean (token) | `GET /v2/account` | No — and DO has **no scope-introspection API** at all, so nothing short of minting can tell | `POST /v2/tokens` with the role's scope string | `DELETE /v2/tokens/{id}` | none |
| DigitalOcean (Spaces key) | `GET /v2/account` | No — same absence of introspection; a PAT authorized for droplets looks identical to one authorized for Spaces keys | `POST /v2/spaces/keys` with the role's exact grants | `DELETE /v2/spaces/keys/{access_key}` | none, and cleanup matters more here (a Spaces key has no upstream expiry) |
| UpCloud | `GET /1.3/account` | No — `can_create_tokens` is fixed at creation and not reported by the account endpoint | `POST /1.3/account/tokens`, `expires_in=10m` | `DELETE .../tokens/{id}` | none |
| OVH | mints a token | N/A — on OVH the health call *is* a mint, so health and capability coincide | `client_credentials` grant | **impossible** (no revoke API) | one 1h access token |
| Exoscale | `GET /v2/zone` | No — answers for any live key; grantability of a specific `role-id` is invisible | `POST /api-key` bound to the role's role-id | `DELETE /api-key/{id}` | none |
| Vultr | reads the account | No — Vultr refuses to grant a sub-user an ACL the creating key lacks, discoverable only by trying | `POST /v2/users` with the role's ACLs | `DELETE /v2/users/{id}` | none |
| Akamai | `GET /api-clients/self` | Partly — `self` reports the client's *own* grants, but not what it may **delegate** | create api client with the role's `apiAccess`/`groupAccess` | delete api client | none |
| AWS | `sts:GetCallerIdentity` | No — **AWS requires no policy to permit it**, so it cannot fail for a permissions reason | `AssumeRole` (ARN + external ID + session tags), `DurationSeconds=900` | **impossible** (STS has no revoke) | one 900s session |
| GCP | self-signed JWT → own token | No — proves only the minter SA's own key; `serviceAccountTokenCreator` is a grant on each **target** SA | `generateAccessToken` (target SA + scopes), `lifetime=60s` | **impossible** (no token revoke) | one 60s token |
| Azure | reads the app registration | No — read rights do not imply `addPassword`, which needs ownership of *that* application | `addPassword` on the role's `app_object_id`, +10m | `removePassword` | none |
| Oracle (OCI) | reads the user | — | **not probed**: the 2-auth-tokens-per-user cap means a probe would consume a rotation slot | — | — |

Consequence for anyone adding a cloud: a plugin's health check is not allowed to
stand in for capability, and if the cloud cannot revoke what a probe mints, the
probe must pin the requested lifetime to the cloud's documented minimum.

## Detailed Findings

### DigitalOcean (reference implementation — complete)

- **Strategy:** JIT via `POST /v2/tokens`
- **API documentation status (verified 2026-08-21): `POST /v2/tokens` and `DELETE /v2/tokens/{id}` are NOT in DigitalOcean's public API.** The public OpenAPI spec has no `/v2/tokens` path (431 `/v2/*` paths checked), and DO documents personal-access-token creation as a control-panel flow only. These are control-panel-internal endpoints. They work, and they are what the plugin uses, but they carry no stability contract — if DO changes or fences them, `credential-do` breaks with no deprecation notice. The documented alternative (the OAuth `doo_v1_` flow) needs interactive authorization and so cannot mint headlessly. This is an accepted, documented risk; see [`docs/do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md) (D1) and note that it is the **first** target of the deferred real-cloud pass (#7).
- **Scoping:** Fine-grained `<resource>:<verb>` scopes mapped to HTTP verbs/CRUD — e.g. `droplet:read`, `droplet:create`, `droplet:update`, `droplet:delete`, `droplet:admin`; `POST /v2/droplets` requires `droplet:create`. `api:read` / `api:write` are aliases for all-read / all-operations. Scopes are fixed at token creation (not editable afterwards). The plugin passes the role's `scopes` string through unvalidated, so any scope DO accepts works with no code change (`scopes=droplet:create,droplet:read`); the trade-off is that a bad scope surfaces as an upstream 4xx at read time rather than at role-write time. **The minter must itself hold every scope it grants** — DO will not let a token confer privileges its creator lacks — which is why the minter set is the capability-isolation boundary. (Corrected 2026-08-21; this bullet previously read "Token scope strings (`read`, `write`). Account-wide, not per-resource.")
- **Revocation:** Hard delete via `DELETE /v2/tokens/{id}`
- **Native TTL:** None sent by the plugin (`{name, scopes}` only). Unresolved: DO's control panel now *requires* an expiry at creation, so the undocumented endpoint may accept or require an expiry field — which would give DO a native TTL and stop revoke being solely load-bearing. Flagged for the real-cloud pass (D5).
- **Safety boundary:** Name prefix `cloud-creds-<role>-<lease_id>`
- **Minter:** Long-lived PAT with token-creation privileges (an account-level capability, NOT a settable token scope).
- **Minter self-rotation:** **Not feasible** (verified 2026-06-01, re-confirmed 2026-08-21 — the only token-management scopes in the spec are `dedicated_inference_tokens:*`, a different resource; and per the bullet above the endpoint isn't public at all). DO's scope catalog has no `token:*` / token-management scope, so a token created via `POST /v2/tokens` cannot be granted the privilege to create further tokens — self-rotation would break after one cycle. The `minter-sets/<set>/rotate` endpoint therefore rejects on DO ("rotate out-of-band"). Operators rotate the DO minter PAT manually; the `cloud_creds_minter_age_seconds` gauge + near-expiry warn-log surface staleness.
- **DO Spaces keys are the other two credential types this plugin serves** (`spaces_key` per lease, `spaces_key_rotated` per role), and the ones it can mint against the real cloud. Full findings in the next two sections (this bullet previously read "No public API for create/delete. Only via web UI.", which was wrong).

### DigitalOcean Spaces access keys (`credential_type=spaces_key`, 2026-09-15)

The second credential type on `credential-do`, and — given KI-009 — the only one it can
issue against real DigitalOcean. Keep this apart from the question of whether object
storage is a viable *per-customer product substrate*, which is a different question with
the opposite answer (`docs/object-storage-credential-audit.md`).

- **The endpoint is public, specified, and `bearer_auth`.** The spec's **Spaces Keys** tag
  carries full CRUD with a granular scope per operation:

  | Operation | Path | Scope |
  |---|---|---|
  | create | `POST /v2/spaces/keys` | `spaces_key:create_credentials` |
  | list | `GET /v2/spaces/keys` | `spaces_key:read` |
  | get | `GET /v2/spaces/keys/{access_key}` | `spaces_key:read` |
  | modify | `PUT`/`PATCH /v2/spaces/keys/{access_key}` | `spaces_key:update` |
  | revoke | `DELETE /v2/spaces/keys/{access_key}` | `spaces_key:delete` |

  So a Spaces minter can be least-privilege, unlike the PAT minter — it needs
  `spaces_key:create_credentials` to mint, plus `:read` and `:delete` to reconcile and
  revoke.
- **Mint shape.** Request `{name, grants: [{bucket, permission}]}`; the `201` answers
  `{key: {name, access_key, secret_key, grants, created_at}}` and the spec is explicit
  that *"we return secret keys only once upon creation"*.
- **`permission` is a free-form string in the spec, not an enum** — `read`, `readwrite`,
  `fullaccess` and `""` are described, and `grants: []` is legal. Account-wide access is
  `[{bucket: "", permission: "fullaccess"}]`. **The spec says two incompatible things
  about mixing `fullaccess` with scoped grants:** it documents a `400` ("Cannot mix
  fullaccess permission with scoped permissions") *and* says `fullaccess` "will be
  prioritized" if both are present. Under the first reading such a role fails every
  issuance; under the second it silently hands out an account-wide key. That is why the
  plugin **parses** grants and refuses the mix at role write rather than passing the
  string through — right under both readings (`plugins/credential-do/spaces_grants.go`).
- **There is no expiry field of any kind, and it cannot be retro-fitted** (re-read against
  DO's published spec 2026-09-16). The `key` schema has exactly four properties — `name`,
  `grants`, and read-only `access_key` and `created_at` — so there is no TTL to send at
  create, and no rotation endpoint. Nor can a key acquire one later: `PUT`/`PATCH` say in
  the spec's own words that *"you cannot convert a fullaccess key to a scoped key or vice
  versa. You can only update the name of the key"*, so the modify path changes a label and
  nothing else. Grants are immutable too, which is why **rotation can only be
  create-new-then-delete-old** rather than re-granting in place — and therefore why an
  overlap window (two live keys) is unavoidable rather than a choice. The whole REST API
  has only these two Spaces paths, so nothing at the bucket or account level bounds a key's
  life either. A key lives until deleted, which makes revoke the entire lifecycle rather
  than an optimisation, and makes the owner-tag reconciler the only backstop
  ([`ttl-semantics.md`](ttl-semantics.md)). Two consequences the implementation depends on:
  the `access_key` must be in the lease's `internal_data` and in the tracking record,
  because the `secret_key` is unrecoverable after create and revoke needs the access key;
  and an unreclaimed key consumes account capacity indefinitely, since Spaces keys count
  against a per-account cap of 200.
- **The listing pages, and a client that ignores that sees a fraction of the account.**
  DO defaults `per_page` to **20** and caps it at **200**, and answers `keys` alongside
  `links.pages.next`/`.last` and a required `meta.total`. On the one credential type with
  no upstream expiry, a single-page read would show the reconciler 20 of up to 200 keys
  and leak the rest forever, so `ListSpacesKeys` walks every page and returns
  all-or-error — never a partial listing, because the reconciler cannot tell a key it was
  not shown from one that was deleted. It requests pages by *number* rather than following
  the response-supplied `links.pages.next` URL, because the request carries the minter's
  bearer token.
- **The evidence that it answers an ordinary bearer PAT is a production service outside
  this repo**, which creates, lists and deletes Spaces keys with
  `Authorization: Bearer <DO API token>` and pins those requests in its own tests. That
  outranks two things that say otherwise, and **both are wrong**: DO's product docs, which
  state three times that Spaces keys are panel-only, and a 2026-08-21 real-account probe
  that answered `404`. A single probe's status code is not an entitlement — the same lesson
  as KI-009, in the opposite direction.
- **KI-009 does not generalise to it.** `/v2/tokens` is absent from the published spec
  entirely, while `/v2/spaces/keys` is fully specified and declared `bearer_auth`. The
  Edge Gateway fence is specific to undocumented token management, not a property of DO
  management endpoints in general.
- **Minter self-rotation is still infeasible on DO** for the reason in the bullet above:
  the `spaces_key:*` scopes govern Spaces keys, not PATs, and the minter is a PAT.
- **What is still unverified, and should be stated when citing any of the above.** This
  repo's own probe (`make test-cloud-real-do-spaces`) has never been run, so *this
  plugin's* behaviour against real DO is unknown; the plugin's Spaces client and the DO
  fake were written from one reading of the spec and therefore agree by construction
  ([`openbao-integration-gaps.md`](openbao-integration-gaps.md) holds what each layer
  proves and what the probe would settle); and whether DO validates that a grant's bucket
  exists is untested, which if it does is a finding about *role writes* — a role passing
  every gate and failing every issuance.

Design rationale for the type — why a new `s3_credentials` credential kind rather than
reusing an existing one, why AWS-style key names, why `endpoint` and `region` ride inside
the credential block, and why reconciler ids carry their credential class — is in the
2026-09-15 entries of [`decisions.md`](decisions.md).

### DigitalOcean Spaces access keys, shared and rotated (`credential_type=spaces_key_rotated`, 2026-09-16)

A third credential type on `credential-do`, on the same two paths as the section above and
needing **no API surface that section does not already describe**. What differs is who the
key belongs to: the role, rather than the lease that read it. Every reader of the role is
handed the same key, and the plugin replaces it on a schedule of its own.

- **The absent expiry field is what makes the type necessary rather than merely possible.**
  Because a key has no TTL and its grants cannot be changed after create (the expiry bullet
  above), the only way to replace one is to create its successor and then delete it — so two
  keys are live for however long the old one is kept. A per-lease key hides that window
  inside one lease (create at read, delete at lease end); a shared key cannot, because the
  key being replaced is in the hands of clients that have not asked again yet. So the window
  is named and bounded instead: `rotation_period` (a **ceiling** — the jitter is subtracted
  from it and never added, so a key is never served for longer than the operator asked),
  `rotation_jitter` (default a tenth of the period, rolled once when the key is minted so the
  date does not move under a client watching its TTL) and `overlap_ttl` (how long the
  replaced key keeps working). Enforced at role write: `rotation_period ≥ 1h`,
  `overlap_ttl ≤ rotation_period`, `max_ttl ≤ overlap_ttl`.
- **The 200-key cap binds the opposite thing.** Per-lease keys spend the cap on *concurrent
  leases* — 200 live at once across the account, however few roles there are. A shared key
  costs **one** per role, two during an overlap, however large the fleet reading it. The cap
  therefore bounds roles (100 rotated roles in the worst case) and stops bounding clients
  altogether, which is the reason to reach for the type: a fleet re-fetching its credential
  on a cron no longer counts against the account at all.
- **It stores the secret, and nothing else in this repo does.** DO returns a Spaces secret
  exactly once, at create, and this type's contract is to hand the *same* credential back to
  a reader who asks again — so either the mount's storage holds the secret or the contract
  cannot be implemented. The per-lease type keeps only the `access_key`, which is all a
  revoke needs. That is a genuine difference in what a compromise of the mount's storage
  exposes: a live credential, not just a handle for deleting one. OCI's rotation slots
  already make the same trade, for the same reason.
- **`DELETE` still exists, which is what separates this from OCI's slots.** The credential
  outliving its reader's lease is a property of sharing, but it is not a property of the
  cloud: DO will delete a Spaces key on demand at any time. So both containment levers are
  real here — replace the key now and let the overlap run, or delete it now and break every
  holder — where OCI's two-token budget leaves only the first
  ([`ttl-semantics.md`](ttl-semantics.md)).
- **Unverified the same way, and one step further.** Everything in the previous section's
  final bullet applies unchanged. Beyond it, rotation issues a create *and* a delete against
  the account in one operation and re-reads a key it minted earlier, and no recording in
  `plugins/credential-do/testdata/cloud-real/` covers any of that — the four that exist are
  from the 2026-08-21 token run.

### UpCloud

- **Strategy:** JIT via `POST /1.3/account/tokens`
- **Native TTL:** Yes — `expires_in` field (e.g. `"1h"`, `"30m"`), set from the role's default TTL. Documented as "a positive duration and maximum of 8760h" — the 8760h ceiling is enforced at role write (`maxUpCloudTTL`); there is no documented minimum, so no floor. Because `expires_in` is fixed at mint and cannot be extended, leases are **not renewable** (see [`ttl-semantics.md`](ttl-semantics.md)).
- **Scoping:** Tokens inherit creating account's permissions. For granular scoping, use a sub-account as the minter (`POST /1.3/account/sub` — heavyweight, requires billing fields).
- **Revocation:** `DELETE /1.3/account/tokens/{id}` (204)
- **Minter requirement:** Token must have `can_create_tokens: true`
- **Key difference from DO:** Native TTL means even if revocation fails, credential expires naturally.

### OVH

- **Strategy:** JIT token minting from a long-lived service account
- **Mechanism:** Store a service account (`client_id`/`client_secret`) as minter. On each read, call the OAuth2 token endpoint with `grant_type=client_credentials` to get a 1-hour access token.
- **Token lifetime:** Fixed at 1 hour (non-configurable) — the token endpoint takes no lifetime parameter — and there is **no token-revoke API**. Neither shortening at mint nor revoking at lease end is therefore possible, so role TTLs are pinned to **exactly 3600s** (both bounds enforced at role write). A shorter TTL would leave the token live after the lease ended, with nothing able to stop it; see [`ttl-semantics.md`](ttl-semantics.md).
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
- **Native TTL:** No. Plugin must revoke explicitly — an unrevoked key persists until the owner-tag reconciler deletes it (which on Exoscale needs the manual `/reconcile` endpoint, KI-004). Any role TTL is therefore enforceable, so no TTL bounds are imposed.
- **Minter:** Needs a key with permission to manage API keys, plus pre-configured IAM roles per vault role.

### Vultr

- **Strategy:** JIT via `POST /v2/users` (creates sub-user with API key)
- **Create:** `POST /v2/users` with `api_enabled=true`. Returns user with API key.
- **Delete:** `DELETE /v2/users/{user-id}` (implicitly invalidates the key)
- **Scoping:** ACL-based with 8 categories: `manage_users`, `subscriptions`, `provisioning`, `billing`, `support`, `abuse`, `dns`, `upgrade`. Coarse-grained.
- **Native TTL:** No. Plugin enforces lifetime by revoking — an unrevoked sub-user persists until the owner-tag reconciler deletes it (manual `/reconcile` on Vultr, KI-004). Any role TTL is enforceable, so no TTL bounds are imposed.
- **Auth:** Bearer API key.

### Akamai

- **Strategy:** JIT via `POST /identity-management/v3/api-clients`
- **Create:** Creates an API client with credentials. `createCredential=true` auto-generates creds.
- **Delete:** `DELETE /identity-management/v3/api-clients/{clientId}` (204, immediate)
- **Scoping:** Rich — `apiAccess` (which APIs), `groupAccess` (which property groups), `ipAcl`, `authorizedUsers`, `purgeOptions`.
- **Native TTL:** No. Credentials live until deleted. The Identity API does return (and can set) an `expiresOn`; the plugin accepts the account default and relies on revoke — setting it to the lease end would be defence in depth, deferred to the real-cloud pass.
- **Auth:** EdgeGrid (HMAC-based request signing with client_token + access_token + client_secret). Not OAuth2.
- **Risk:** No expiry means leaked credentials with failed revocation live forever. Reconciler is critical.

### AWS

- **Strategy:** Native (partial) — OpenBao has an AWS secrets engine in `openbao/openbao-plugins`
- **OpenBao support:** IAM users with `iam_tags` — works. STS AssumeRole exists but WITHOUT `session_tags`.
- **Safety boundary:** `iam_tags` (e.g. `Owner=cloud-creds`) works for dynamic IAM user credentials. For assumed-role, no tag-based attribution exists in OpenBao.
- **Gap:** If STS assumed-role credentials are needed, would require upstream contribution to add `session_tags` or a custom wrapper calling STS directly.
- **Note:** The AWS engine is in a separate repo (`openbao/openbao-plugins`), not built into OpenBao core.
- **TTL bounds:** STS `DurationSeconds` is documented as minimum 900, maximum 43200. Both bounds are enforced at role write (`minSTSTTL`/`maxSTSTTL`) on `default_ttl` and `max_ttl`; STS sessions cannot be revoked, so an out-of-range TTL could not be compensated for at lease end.

### GCP

- **Strategy:** JIT (direct GCP API calls) — NO OpenBao GCP engine exists
- **OpenBao support:** None. The GCP secrets engine was NOT ported from Vault. Not in core, not in plugins repo.
- **Direct approach:** Call GCP IAM APIs:
  - Impersonation tokens: `POST generateAccessToken` on a service account (short-lived, 1h max)
  - SA keys: `POST serviceAccounts/{sa}/keys` (long-lived, avoid)
- **Scoping:** IAM bindings on the target service account
- **Safety boundary:** Post-creation label patch (`serviceAccounts.patch` to apply `labels: {owner: "cloud-creds"}`), or name-prefix matching
- **Recommended:** Use impersonation tokens (native short TTL, no cleanup needed) rather than SA keys
- **TTL bounds:** `lifetime` maxes at 3600s by default and 43200s with the credential-lifetime-extension org policy; the 43200s ceiling is enforced at role write (`maxGCPTTL`). GCP documents **no minimum**, so no floor is imposed.

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
- **TTL bounds:** the secret's `endDateTime` is set to mint time + the role's default TTL, so the credential expires with the lease and hard revoke closes it earlier if needed. Microsoft documents no minimum, so no floor is imposed — but a very short TTL interacts badly with the Graph propagation lag (KI-003). Because `endDateTime` cannot be extended, leases are **not renewable**.

### Oracle Cloud (OCI)

- **Strategy:** Phased rotation (N=2, T configurable)
- **Why not JIT:** Per-user credential limits are very low (max 2 auth tokens, max 3 API keys). Rapid create/delete would hit limits immediately.
- **Credential types:** Auth tokens (max 2/user), customer secret keys (max 2/user for S3-compat), API signing keys (max 3/user, RSA).
- **Native TTL:** None. All credentials persist until deleted — hence the phased-rotation strategy, and hence OCI's **soft** revoke: the lease ends but the slot's token stays live until its scheduled rotation. The lease never overstates validity (TTL is clamped to the time until that slot's next rotation), but the credential can outlive it by design — see [`ttl-semantics.md`](ttl-semantics.md).
- **Scoping:** IAM policies on groups/compartments. Credentials themselves are unscoped.
- **No STS equivalent:** No headless session token API. Instance principals are compute-bound only.
- **Rotation approach:** Pre-provision 2 auth tokens per role-user. Rotate one every T/2. Read returns the freshest. Lease TTL = time until that slot's next rotation.
- **Phased rotation:** OCI is the only cloud requiring it. Slot management was built in-plugin (`plugins/credential-oci/slots.go`), not as a shared `pkg/rotator/` package.

## Architecture Implications

### Major correction from techrfc

The techrfc assumed OpenBao has native AWS, GCP, and Azure secrets engines to wrap. In reality:
- **AWS:** Engine exists (in separate plugin repo) but with limited tag support
- **GCP:** Engine does NOT exist in OpenBao
- **Azure:** Engine does NOT exist in OpenBao

All clouds need full JIT implementations calling cloud APIs directly, except OCI (phased rotation). No cloud uses the OpenBao native-engine-wrapper approach in the end.

### Strategy distribution (as built)

| Strategy | Clouds |
|----------|--------|
| JIT (create/delete) | DO (PATs, and per-lease Spaces keys), UpCloud, OVH, Exoscale, Vultr, Akamai, GCP (impersonation), Azure (SP secret), AWS (STS direct) |
| Phased rotation | Oracle (OCI) |
| Rotation with overlap | DO (shared Spaces keys) |

The third row is not phased rotation with N=1. OCI pre-provisions its slots and a rotation
deletes the slot's credential as it replaces it, sizing each lease to end first; a shared
Spaces key is minted on first demand and the key it replaces is deliberately kept alive for
`overlap_ttl`, because a client that already holds it may not ask again for hours. The
difference exists because the caps differ: OCI's two-tokens-per-user budget has no room for a
grace period, and DO's 200-keys-per-account has plenty.

### Shared infrastructure (all built)

- `pkg/credenvelope/` — envelope + error codes, used by all
- `pkg/recovery/` — minter recovery state machine, used by all
- `pkg/reconciler/` — orphan reclamation, used by JIT plugins
- `pkg/worker/` — background worker lifecycle, used by all
- Phased-rotation slot management lives **in-plugin** (`plugins/credential-oci/slots.go`), not in a shared `pkg/rotator/`. OCI is the only cloud that needs it, so per YAGNI it was not extracted into a shared package.

### Build order followed (all complete)

Implemented in this sequence after DO; each note records the distinguishing trait:

1. **UpCloud** — native TTL makes it the safest JIT after DO. Validated the shared packages on a second cloud.
2. **Exoscale** — IAM-role-based scoping; validated the granular permission model.
3. **AWS (STS direct)** — called STS directly with session tags (skipped the native engine).
4. **GCP** — impersonation tokens are natively short-lived; no revocation needed.
5. **OVH** — token minting from a service account; validated the OAuth2 flow pattern.
6. **Azure** — SP secret creation via Graph; standard JIT with hard revoke.
7. **Vultr** — simple JIT, coarse ACL scoping.
8. **Akamai** — EdgeGrid HMAC auth (CDN/Identity API; not Linode object storage).
9. **Oracle (OCI)** — the only cloud needing phased rotation; slot manager built in-plugin (`slots.go`).
