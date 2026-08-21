# DigitalOcean API Re-Verification (2026-08-21)

Re-check of the DO assumptions baked into `credential-do` (the reference implementation) and into the DO Spaces deferral, against DigitalOcean's **current** public API surface.

**Method.** Pulled the live public OpenAPI spec
(`https://api-engineering.nyc3.cdn.digitaloceanspaces.com/spec-ci/DigitalOcean-public.v2.yaml`,
~3.0 MB, 431 `/v2/*` paths) and cross-read the docs pages for
`reference/api/scopes/`, `reference/api/create-personal-access-token/`, and the
API reference index. No live API calls were made (no credentials used).

| # | Assumption as documented | Verdict | Impact |
|---|--------------------------|---------|--------|
| D1 | `POST /v2/tokens` / `DELETE /v2/tokens/{id}` are public DO API endpoints | **REFUTED** — absent from the public spec; PAT creation is documented as control-panel-only | Docs corrected; the plugin's mint/revoke path is an undocumented dependency |
| D2 | DO token scopes are coarse (`read`, `write`), account-wide, not per-resource | **STALE** — DO has a fine-grained `<resource>:<verb>` catalog | Roles can be far more tightly scoped than the docs claimed; no code change needed |
| D3 | No token-management scope exists → minter self-rotation infeasible | **REAFFIRMED** | `minter-sets/<set>/rotate` correctly rejects on DO |
| D4 | DO Spaces keys cannot be created via public API | **REFUTED** — `/v2/spaces/keys` is now in the public spec with full CRUD | The Spaces deferral's stated blocker is gone; the quota blocker remains |
| D5 | The plugin's `{name, scopes}` request body is the correct/complete shape | **UNVERIFIED** — the control panel now *requires* an expiry at token creation | Possible required field; possible native TTL. Real-cloud pass (#7) must settle it |

---

## D1 — `POST /v2/tokens` is not a public documented endpoint

The public spec contains no `/v2/tokens` path (the only token-ish paths are
`/v2/dedicated-inferences/{id}/tokens` and `/v2/gen-ai/oauth2/dropbox/tokens`,
both unrelated). `docs.digitalocean.com/reference/api/create-personal-access-token/`
documents PAT creation as a control-panel flow only (Account → API → Tokens →
Generate New Token), and the spec's own auth preamble says tokens are obtained by
"visiting the Apps & API section of the DigitalOcean control panel" or via the
OAuth flow. `dop_v1_` is described as the prefix for "personal access tokens
generated in the control panel".

So `POST /v2/tokens` / `GET /v2/tokens` / `DELETE /v2/tokens/{id}`
(`plugins/credential-do/do_client.go`) are control-panel-internal endpoints, not
contract-covered API. Previously `docs/cloud-credential-research.md`,
`docs/design.md`, `docs/techrfc.md` and `docs/decisions.md` all presented them as
ordinary public API.

**Why this matters more than a doc nit:** `docs/object-storage-credential-audit.md`
rejected DO Spaces *specifically* for depending on an undocumented endpoint
("no stability guarantee, unsuitable for an open-source plugin"). The same
standard, applied consistently, lands on the DO plugin's own hot path. The two
positions were inconsistent.

**Resolution taken:** keep the plugin (it is the reference implementation and the
behaviour is real), but state the dependency plainly wherever the endpoint is
documented, and promote DO to the highest-priority target of the real-cloud
verification pass (deferred item #7). If DO ever changes or fences the endpoint,
`credential-do` breaks with no deprecation notice — that is the risk being
accepted, not hidden.

**Alternatives considered and rejected:**
- *OAuth flow tokens* (`doo_v1_`, documented, scopable, expiring) require
  interactive user authorization — not headless, so not usable for JIT minting.
- *Dropping DO* — disproportionate; the endpoint demonstrably works and is what
  the control panel itself uses.

## D2 — Scopes are fine-grained, not `read`/`write`

DO's scope catalog follows `<resource>:<verb>` mapped to HTTP verbs/CRUD, with
`api:read` / `api:write` as aliases. For Droplets: `droplet:read`,
`droplet:create`, `droplet:update`, `droplet:delete`, `droplet:admin`. The spec
states the rule directly: `POST /v2/droplets` requires `droplet:create`; each
endpoint in the reference names its required scope. Scopes are fixed at creation
(a token's scope cannot be edited afterwards).

The plugin already supports this with **no code change**: `role.Scopes` is an
opaque comma-separated string (`path_roles.go`), split at issue time
(`path_creds.go`) and marshalled straight into the mint request
(`do_client.go`). `cloudconfig.ValidateRole` checks only name and TTLs, so any
scope string DO accepts works today:

```
bao write cloud-creds/digitalocean/roles/droplet-creator \
    minter_set=infra scopes=droplet:create,droplet:read default_ttl=15m
```

Two consequences of pass-through, both intentional and now documented:
- The **minter must itself hold** the scopes it grants; DO will not let a token
  confer privileges its creator lacks. Scope the minter set to the union its
  bound roles need — that is what makes minter sets the capability-isolation
  boundary.
- Scopes are **not validated** against DO's catalog, so a typo surfaces as an
  upstream 4xx at read time (`upstream_auth_failed` / issuance error), not as a
  role-write error. Deliberate: hard-coding a scope catalog would go stale on
  every DO product launch.

## D3 — No token-management scope (self-rotation still infeasible)

Grepping the spec for token-management scopes yields only
`dedicated_inference_tokens:{read,create,delete}` (a different resource). There
is no `token:*` / PAT-management scope, so a minted token can never be
mint-capable. The 2026-06-01 conclusion holds: DO's
`minter-sets/<name>/rotate` rejects, and DO minter PATs are rotated
out-of-band. Reinforced, not weakened — the endpoint isn't merely unscopable, it
isn't public at all.

## D4 — DO Spaces keys ARE now API-issuable

The public spec now carries a **Spaces Keys** tag:

| Operation | Endpoint | Required scope |
|-----------|----------|----------------|
| `spacesKey_list` | `GET /v2/spaces/keys` | `spaces_key:read` |
| `spacesKey_create` | `POST /v2/spaces/keys` | `spaces_key:create_credentials` |
| `spacesKey_get` | `GET /v2/spaces/keys/{access_key}` | `spaces_key:read` |
| `spacesKey_update` / `spacesKey_patch` | `PUT` / `PATCH /v2/spaces/keys/{access_key}` | `spaces_key:update` |
| `spacesKey_delete` | `DELETE /v2/spaces/keys/{access_key}` | `spaces_key:delete` |

Properties relevant to this repo's machinery:
- **Per-bucket scoping** via `grants: [{bucket, permission}]` with
  `read` / `readwrite` / `fullaccess`. `fullaccess` cannot be mixed with scoped
  grants (and wins if both are sent).
- **Secret returned once on create** (`key_create_response.secret_key`) — matches
  the mint-and-hand-over model.
- **`name` is settable and `created_at` is returned** — so both the
  `cloud-creds-<role>-` owner-prefix safety boundary and the reconciler's
  `ConfirmationHold` age check (which needs a create timestamp, cf. F1 in
  `state-assumption-verification-2026-05-31.md`) are satisfiable.
- **No native expiry field** — consistent with cross-cutting finding #1 in the
  object-storage audit: the plugin would own the TTL, via JIT revoke or phased
  rotation.
- **A Spaces minter can be least-privilege**: a PAT scoped to
  `spaces_key:create_credentials` + `spaces_key:read` + `spaces_key:delete`
  suffices, unlike the PAT-minting minter, which needs an unscopable capability.

**What is still unresolved:** the original deferral had two blockers, and only
one has cleared. The 200-keys-per-account cap still makes per-customer long-lived
isolation at ~100k services impossible; per-bucket grants now address *scoping*
but not *volume*. Short-lived JIT issuance (keys live minutes, not forever) fits
comfortably under the cap and is newly viable. Object storage remains out of
scope for this repo, but the reason has changed from "impossible" to "not built,
and quota-bounded for the long-lived use case".

## D5 — Request-shape and expiry gap (unverified)

The control panel now requires choosing an expiry when generating a token
("After the interval passes, the token can no longer authenticate"). The plugin
sends only `{"name": ..., "scopes": [...]}`. Two possibilities, neither
resolvable from documentation of an undocumented endpoint:
1. The API defaults the expiry (or leaves the token non-expiring) — current
   behaviour is fine, and the `Native TTL: No` assumption holds.
2. The API accepts (or requires) an expiry field — in which case DO gains a
   **native TTL**, revoke stops being solely load-bearing, and a bounded
   worst-case leak window comes for free. That would be a material improvement
   worth wiring in.

Also unverified against real DO: whether fine-grained scopes (D2) are accepted by
the undocumented mint endpoint, or whether it only honours the alias scopes.

**Action:** fold D1/D5 into the deferred real-cloud pass (#7) as its first
target, using a disposable account: confirm request/response shape, expiry
support, fine-grained-scope acceptance, and the `dop_v1_` prefix on minted
tokens.

## Doc sites corrected by this pass

- `docs/cloud-credential-research.md` — DO summary row + detailed section (D1, D2), DO Spaces row + section (D4), strategy distribution
- `docs/object-storage-credential-audit.md` — TL;DR row, "DigitalOcean Spaces" section, build-priority list (D4)
- `docs/decisions.md` — "Why DO is the reference implementation" (D1)
- `docs/techrfc.md`, `docs/design.md` — status banners (D1); DO scope example (D2)
- `CLAUDE.md`, `README.md`, `SUMMARY.md` — DO mechanism rows and the object-storage scope note
