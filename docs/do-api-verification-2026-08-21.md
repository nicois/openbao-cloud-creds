# DigitalOcean API Re-Verification (2026-08-21)

Re-check of the DO assumptions baked into `credential-do` (the reference implementation) and into the DO Spaces deferral, against DigitalOcean's **current** public API surface.

**Method.** Pulled the live public OpenAPI spec
(`https://api-engineering.nyc3.cdn.digitaloceanspaces.com/spec-ci/DigitalOcean-public.v2.yaml`,
~3.0 MB, 431 `/v2/*` paths) and cross-read the docs pages for
`reference/api/scopes/`, `reference/api/create-personal-access-token/`, and the
API reference index. No live API calls were made (no credentials used).

**Addendum, same day:** a live probe against a real DO account was added later
that day (`plugins/credential-do/real_cloud_test.go`, build tag `cloud_real`), and
run twice — once with a granular PAT, then with a **full-access** one. The
spec-only reasoning D1–D5 below stands, but its *consequence* is now far sharper
than "undocumented": `/v2/tokens` refuses personal-access-token authentication
outright, at DigitalOcean's edge. See
[Real-account probe](#real-account-probe-2026-08-21) at the end, and **KI-009** in
[`known-issues.md`](known-issues.md), which is where that conclusion is tracked.

| # | Assumption as documented | Verdict | Impact |
|---|--------------------------|---------|--------|
| D1 | `POST /v2/tokens` / `DELETE /v2/tokens/{id}` are public DO API endpoints | **REFUTED, twice over** — absent from the public spec, PAT creation documented as control-panel-only, and (R1) refused at DO's edge gateway for *any* PAT | The plugin's mint/revoke path **does not work against real DigitalOcean** — KI-009 |
| D2 | DO token scopes are coarse (`read`, `write`), account-wide, not per-resource | **STALE** — DO has a fine-grained `<resource>:<verb>` catalog | Roles can be far more tightly scoped than the docs claimed; no code change needed — though moot for issuance while D1 holds |
| D3 | No token-management scope exists → minter self-rotation infeasible | **REAFFIRMED, and overtaken** — no PAT can manage tokens at all (R1), let alone a minted one | `minter-sets/<set>/rotate` correctly rejects on DO, now for a stronger reason than "no scope for it" |
| D4 | DO Spaces keys cannot be created via public API | **CONTESTED** — in the public spec with full CRUD, but DO's product docs say panel-only (stated three times) and a real account answered **404** | The Spaces deferral's API blocker is **not** cleared after all; the quota blocker (100 buckets / 200 keys per account) stands, and so does an outage-tolerance blocker the audit had not considered |
| D5 | The plugin's `{name, scopes}` request body is the correct/complete shape | **UNANSWERABLE** — the request is refused before any body is parsed (R1), so no credential this plugin can hold will ever elicit a shape verdict | The `Native TTL: No` assumption stands by default, and cannot be improved on |

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

> **Update, hours later (R1).** That risk was not hypothetical and not future: the
> endpoint **is** fenced, today, for PAT authentication. Promoting DO to the first
> real-cloud target was the right call and it paid immediately. What the endpoint
> demonstrably works *for* is DigitalOcean's own control panel, which authenticates
> with a session rather than a bearer token — a distinction this document could not
> have drawn from the spec, and one that makes the whole "undocumented but working"
> framing wrong. The plugin's retention is now argued on different grounds (it is
> the code-shape reference and the origin of the DO fake), recorded in
> [`decisions.md`](decisions.md) and KI-009.

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

## D4 — DO Spaces keys: the spec says yes, DO's own docs say no

> **Corrected later the same day.** This section was written as "DO Spaces keys ARE now
> API-issuable" on the strength of the public spec alone. That was the same mistake D1 had
> just been punished for, made in the opposite direction — reading a spec as a statement
> about what a credential may *do*. DO's product docs
> (`products/spaces/how-to/manage-access/`, `products/spaces/details/limits/`) state three
> times that Spaces access keys "can only be created and managed through the DigitalOcean
> Control Panel" and "cannot currently be created, edited, or deleted using the
> DigitalOcean API or CLI" — and the real-account probe's unexplained **404** on
> `/v2/spaces/keys` (below) fits that, not the spec. Two of three sources say no API.
>
> The pattern across both DO credential types is now consistent and worth naming: **DO
> keeps credential management out of the API.** `/v2/tokens` is absent from the spec, works
> for the control panel, and is fenced from PATs at the edge gateway; `/v2/spaces/keys` is
> present in the spec while the docs say API callers cannot use it. A spec entry is not an
> entitlement, in either direction. D4's verdict is **CONTESTED**, and the Spaces "the
> blocker is gone" conclusion in
> [`object-storage-credential-audit.md`](object-storage-credential-audit.md) is withdrawn
> there too.

The public spec carries a **Spaces Keys** tag (accuracy of which is what the note above
disputes):

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
  `ConfirmationHold` age check (which needs a create timestamp, absent which the
  reconciler fails closed — `known-issues.md` KI-004) are satisfiable.
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

> **Done, same day, and it answered a bigger question than the one asked.** None of
> the four items above can be resolved: the mint request is refused before its body
> is read (R1). D5 is closed as unanswerable rather than confirmed or refuted.

## Real-account probe (2026-08-21)

**Method.** `plugins/credential-do/real_cloud_test.go` (build tag `cloud_real`,
run by `make test-cloud-real-do`) against a real, disposable DO account. It drives
the plugin's **own** `doClient` — not a fresh HTTP client — so that response
decoding is under test too: a field name the plugin gets wrong would mint
successfully and hand back an empty credential, which is precisely the bug class a
fake written from the same reading of the docs cannot catch. Every response is
written to `plugins/credential-do/testdata/cloud-real/` through a fail-closed
scrubber (it aborts the test rather than write a file containing a credential).
A read-only `curl` matrix was used alongside it to classify the failures.

It ran **twice**, and the two runs are what make the finding safe to state.

### Run 1 — a granular (scoped) PAT

The PAT initially available turned out to be scoped, which the probe established
rather than assumed:

| Call | Status |
|------|--------|
| `GET /v2/regions`, `GET /v2/sizes`, `GET /v2/droplets` | **200** |
| `GET /v2/account` | 403 |
| `GET /v2/projects`, `GET /v2/tags`, `GET /v2/account/keys` | 403 |
| `GET /v2/tokens`, `GET /v2/tokens/scopes` | 403 |
| `POST /v2/tokens` | 403 — `{"id": "Forbidden", "message": "You are not authorized to perform this operation"}` |

Two hundreds alongside the 403s is the whole point of the matrix: it proves the
token is **live**, which is what makes each 403 an authorization verdict rather
than an authentication one. Without that discrimination a wall of 403s is
unreadable, and the probe's first attempt duly mis-attributed its own finding.

This run supported exactly one conclusion — a scoped PAT cannot mint — and the
probe said so in its own failure text: *"Re-run with a FULL-ACCESS PAT to test the
endpoint itself; if a full-access PAT also gets 403, the mint path does not work
headlessly at all."*

### Run 2 — a full-access PAT

| Call | Status | `X-Response-From` |
|------|--------|-------------------|
| `GET /v2/account`, `/v2/projects`, `/v2/tags`, `/v2/account/keys`, `/v2/droplets`, `/v2/sizes`, `/v2/images`, `/v2/volumes`, `/v2/kubernetes/clusters`, `/v2/databases`, `/v2/apps` | **200** | `service` |
| `GET /v2/tokens`, `GET /v2/tokens/scopes` | 403 | **`Edge-Gateway`** |
| `POST /v2/tokens` | 403 | **`Edge-Gateway`** |
| the same paths, **no `Authorization` header** | 401 | `Edge-Gateway` |

**R1 — no PAT can mint; `/v2/tokens` is fenced at DO's edge (supersedes the
earlier reading).** A privileged token reads eleven endpoints and is still refused
on `/v2/tokens`, so privilege is not the variable. What identifies the mechanism is
DigitalOcean's own `X-Response-From` header: successful calls are answered by a
`service`, every `/v2/tokens*` call by `Edge-Gateway`. The refusal is made by DO's
gateway **before** any service weighs the token — and the unauthenticated 401s on
those same paths show the gateway authenticates first and then declines the route.
This is routing, not authorization.

So the intermediate conclusion drawn from run 1 — "a DO minter must be a full-access
PAT" — is **wrong**, and worth recording as wrong: there is no mint-capable PAT of
any kind. Tracked as **KI-009**; surfaced to operators as `forbiddenMintHint` on the
capability probe's 403, because DO's bare "You are not authorized to perform this
operation" sends them hunting for a privilege that does not exist. What the endpoint
works for is the control panel, which holds a session rather than a bearer token.

Not tested: OAuth (`doo_v1_`) tokens. They are a different credential class and
require interactive authorization, so they cannot be minted headlessly regardless —
already the rejected alternative under D1. Also noted without conclusion at the time:
`/v2/actions`, `/v2/ssh_keys` and `/v2/spaces/keys` returned 404 on this account,
which is odd but does not bear on the reasoning above — `/v2/tokens` is *routed and
refused*, not absent.

**Those three 404s were followed up 2026-09-15, and they do not hold together as
evidence of an absent path.** DO's Edge Gateway decides routing *before* it
authenticates, so an unauthenticated request separates "path unknown" from "path known,
credential needed" at no cost and with no credential:

| Unauthenticated `GET` | Status | Reading |
|---|---|---|
| `/v2/definitely-not-a-real-path` | **404** (`X-Response-From: Edge-Gateway`) | this is what an unrouted path looks like |
| `/v2/spaces/keys` | **401** | routed |
| `/v2/spaces/keys/<key>` (also `POST`/`DELETE`) | **401** | routed, per method |
| `/v2/actions` | **401** | routed — yet it 404'd on the probe account |
| `/v2/ssh_keys` | **404** | not a DO path at all; SSH keys are `/v2/account/keys` |
| `/v2/tokens` | **401** | routed — and still 403 for every PAT (KI-009) |

So of the three, one was simply the wrong URL, and the other two are routed at the edge:
whatever produced those 404s was not the gateway saying the path does not exist. That
removes the 404 as a reason to doubt Spaces-key issuance, and is why D4's **contested**
verdict is superseded — the findings that replace it are in
[`cloud-credential-research.md`](cloud-credential-research.md), "DigitalOcean Spaces
access keys".

**It proves routing, not entitlement, and the distinction is the whole of KI-009.**
`/v2/tokens` is routed too and is refused for every PAT. An unauthenticated 401 says a
request will be *weighed*, never that it will be allowed, so this cannot stand in for
`make test-cloud-real-do-spaces`. What it does is retire one piece of contrary evidence.

**R2 — the health check needs `account:read` (from run 1, still stands).** This
plugin's health check *is* `GET /v2/account` (`do_client.go`), which a granular PAT
is forbidden from calling while otherwise perfectly alive; a scoped minter would be
driven to `AuthFailing` by the recovery state machine on liveness grounds that are
false. Kept as-is deliberately — see [`decisions.md`](decisions.md), whose argument
survives R1 intact but on narrower grounds: with no PAT able to mint at all, the DO
health check is only ever exercised against a full-access token (200) or in tests
against the fake, and the false-alarm case still cannot arise.

**R3 — D1/D5 are now closed, unfavourably.** The question the probe existed for is
answered: `POST /v2/tokens` does not accept PATs, so the reference plugin's mint
path does not work in production. D5's request-shape question (does DO accept an
expiry field, which would give it a native TTL?) is not merely unanswered but
**unanswerable with any credential this plugin can hold** — the request never
reaches a body parser.

The probe therefore changed job, from asking to **pinning**: it now asserts the
fence (`/v2/account` 200 from `service` as the control, `GET`/`POST` `/v2/tokens`
403 from `Edge-Gateway`) and *fails as good news* if DO ever allows the mint —
whereupon it exercises the full success path it has always carried (assert `token.id`
and `token.access_token` are non-empty, use the credential, `DELETE` it, confirm it
stops authenticating within 15s, since with no upstream expiry revoke is the only
bound on a DO credential — [`ttl-semantics.md`](ttl-semantics.md)) and says to
re-verify D1/D5. The credential-free half of the evidence is checked by
`plugins/credential-do/fake_parity_test.go` on every ordinary `go test`.

**Fixture parity, first data point.** The error envelope DO returns here is
`{"id", "message"}` — the shape `pkg/credenvelope/fakes/do.go` already used, so
the fake was right about the thing that matters. (Strictly this is the *gateway's*
envelope, not a service's; the fake is held to it anyway, because it is what a real
minter receives, and the fake stands in for what DO answers rather than for what DO
documents.) It differed in the literals
(lowercase `"forbidden"`, a friendlier message); the fake's mint-forbidden body is
now byte-for-byte DO's, cited to the recording — and held there by
`plugins/credential-do/fake_parity_test.go`, an ordinary credential-free test that
drives the fake to the same state and compares bodies. This is the mechanism
`docs/free-account-viability.md` describes working as intended: one privileged run
turning into a permanent check on the fake. Recordings the fake is *not* answerable
for are declared there with reasons rather than left to rot unused: the two `GET`
403s (reachable in the fake only through its deliberately synthetic injected-error
knob) and the `/v2/account` 200 (whose body `CheckHealth` discards unread, and which
is kept as the *control* for R1 — same token, answered by a `service`).

## Doc sites corrected by this pass

- `docs/known-issues.md` — **KI-009**, where R1's consequence for the plugin is tracked
- `docs/cloud-credential-research.md` — DO summary row + detailed section (D1, D2), DO Spaces row + section (D4), strategy distribution
- `docs/object-storage-credential-audit.md` — TL;DR row, "DigitalOcean Spaces" section, build-priority list (D4)
- `docs/decisions.md` — "Why DO is the reference implementation" (D1)
- `docs/techrfc.md`, `docs/design.md` — status banners (D1); DO scope example (D2)
- `CLAUDE.md`, `README.md`, `SUMMARY.md` — DO mechanism rows and the object-storage scope note
