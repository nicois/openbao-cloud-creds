# Handover: minting DO Spaces keys, and why this repo needs it

**Date:** 2026-09-15
**Status:** **implemented** (2026-09-15) — `credential_type=spaces_key` on a `credential-do` role.
Two of this note's implementation recommendations were overridden; see "What was built" below. The
one thing no test here can settle — whether `POST /v2/spaces/keys` answers *this* repo's bearer PAT
— has a real-cloud probe written for it (`make test-cloud-real-do-spaces`) that has **not yet been
run**, because no DO token is reachable from the development environment.
**Corrects:** [`docs/object-storage-credential-audit.md`](object-storage-credential-audit.md) — its
DigitalOcean Spaces row records API issuance as *contested* on the strength of a real-account 404.
That objection is now cleared by production evidence. Its **quota** objection is untouched; see
"What this does not clear".

## Why this matters more than an extra credential type

KI-009 leaves `plugins/credential-do` with **nothing it can mint**. The plugin issues through
`POST /v2/tokens` ([`plugins/credential-do/backend.go:18`](../plugins/credential-do/backend.go),
[`do_client.go:67`](../plugins/credential-do/do_client.go)), and that endpoint answers `403` from
`X-Response-From: Edge-Gateway` for every bearer PAT — the known-issues entry says as much: *"it
says the reference plugin cannot issue against the real cloud"*.

Spaces access keys are a credential this repo's DigitalOcean plugin **can** mint with the minter it
already has. That is the point of the work.

## What is verified

### The endpoint

`POST /v2/spaces/keys` is in DigitalOcean's published OpenAPI spec, non-beta, declared
`bearer_auth`, with per-operation granular scopes:

| Operation | Path | Scope |
|---|---|---|
| create | `POST /v2/spaces/keys` | `spaces_key:create_credentials` |
| list | `GET /v2/spaces/keys` | `spaces_key:read` |
| get | `GET /v2/spaces/keys/{access_key}` | `spaces_key:read` |
| modify | `PUT`/`PATCH /v2/spaces/keys/{access_key}` | `spaces_key:update` |
| revoke | `DELETE /v2/spaces/keys/{access_key}` | `spaces_key:delete` |

Request body is `{name, grants: [{bucket, permission}]}`. `permission` is a free-form string in the
spec, not an enum, with `read`, `readwrite`, `fullaccess` and `""` documented. `grants: []` is
legal. Full access is expressed as `[{bucket: "", permission: "fullaccess"}]`, and the spec says two
incompatible things about mixing `fullaccess` with scoped grants: it documents a `400` ("Cannot mix
fullaccess permission with scoped permissions") and it also says `fullaccess` "will be prioritized"
when both are added. Either way the combination is worth rejecting at role-write time rather than
passing through — a role that fails every issuance under the first reading, a silent privilege
escalation under the second.

The `201` response is `{key: {name, access_key, secret_key, grants, created_at}}`, and the spec is
explicit: *"We return secret keys only once upon creation."*

### It works in production, with a plain bearer token

A production service outside this repo creates Spaces keys today with
`Authorization: Bearer <DO API token>` against `https://api.digitalocean.com/v2/spaces/keys`, and
its unit tests pin the literal requests for create, list and delete. That is the real-account evidence the object-storage audit said was
missing, and it is stronger than a probe because it is load-bearing for a running service.

This also resolves the audit's contradiction — DO's product docs still claim Spaces keys are
panel-only, and the reference disagrees. **The reference is right.** Treat the how-to page as stale.

### KI-009 does not generalise

`/v2/tokens` is **absent from the published spec entirely**, while `/v2/spaces/keys` is fully
specified with `bearer_auth`. The Edge Gateway fence is specific to undocumented token management,
not a property of management endpoints in general. Production traffic to `/v2/spaces/keys`
corroborates that.

### There is no upstream expiry

No TTL field, no expiry, no rotation endpoint. A Spaces key lives until deleted. Two consequences,
both load-bearing:

- A lease over one is a promise only this plugin can keep. `DELETE` on revoke is not an
  optimisation, it is the entire lifecycle. The `revoke` conformance category and
  `Harness.TrackingPrefix` are what stop that regressing.
- Revocation needs the `access_key`, and the `secret_key` is unrecoverable after create. So the
  tracking record must carry `access_key` and the lease's `internal_data` must too — losing it
  orphans a credential that never expires.

## What this does not clear

The audit's **quota** objection stands: 200 access keys and 100 buckets per *account*, both
per-account rather than per-team, and buckets cannot be moved between accounts. That rules out
Spaces as a substrate for per-customer isolation at ~100k services, which is what the audit was
assessing.

It does not bear on this work. The consumer here needs a handful of operational keys for the
management plane, not one per customer. Keep the two questions apart: this handover clears *API
issuance*, not *object storage as a product feature*.

`pkg/upstreamquota` and `pkg/mintercapacity` are the right places for the 200-key cap to become
visible rather than a surprise.

## What remains unproven

One thing, and it gates only the *console* path, not this repo's:

**Whether a granular token can be minted carrying `spaces_key:*`.** Nobody has minted a permission
outside `database`, `regions`, `sizes` and `actions`. For this repo it does not matter — the minter
is an operator-supplied PAT, and an operator can grant it `spaces_key:create_credentials` in the
DO panel. It matters for the sibling console driver, which mints its own tokens.

Cheapest settlement: create one granular token in the panel with the Spaces scopes, then read it
back through the private API's `ListTokens` and record the `permissions` array verbatim. That also
answers the wider open question of DO's `{namespace, action}` vocabulary.

## What was built (2026-09-15)

`credential_type` on a `credential-do` role selects the shape: `token` (the default, unchanged for
every existing role) or `spaces_key`. A Spaces role takes `grants` and `region`, and optionally
`endpoint`; a token role keeps `scopes`. Each type's fields are refused on the other's role rather
than ignored. Rationale for all of it: [`decisions.md`](decisions.md), the four 2026-09-15 entries.

Two of the implementation notes below were **overridden**:

- **A new credential kind was added after all: `s3_credentials`**, not `KindKeySecret`. The S3 API
  is a de-facto standard, so the shape gets its own name and is sized for every backend that will
  serve it — `{access_key_id, secret_access_key, endpoint, region}` (+ `session_token` where a
  cloud grants one). `endpoint` and `region` are inside the credential block because an S3 client
  cannot be constructed without them and neither is derivable from the key material.
- **Key names are AWS-style, not DigitalOcean's.** The kind is named for the protocol, so its keys
  are spelled the way S3 clients spell them; a shared shape carrying one vendor's field names would
  make the second plugin serving it either wrong or inconsistent.

The scope shape became `ScopeKindGrants`, as this note predicted, and grants are **parsed** rather
than passed through — the spec's two incompatible answers about mixing `fullaccess` with scoped
grants (above) mean a role reading as least-privilege would otherwise either fail at every issuance
or get an account-wide key, and refusing the mix at role write is right under both.

Also landed, and not anticipated here: reconciler ids now carry their credential class
(`token:` / `spaces_key:`), a failed listing of one class no longer fails the whole pass, the
conformance and e2e registries gained a `do (spaces_key)` variant, and the real-cloud recorder can
withhold a recording until it has been told what in the response is secret.

## The fake is validated against the SPEC, not against DigitalOcean (2026-09-15)

This is the honest gap in everything above, and it is structural rather than an oversight: the
plugin's Spaces client and `pkg/credenvelope/fakes`' Spaces endpoints were both written from **one
reading of DO's OpenAPI spec**, so every field name and status code they agree on is unverified by
construction. No in-process test can question that agreement, because both sides of it are the same
assumption.

What partially substitutes, and what it is worth:

- `TestDOFakeSpacesShapesMatchTheDocumentedAPI` (`plugins/credential-do/fake_parity_test.go`) pins
  the fake to `documentedSpacesCreateShape`/`documentedSpacesListShape` — the spec's field paths
  **transcribed as literals**, so renaming a field in the fake cannot quietly keep the test green.
  That catches the fake drifting from the spec. It cannot catch the spec being wrong.
- `testdata/cloud-real/` holds **four** recordings, all from the 2026-08-21 token run
  (`GET`/`POST /v2/tokens` 403, `GET /v2/account` 200 and 403). **There is no Spaces recording**, so
  `TestDOFakeMatchesRecordedRealResponses` has nothing Spaces-shaped to compare.

**One thing can be done without a credential, and doing it found three defects (2026-09-15).** The
transcription is only as good as the reading behind it, so the fake was re-checked against DO's
*published* spec rather than against the notes taken from it. All three were about **pagination**,
which the first reading missed entirely:

1. **The fake answered every listing in one page.** DO defaults `per_page` to **20** and caps it at
   **200**, and returns `keys` + `links.pages.next`/`.last` + a required `meta.total`. The fake
   returned a bare `{"keys": [...]}` with everything in it. Fixed by `paginateDO` in
   `pkg/credenvelope/fakes/respond.go`. It also had to start **sorting** — paging over Go's
   randomised map iteration puts one key on two pages and another on none, which would have made a
   correctly-paging client look broken.
2. **The client read one page and called it the account's holding.** `ListSpacesKeys` issued a
   single unparameterised `GET`, so against real DO it would have seen **20 of up to 200** keys.
   That is the worst place in the plugin for a truncated listing: a Spaces key has **no upstream
   expiry**, so the owner-tag reconciler is the only thing that ever reclaims a leaked one, and an
   orphan it never sees lives forever while still consuming the cap. It now walks every page and
   returns **all-or-error** — never a partial listing, because the reconciler cannot tell a missing
   key from a deleted one. It requests pages by *number* rather than following `links.pages.next`,
   because that URL is response-supplied and the request carries the minter's bearer token.
3. **`documentedSpacesListShape` didn't mention `links` or `meta` either** — the same missed reading,
   which means the first real recording's parity check would have failed on a field the fake never
   sent.

Note the ordering the fix required: the client's own paging test **passed vacuously** while the fake
still returned all 45 seeded keys in one page. The fake had to be corrected *first* before the client
test could fail honestly. That is the failure mode a fake exists to prevent, reproduced in miniature
— and the reason the remaining gap above is worth the words it gets.

The wiring for closing it is already in place and needs no further work: that test carries three
standing branches (create → 201, list → 200, delete → 204) that compare **by shape**, since a
Spaces body's values are the account's own and a scrubbed one cannot be compared byte-for-byte.
The first successful `make test-cloud-real-do-spaces` writes the recordings, and from then on the
ordinary credential-free `go test` checks the fake against DigitalOcean's real answers.

**The only missing input is a DO PAT holding the `spaces_key` scopes**, in `.env.cloud-real`.
Specifically *not* a blocker, contrary to the earlier assumption that the proxy EC2 instance would
be needed: `api.digitalocean.com` is directly reachable from the dev environment (checked
2026-09-15 — unauthenticated `GET /v2/spaces/keys` answers 401 from `Edge-Gateway`, no proxy
configured or required). See the routing table added to
[`do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md), which used that
reachability to retire the 404 — but proves routing only, never entitlement.

Two things will remain unvalidated even after a successful run, and both are declared rather than
hidden:

- **Credential usability.** The probe does not authenticate against the S3 endpoint with what it
  minted — that needs a SigV4 signer this repo has no dependency for, and it would answer a
  question about Amazon's signing algorithm rather than about this plugin. Unlike the AWS probe,
  which *does* use its credential. The probe checks that the endpoint derived for the region
  resolves, and stops there.
- **Whether DO validates a grant's bucket exists.** The probe's default bucket deliberately need
  not exist, because `checkGrantPrivilege` checks the privilege shape and nothing else. If DO refuses a
  grant on an absent bucket, that is a finding about *role writes* — a role passing every gate and
  failing every issuance.

## Implementation notes

- ~~**Credential kind already exists.** `credenvelope.KindKeySecret` is the access-key/secret-key
  shape. Do not add a kind~~ — **overridden**, see above. The rest still holds: do not reuse
  `KindScopedToken`, because `TestOneCredentialKindMeansOneKeySet` in `conformance/` exists
  precisely to stop one kind covering two key sets.
- ~~**Field naming is a decision, not a detail.**~~ Decided: AWS-style spellings, because the kind
  is named for the protocol rather than the vendor. `Harness.CredentialKeys` declares all four and
  the `lease` category holds the plugin to them.
- **Scope shape.** Grants are per-bucket, so a role declaring scopes needs a bucket as well as a
  permission — which is a different `ScopeKind` from `credential-do`'s current one. That is the part
  most likely to need thought rather than typing. *(Built as `ScopeKindGrants`.)*
- **The capability probe fits naturally.** A mint-then-delete probe against `/v2/spaces/keys` is
  cheap, needs no login, and leaves no residue — unlike the console driver, where a probe costs an
  interactive TOTP handshake.
- **Do not** add a `consent_required` error code. It was requested by a consumer that turned out not
  to use it, and no definition of what it would signify exists.
- **Do not** touch the console driver. It lives in a different repository, mints API tokens through
  the private GraphQL API, and is out of scope here.

## Evidence

| Claim | Where |
|---|---|
| Endpoint, schema, scopes, secret-once | `digitalocean/openapi` published spec: `specification/resources/spaces/{key_create,models/key,models/grant,models/key_create_response}.yml` |
| Scope table | `docs.digitalocean.com/reference/api/scopes/` |
| Production use with a bearer PAT | the private upstream service's DO credential module and its unit tests (outside this repo) |
| Consumer credential shape | that service's DO credential schema (outside this repo) |
| `/v2/tokens` fence, and its absence from the spec | [`docs/known-issues.md`](known-issues.md) KI-009; `plugins/credential-do/testdata/cloud-real/POST_v2_tokens_403.json` |
| Reference plugin cannot issue | [`docs/known-issues.md`](known-issues.md) KI-009 |
| Prior contested verdict being corrected | [`docs/object-storage-credential-audit.md`](object-storage-credential-audit.md), Revision 2 |
