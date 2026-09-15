# Handover: minting DO Spaces keys, and why this repo needs it

**Date:** 2026-09-15
**Status:** research complete, implementation not started
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
legal. Full access is expressed as `[{bucket: "", permission: "fullaccess"}]`, and the spec warns
that `fullaccess` **cannot be mixed** with scoped grants — a mixed list silently prioritises
`fullaccess`, which is a privilege-escalation shape worth rejecting at role-write time rather than
passing through.

The `201` response is `{key: {name, access_key, secret_key, grants, created_at}}`, and the spec is
explicit: *"We return secret keys only once upon creation."*

### It works in production, with a plain bearer token

The Aiven management plane creates Spaces keys today with `Authorization: Bearer <DO API token>`
against `https://api.digitalocean.com/v2/spaces/keys`, and its unit tests pin the literal requests
for create, list and delete. That is the real-account evidence the object-storage audit said was
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

## Implementation notes

- **Credential kind already exists.** `credenvelope.KindKeySecret` is the access-key/secret-key
  shape. Do not add a kind, and do not reuse `KindScopedToken` — the
  `TestOneCredentialKindMeansOneKeySet` test in `conformance/` exists precisely to stop one kind
  covering two key sets.
- **Field naming is a decision, not a detail.** DO returns `access_key`/`secret_key`; the known
  consumer wants `aws_access_key_id`/`aws_secret_access_key` because it feeds an S3 client. Whatever
  this plugin emits, `Harness.CredentialKeys` must declare it, and the `lease` category will hold it
  to that. Emitting DO's names and letting the consumer rename is the more honest option; emitting
  AWS-style names is the more useful one. Pick one and write down why.
- **Scope shape.** Grants are per-bucket, so a role declaring scopes needs a bucket as well as a
  permission — which is a different `ScopeKind` from `credential-do`'s current one. That is the part
  most likely to need thought rather than typing.
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
| Production use with a bearer PAT | `aiven-core`: `aiven/logic/credentials/do_credentials.py`, `tests/unit/logic/credentials/test_do_credentials.py` |
| Consumer credential shape | `aiven-core`: `aiven/utils/credentials_schema/do_model.py` |
| `/v2/tokens` fence, and its absence from the spec | [`docs/known-issues.md`](known-issues.md) KI-009; `plugins/credential-do/testdata/cloud-real/POST_v2_tokens_403.json` |
| Reference plugin cannot issue | [`docs/known-issues.md`](known-issues.md) KI-009 |
| Prior contested verdict being corrected | [`docs/object-storage-credential-audit.md`](object-storage-credential-audit.md), Revision 2 |
