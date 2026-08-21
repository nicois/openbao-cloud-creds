# Minter capability verification

**Status:** implemented on all ten plugins (2026-08-21). Authoritative for what a
capability probe is, when it runs, what it costs on each cloud, and what it
deliberately does not do.

## The problem: health is not capability

Every plugin health-checks its minters and drives a recovery state machine off
the result. A health check answers *"is this credential live?"* — it does not
answer *"may this credential mint what the roles bound to its set ask for?"*

The gap is real on every cloud, and on several of them the health check *cannot*
close it even in principle:

| Cloud | Health check | What it cannot see |
|-------|--------------|--------------------|
| AWS | `sts:GetCallerIdentity` | AWS requires no policy to permit it at all; says nothing about `sts:AssumeRole` on the role's ARN, the role's trust policy, the external ID, or `sts:TagSession` |
| GCP | self-signed JWT → own access token | `roles/iam.serviceAccountTokenCreator` is a grant **on each target SA**; also per-scope refusals and disabled targets |
| Akamai | `GET /api-clients/self` | any live EdgeGrid credential can read itself; Akamai refuses to let a client delegate access it does not hold |
| UpCloud | `GET /1.3/account` | `can_create_tokens` is fixed at token creation and is not reported by the account endpoint |
| Azure | reads the app registration | `addPassword` needs `Application.ReadWrite.OwnedBy` **plus ownership of that app** (or `.All`) |
| DO | `GET /v2/account` | scopes are fixed at creation, DO refuses to confer privileges the creator lacks, and there is **no scope-introspection API** |
| Exoscale | `GET /v2/zone` | api-key creation right, and permission to grant the specific `role-id` a role names |
| Vultr | reads the account | Vultr refuses to grant a sub-user an ACL the creating key does not hold |
| OVH | mints a token | (nothing — on OVH minting *is* the health check; see below) |

Left unverified, an incapable minter is reported **healthy indefinitely** and
fails at the first credential read, as an upstream 403 delivered to an unrelated
caller — while the operator who introduced the problem got a `200 OK` on their
config write.

## The mechanism: a throwaway probe mint

`pkg/capability` drives a **probe**: mint a credential with the same request
shape a real issuance would use, then immediately delete it. If minting fails,
the *configuration write* is rejected, naming the minter and the affected roles.

Probes run at three points:

| Trigger | What is proved |
|---------|----------------|
| `minter-sets/<set>` write | every **active** minter in the candidate set can mint for every **enabled** role already bound to that set |
| `roles/<role>` write | every active minter of the set the role binds to can mint what *this* role asks for |
| `minter-sets/<set>/rotate`, before the commit | the rotation **successor** can mint for every enabled role bound to the set |

Role-write verification is what stops an operator defining a role whose minting
key is unsuitable. It has a deliberate side effect: **a minter set must exist and
be demonstrably capable before any role can bind to it**, which pins the
configuration order to `config` → `minter-sets` → `roles` (already the documented
flow).

Rotation verification is the point where the probe earns the most. A successor
passes its health check by construction — it was just minted — but its
privileges are *inherited* (AWS: a new access key on the same IAM user; GCP: a
new key for the same SA) or *constructed* (Akamai: grants copied from the
incumbent; Azure: a secret on one app registration while the set's roles may name
several). Health cannot tell an inheriting successor from a narrowed one; the
pre-commit probe can, and a failed probe aborts the rotation, deletes the
successor's upstream credential, and leaves the set byte-identical.

### Probes are deduplicated by mint shape

A probe is keyed on `(minter ID, mint-request shape)` — the shape being exactly
those role fields that reach the upstream mint call. Two roles that would produce
an identical mint request are proved by one probe; a set write with 8 roles and 2
minters may run far fewer than 16 probes. Failure messages still name every role
sharing the collapsed key.

Every active minter is probed, not just one, because minter selection picks
arbitrarily among a set's selectable minters: one incapable minter out of three
makes issuance fail *intermittently*, which is worse to diagnose than failing
outright.

Verification stops at the **first** failure, so an operator sees the first thing
that is wrong rather than a cascade of consequences.

## Per-cloud probes and their cost

Probe credentials are named `cloud-creds-<role>-probe-<unique>` — they carry the
owner-tag prefix, so a probe whose own delete failed is still reclaimed by the
owner-tag reconciler. Probes are never recorded in lease tracking, so the
reconciler sees them as orphans by construction. A failed *delete* does not fail
the probe: minting was what was being proved.

| Cloud | Probe mint | Dedup shape | Cleanup | Residue if cleanup fails |
|-------|-----------|-------------|---------|--------------------------|
| DO | `POST /v2/tokens` with the role's scope string | scopes | `DELETE /v2/tokens/{id}` | a PAT, reconciler-reclaimable |
| AWS | `AssumeRole` (role ARN, external ID, session tags), `DurationSeconds=900` | ARN + external ID + sorted tags | **none possible** | one 900s STS session (the AWS floor) |
| GCP | `generateAccessToken` for the role's target SA + scopes, `lifetime=60s` | target SA + scopes | **none possible** | one 60s access token |
| Azure | `addPassword` on the role's `app_object_id`, `endDateTime` +10m | app object ID | `removePassword` | a client secret, ≤10m of validity |
| OVH | `client_credentials` token mint | *(empty — see below)* | **none possible** | one 1h access token |
| UpCloud | `POST /1.3/account/tokens`, `expires_in=10m` | *(empty)* | `DELETE .../tokens/{id}` | a token, ≤10m of validity |
| Exoscale | `POST /api-key` bound to the role's `role_id` | role-id | `DELETE /api-key/{id}` | an API key, reconciler-reclaimable |
| Vultr | `POST /v2/users` with the role's ACL list | ACLs + email domain | `DELETE /v2/users/{id}` | a sub-user, reconciler-reclaimable |
| Akamai | create api client with the role's `apiAccess`/`groupAccess` | apiAccess + groupId | delete api client | an api client, reconciler-reclaimable |
| OCI | **not probed** — see below | — | — | — |

Three clouds cannot revoke what the probe mints (AWS, GCP, OVH), so on those the
probe's requested lifetime *is* the bound on what it leaves behind, and it is
pinned to the shortest value the cloud accepts: AWS's documented 900s floor, 60s
on GCP, and OVH's fixed 1h. The credential is never returned to a caller and
never recorded in a lease. Operators who cannot accept even that set
`verify_minter_capability=false`.

**OVH is the weak case, kept for uniformity.** OVH roles carry nothing that
reaches the token request — scopes come from the IAM policy attached to the
service account itself — so the probe is the same call the health check makes,
and dedupes to one probe per minter. It proves less new information than
elsewhere, but it still enforces the uniform guarantee: a role cannot bind to a
set whose minters have not been shown to mint, and a replacement minter that does
not work is rejected at write time instead of being discovered by a background
health check some minutes later.

**OCI is deliberately not probed.** OCI caps a user at **two** auth tokens, which
is the entire reason that plugin uses phased rotation instead of JIT. A probe
would have to consume one of those two tokens, so it would either fail (both
slots provisioned — the steady state) or, worse, succeed by displacing a slot a
live lease is drawing from: verification would break issuance in order to prove
issuance works. OCI's checks return `capability.ErrUnsupported`, which `Verify`
counts as *skipped* (recorded in the operator-facing log) rather than failed, so
the write proceeds. OCI needs it less urgently anyway: slot provisioning is
itself a real `create-auth-token` call made at role-write/rotation time, so an
incapable minter already surfaces as a failed provision to the operator who
configured it.

## Configuration

```bash
bao write cloud-creds/<cloud>/config verify_minter_capability=false   # default: true
```

Verification is **on by default**: the failure it prevents is silent, lands on
someone other than the person who caused it, and is expensive to diagnose from
the far end (an upstream 403 with no local explanation). The flag is read from
the backend's in-memory config snapshot, which a config write refreshes on the
node serving it — the same reload semantics as every other operational field.

Every rejection message ends with `(set verify_minter_capability=false on the
config endpoint to skip this check)`, so a probe that cannot succeed in a
particular environment — a locked-down account, a cloud-side quota, an
air-gapped test rig — is never a dead end.

Roles marked `disabled` are excluded from probing: they cannot issue, so an
incapable minter cannot hurt them, and probing them would block a set write over
a role the operator has already turned off. A stored role whose JSON cannot be
parsed is treated as not bound rather than blocking set writes.

## Failure surface

A failed probe produces a **configuration-time error response** on the write that
triggered it:

```
minter capability verification failed: minter "minter-1" cannot mint the
credential role(s) purge-only require: probe api-client creation returned 403:
you may not grant access to apiId 9901
(set verify_minter_capability=false on the config endpoint to skip this check)
```

It is not an issuance-time envelope error, so it carries no `error_code` — the
`error_code` model in [`techrfc.md`](techrfc.md) describes credential-read
responses, and this response never reaches a credential-reading client. Nothing
in the response-envelope contract changed; `api_version` stays `"2"`.

### Not done: a runtime `minter_insufficient_privilege` error code

A companion idea was considered and **excluded**: distinguishing a runtime 403 at
issuance time with a new `minter_insufficient_privilege` error code, and not
letting such a 403 drag the minter's recovery state machine to `AuthFailing`.

Excluded for two reasons. First, it is a **spec change** to the error-code model
— a new code is a contract change for every client, requiring a techrfc revision
(see the "Don't" list in `CLAUDE.md`). Second, probes largely remove the need:
the privilege gap is now diagnosed at configuration time by the operator who
caused it, so a runtime privilege 403 becomes the rare residual case (a
privilege revoked upstream after configuration). Today such a 403 maps to
`upstream_auth_failed` and does count toward `AuthFailing`, which is
conservative-but-blunt: it withdraws a minter that is live but unusable for
*this* role, and may be usable for others. That remains an open refinement, not a
gap this work claims to have closed.

## Testing

Every plugin has a `capability_test.go` covering four cases against the
cloud-fakes (never mocks): a role write rejected when the minter cannot mint, the
probe using the role's real mint shape (and the minimum lifetime on the
no-revoke clouds), a rotation rejected when only the *successor* is refused (set
unchanged, nothing retired, no upstream leak), and `verify_minter_capability=false`
skipping the probe entirely.

The "authenticates but cannot mint" shape is expressed with a dedicated fake knob
rather than a one-shot status override — e.g. Akamai's `SetUngrantableAPIID`
(create is refused only when it delegates that apiId, while `GET self` keeps
succeeding), and per-test recorders on the injected-client plugins (AWS/GCP)
that deny `AssumeRole`/`generateAccessToken` for one access key or key JSON while
the health call keeps passing.

**Superseded (2026-08-21): there is now a shared `capability` category.** This
document previously argued against one, on the grounds that "refuse a mint while
the health call keeps passing" is expressed differently on every cloud — an
ungrantable apiId here, a denied `AssumeRole` for one access key there, a
`can_create_tokens` flag elsewhere — so a uniform fake knob would be a per-cloud
lie underneath. The first half of that is still true; the conclusion was wrong.
The per-cloud part is only *how you make the minter incapable*, which is two
function values (`DenyMint`/`AllowMint`) on a harness. What must then happen — the
role write is rejected with a capability error and does **not** persist, a
rejected set rewrite leaves the live set untouched, a successful probe leaves zero
credentials upstream, a disabled role is not probed, and
`verify_minter_capability=false` skips the probe — is identical on all ten clouds
and is asserted once in `pkg/plugintest/capability.go`, run against every plugin
from the `conformance/` table (see `AGENTS.md`). The knobs live in the fakes with
the cloud's own vocabulary, exactly as before; only the assertions moved. OCI
declares the category as a skip with its reason (a probe would consume one of the
two auth tokens a user may hold).

A systemic hazard this work surfaced and closed: **a test backend that never
writes config becomes a live cloud API caller once probes exist.** Before this
change several plugins' `getTestBackend` helpers left the API base URL empty (or
the injected client unset), which was harmless while nothing minted at
config-write time. All ten now stand up a fake (or inject a succeeding fake
client) in that helper. Two AWS and two GCP tests whose injected clients fail
*on purpose* set `verify_minter_capability=false`, with a comment saying why:
they exercise issuance-time failure and recovery, not configuration-time
verification.
