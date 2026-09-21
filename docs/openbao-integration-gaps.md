# What testing the plugins in isolation from OpenBao does not cover

**Status:** assessment 2026-08-21. Authoritative for what the test layers below
each prove, which gaps the `e2e/` module closes, and which remain open (with
where they are tracked).

Every test in this repo before 2026-08-21 either drove a backend **in-process**
(`logical.InmemStorage`, `b.HandleRequest` called directly) or checked only that
a plugin **registers** in a live server. Neither exercises the two things
production actually depends on: the plugin *process* boundary, and OpenBao
*core* (mount table, expiration manager, plugin lifecycle). This document
records the resulting gaps, found by auditing what the code reads from `req`,
`conf` and `resp.Secret` versus what the tests can populate.

## The layers

| Layer | What it drives | What it can prove |
|---|---|---|
| plugin unit + fake-backed tests (`plugins/*/`) | `logical.Backend` in-process, `httptest` cloud fake | upstream request shape, per-cloud vocabulary |
| conformance table (`conformance/`, suites in `pkg/plugintest`) | same, × all ten plugins | cloud-agnostic invariants: reload-from-storage, `Initialize`, envelope/lease agreement, revoke idempotence, capability probes, reconciler safety |
| **`e2e/` (new)** | **plugin binary as a child process of a live `bao server -dev`, driven over HTTP** | **lease lifecycle through the expiration manager, plugin RPC round-trip, core-assigned `req.ID`, `bao plugin reload`** |
| `make smoke-test` | live `bao`, register + enable only | the binary exists, `Factory` does not panic, the RPC handshake matches |
| `cloud_real` build tag (DO, AWS) | the plugin's own client against the **real cloud API**, with a real credential | whether the cloud accepts the plugin's actual mint shape, whether the credential it returns works, and what the fake gets wrong; nothing about the other eight clouds |

## The gaps

### G1 — nothing exercised a plugin *as a plugin* — CLOSED by `e2e/`

In-process tests share the test's address space with the backend, so the plugin
RPC boundary, the mount table and the expiration manager were all absent.
`make smoke-test` (`scripts/registration-smoke-test.sh`) starts a real server
but stops at `bao secrets list | grep -q "^smoke-<name>/"`.

**Closed for 7 of 10 clouds** by the `e2e/` module: config → minter set → role →
`read creds/<role>` → lease lookup → renew → revoke → `plugin reload` → re-issue →
`revoke-upstream` (dry run, then the purge, then progress), against a plugin binary in a
live dev server, with the cloud fake in the *test* process so upstream state can be
asserted directly. The purge is last because it needs live credentials issued through the
RPC boundary to delete, and what this layer adds over conformance there is the wire: the
report's numbers arrive as `json.Number`, and a refusal reaches a client wrapped in the API
client's own request context rather than as a bare `<code>: <message>` string. AWS, GCP and OCI are declared
gaps in the e2e table — see G8.

A cloud contributes a **subject** rather than a row, so the nine driven subjects come from
seven clouds: `credential-do` appears three times, once per credential type. The third of
those — `spaces_key_rotated`, a credential the role owns and every reader shares — is what
the layer exists for, because three of its properties cannot be produced in process. A
`framework.Secret` registering no `Renew` has to reach **core's expiration manager** as a
genuinely non-renewable lease, so `bao lease renew` is refused rather than extending a lease
past the moment the shared key is deleted. A **third serialized secret type** has to dispatch
its own revoke, where the per-lease Spaces callback beside it would delete the key every
other reader is holding. And **re-serving has to survive `plugin reload`**, which is where
the role's stored record stops being a struct in memory. It is also the row where the two
facts about deletion come apart — a lease ending deletes nothing, while `revoke-upstream`
still deletes what the role issued — so the scenario asserts them separately rather than
inferring one from the other.

### G2 — background workers are never started by `Factory` — CLOSED (KI-007), one residual

`startWorkers` was called from `pathConfigWrite` and `pathMinterSetWrite` only;
no `Factory` called it. Every `backend.go` mentioned it in a comment and none
invoked it. So after any plugin reload, mount remount or raft leader failover, the
health-check, metrics-flush and reconciler workers (and OCI's rotation worker)
stayed dead until an operator re-wrote `config` or a minter set — silently, since
issuance itself kept working.

Invisible in-process because every test writes config, which starts the workers
as a side effect.

**Closed:** all ten plugins now set `InitializeFunc: b.initialize`, which loads
config + minter sets from `req.Storage` and then starts the workers. Core calls it
after mount setup, unseal and plugin reload. Chosen over calling `startWorkers`
from `Factory` so a config-less construction still makes no network calls. See
**KI-007** in [`known-issues.md`](known-issues.md) and the decision note in
[`decisions.md`](decisions.md).

**Residual:** the `reload` category's `InitializeRehydratesAndIssues` subtest
asserts the hook exists, is idempotent, does not error and leaves the backend able
to issue — it does **not** assert worker *liveness*. Proving a health check
actually ran needs a clock seam or a bounded poll in every harness; not built.

### G3 — KI-001 is still open on AWS, GCP and OCI — CLOSED

KI-001 ("config not reloaded in `Factory`") was fixed by adding `loadConfig` to
the seven HTTP-fake plugins. **AWS, GCP and OCI never got one.** `b.config` plus
`b.region` / `b.project` are assigned only in `pathConfigWrite`
(`plugins/credential-aws/path_config.go:122,124`,
`plugins/credential-gcp/path_config.go:85,87`,
`plugins/credential-oci/path_config.go:134,135`); their `Factory` calls
`loadAllMinterSets` and nothing else.

The `reload` conformance category runs on all ten and passes, because it cannot
see this: the injected fake clients ignore region/project, and a `nil`
`b.config` is silently defaulted by nil-receiver methods
(`pkg/cloudconfig/config.go:34`). The observable production effects are an
STS/IAM call built with an empty region, and `startWorkers` returning early on
`cfg == nil` (G2) even after a config write elsewhere in the cluster.

**Closed:** all three now have a `loadConfig`, called from `Factory` *and* from the
new `InitializeFunc` (G2). AWS persists `region` + `sts_endpoint` and GCP persists
`project` in a side `config_meta` storage entry — the DO pattern — because
`cloudconfig.PluginConfig` has no field for them; OCI rehydrates its region so the
signing client stops falling back to `us-ashburn-1` after a failover.

**Residual:** the shared suite still cannot *catch* a regression here, for the same
reason it could not see the original bug. An assertion strong enough must depend on
a config-derived value — either the harness asserting the reloaded backend's config
read-back, or (better) the e2e layer reaching the cloud through an endpoint the
config supplies, which is exactly what AWS/GCP/OCI cannot do today (G8). So this
gap is fixed in the code but not yet fenced by a test.

### G4 — `req.ID` is populated by core, and seven plugins name credentials from it — PARTLY CLOSED by `e2e/`

The upstream credential name comes from the lease request ID: DO, UpCloud,
Exoscale, Azure (`fmt.Sprintf("cloud-creds-%s-%s", roleName, req.ID)`), AWS
(session name, truncated at `maxSessionNameLen`), Akamai (`leaseShortID(req.ID)`),
Vultr (`buildUserIdentity` → `cloud-creds-<role>-<short>@<domain>`). In-process
tests either leave `req.ID` empty or set it themselves, so neither its real shape
(a UUID) nor uniqueness across reads was ever proved.

`e2e/` issues twice per cloud and asserts two distinct leases, two distinct
credentials and two distinct upstream entities. Still uncovered: concurrent
issuance, and the per-cloud name-length/charset limits under a real UUID
(Akamai's truncation and Vultr's email construction are the tight ones).

### G5 — lease semantics are core's, and were only ever asserted as struct fields — PARTLY CLOSED by `e2e/`

The plugins set `resp.Secret.TTL` / `.MaxTTL` / `Renewable` and let core do the
rest. Nothing in the repo reads `System().MaxLeaseTTL()` or
`System().DefaultLeaseTTL()` (zero occurrences), so a role TTL above the mount's
or the system's `max_lease_ttl` is silently clamped by core — and the plugin's
envelope `expires_at`, computed from the *role* TTL, would then outlive the
lease. That is an OBC-002 violation reachable purely through mount tuning, with
no plugin-side error.

`e2e/` asserts the lease OpenBao actually created: a non-empty `lease_id`, a
`lease_duration` equal to the role TTL, and `renewable` matching each cloud's
documented contract ([`ttl-semantics.md`](ttl-semantics.md)) — renew *succeeds*
where the credential's expiry is not fixed at mint and *fails* where it is.

**This is the gap that paid for the layer immediately: it found KI-008.** Six
plugins advertised `renewable: true` while renewal always failed, and OpenBao
*revokes* a lease whose renewal fails — so a client following the advertisement
destroyed its own credential. The cause was `framework.Secret.Renewable()` being
`(Renew != nil)`: KI-005 had made the callbacks refuse, but leaving them
registered kept the flag true. The six now register no callback.

The permanent guard is in-process, not in e2e: the new **`lease` conformance
category** (`pkg/plugintest/lease.go`) asserts, for all ten plugins, that the
envelope and the lease agree on renewability *and* on TTL, that a non-renewable
lease is refused by the framework with `ErrUnsupportedOperation`, and that
`internal_data` survives a JSON round trip (G6, without needing a live server).
It caught a second divergence on the spot: AWS and GCP built the lease from the
role TTL while publishing the cloud's real expiry, so a 900s lease named an 899s
credential — both now derive the lease from the upstream expiry.

Still uncovered: the mount-clamping case above (needs a mount tuned below the role
TTL), and revocation driven by natural lease expiry rather than an explicit
revoke.

### G6 — the plugin RPC boundary JSON-round-trips everything — CLOSED by `e2e/`

In production `resp.Data` and the lease's `internal_data` are serialized between
the plugin process and core; in-process tests hand the same Go values straight
back. A `time.Time`, `time.Duration` or `int64` that survives in-process can
return as an RFC3339 string or a `float64` — and `internal_data` is what revoke
reads to find the upstream ID, so a coercion bug there breaks revoke only in
production. (`pkg/credenvelope/envelope.go:74-91` is deliberately JSON-safe;
nothing tested that it stayed so, or that each plugin's `internal_data` is.)

`e2e/` reads the envelope back over HTTP and revokes through core, so both
directions cross the real boundary.

### G7 — core lifecycle hooks are neither implemented nor exercised — PARTLY CLOSED

`InitializeFunc` is now set by all ten plugins (G2 / KI-007). The other three
hooks — `PeriodicFunc`, `Invalidate`, `SpecialPaths` — are still absent
repo-wide. Consequences, in order of significance:

- **No `Invalidate`.** A config or minter-set write on one node does not
  invalidate the in-memory snapshot on the others; peers serve stale minters
  until they are reloaded. This is precisely the hazard `minter_retire_grace`
  exists to survive (see [`decisions.md`](decisions.md)) — the grace period is
  the mitigation for a missing invalidation, not a substitute for it.
- **No `SpecialPaths`.** `minter-sets/<name>` accepts long-lived cloud
  credentials and is not declared root-protected or seal-wrapped; it is
  protected by ACL policy alone.
- **No `PeriodicFunc`.** Worker cadence is hand-rolled (`pkg/worker`), which is
  why G2 was possible at all — core would have called `PeriodicFunc` on a
  reloaded backend without a config write. `InitializeFunc` closes the symptom;
  the hand-rolled cadence remains.

Accepted for now (each is a design change, not a test gap), recorded so the
next audit does not rediscover them.

### G8 — AWS, GCP and OCI cannot be driven end-to-end at all — OPEN, declared in the e2e table

They use in-process client injection, not an HTTP endpoint, so a plugin running
as a child process has nothing to point at a fake:

| Cloud | Endpoint override | What e2e would need |
|---|---|---|
| AWS | `sts_endpoint` **exists** (`plugins/credential-aws/path_config.go:55`) | a fake STS (SigV4-accepting, XML `AssumeRole` response) in `pkg/credenvelope/fakes/` — the smallest of the three |
| GCP | none | an override for the IAM Credentials / OAuth2 token endpoints, plus a fake that accepts a signed JWT |
| OCI | none, **and request signing is a stub** — `plugins/credential-oci/oci_client.go:48-62` returns `upstream_auth_failed: OCI request signing not implemented in this build` for all four methods | working signing first; OCI cannot be exercised against anything real today |

Declared as skips with these reasons in the e2e registry, so the matrix prints
them rather than the table quietly covering seven clouds and claiming ten.

### G9 — `cloud_real` carried nothing — PARTLY CLOSED on DigitalOcean and AWS, still open for eight clouds

As found: `grep -rl 'go:build cloud_real'` returned nothing, so the documented
real-cloud test ran zero tests and the claim the fakes make — that they resemble
the clouds they stand in for — was untested. G8's OCI signing stub is the class of
thing that hides behind that.

**Closed for DO (2026-08-21).** `plugins/credential-do/real_cloud_test.go` is the
first file to carry the tag (`make test-cloud-real-do`). It drives the plugin's own
`doClient` against real DO with a real PAT, mints and deletes real tokens under the
owner-tag prefix, and records every response through a fail-closed scrubber into
`plugins/credential-do/testdata/cloud-real/`. It produced, in two runs, findings
neither the spec pass nor any fake could reach: the health check `GET /v2/account`
is 403 for a scoped PAT, one fake correction (DO's real 403 body), and — decisively
— **KI-009**: `POST /v2/tokens` is refused for a *full-access* PAT too, from
DigitalOcean's edge gateway (`X-Response-From: Edge-Gateway`) rather than from a
service, while eleven other endpoints on the same token are served normally. The
reference plugin cannot mint against real DigitalOcean
([`known-issues.md`](known-issues.md), and R1 in
[`do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md)).

That is what this layer is *for*, and it is worth being blunt about how the layers
compare: the in-process table, `e2e/`, the fakes and a careful read of DO's
published spec all agreed the mint path was sound. It is not. Only a real credential
against the real API could tell "undocumented" from "forbidden", and the discriminator
was a response header, not a status code.

**Closed for AWS (2026-08-21), and it is the contrasting case.**
`plugins/credential-aws/real_cloud_test.go` (`make test-cloud-real-aws`) drives the
plugin's own STS client — built by the plugin's own `newRealSTSClient`, shaped by its
own `buildAssumeRoleInput`/`probeAssumeRoleInput` — against real STS with a real IAM
user's access key. The recorder is injected **per call** through the options
`STSClient` already exposes, so no production seam exists for the test's benefit.
Everything the plugin claims held: the capability probe's shape is accepted, session
tags are accepted, the credential AWS returns **authenticates**, and the granted
expiry equals the requested TTL exactly (15m→15m, 30m→30m) — which is the assumption
the whole AWS TTL contract rests on, since an STS session cannot be revoked.

It still found a defect on its first run: **KI-010**. AWS refuses an out-of-range
duration with `<Type>Sender</Type><Code>ValidationError</Code>`, and
`classifyAWSError` has no branch for it, so a caller's invalid request is reported as
`error_code: internal` *and* recorded as a fault against a healthy minter. That is
the surfacing behaviour of a gap neither write-time gate can see: the capability
probe pins its request to AWS's 900s floor, so a target role whose
`MaxSessionDuration` is below a role's TTL passes verification and fails every
issuance. The probe **declares** that gap rather than skipping it, and takes an
optional `CLOUDREAL_AWS_LOWCAP_ROLE_ARN` to turn the declaration into a live
assertion.

Two clouds in, the layer's record is one upstream blocker and one code defect,
neither reachable from a fake — because a fake answers with whatever the plugin's
authors believed. Fixture parity had to be built differently here: AWS is an
injected-client plugin (G8), so there is no HTTP-level fake to replay bodies
against, and `plugins/credential-aws/fake_parity_test.go` instead holds
`fakeSTSClient` to the *set of elements real STS sends* and re-applies every scrub
gate to the committed recordings.

**A third probe exists and has never been run (2026-09-15).**
`plugins/credential-do/real_cloud_spaces_test.go` (`make test-cloud-real-do-spaces`)
probes the credential type the plugin can actually issue — `POST /v2/spaces/keys` — and
it is written to answer four assumptions that no fake can test, because the fake and the
plugin were written from one reading of the same spec and therefore agree by
construction: that the endpoint answers a bearer PAT with `201`, that the key material
is under `key.access_key`/`key.secret_key` (a wrong name mints successfully and hands
back an *empty* credential whose access key the lease also cannot record, so it is
unrevocable), that the list envelope is `keys` alongside `links` and a required
`meta.total` (a wrong one makes every listing decode as empty, silently disabling orphan
reclamation for a credential with no upstream expiry), and that `DELETE` answers exactly
`204` (anything else makes every revoke look failed — the KI-002 class).

It has **not been run**: no DO token is reachable from the development environment, and
the probe fails rather than skips without one, by the rule this layer is built on. So the
Spaces credential type currently sits exactly where the token type sat before
2026-08-21 — every layer below the real cloud agrees it works, and `credential-do`'s
*verified* real-cloud status is unchanged. Two things reduce the
exposure in the meantime: the probe withholds its recordings until it has been told what
in the response is secret (so a field name nobody anticipated cannot leak into a public
repository), and `fake_parity_test.go` pins the fake's Spaces shapes to literals written
from DO's published spec — weaker than a recording, and labelled as such in the test.

**What is still open, and should not be glossed:**
- **Nine clouds have no real-cloud test at all.** DO was chosen first because its
  mint endpoint is undocumented, so it carried the most assumption risk — and that
  judgement was vindicated in the worst way. The same class of surprise is
  unexcluded on the other nine.
- **Nothing runs it automatically** — there is no CI job, so this is an on-demand
  test, not coverage that defends itself. (Fixture parity *is* wired: DO's
  recordings are replayed against the fake by `fake_parity_test.go` in ordinary
  credential-free `go test`, and drift fails the build. That mechanism is
  DO-shaped and not yet generalised.)

The plan for the rest (disposable accounts, CI secrets, record/replay so real
interactions become durable fixtures) remains
[`free-account-viability.md`](free-account-viability.md).

### G10 — the identity store was read by every in-process test through a double — CLOSED for the key that matters (2026-09-21)

Caller lineage (see [`decisions.md`](decisions.md), "Why lineage is read from the identity store and
enforced at issuance") rests on one factual claim about OpenBao: that `custom_metadata` written onto
an entity ALIAS is returned by `SystemView.EntityInfo` to a plugin running in **another process**.

Nothing in the conformance layer could check that, and the shape of the gap is worth naming because
it is the same one G1 and G6 describe. Every in-process case supplies its own `logical.SystemView`
via `Harness.SystemView`, so twelve subjects × five lineage cases fence the plugin's USE of the
interface and say nothing whatever about core's implementation of it. Had real aliases dropped
`custom_metadata` across the plugin gRPC boundary, all sixty cases would have stayed green while the
feature recorded nothing on any cloud — an absent field looking exactly like a passing test, which is
this repository's characteristic failure.

`pkg/baotest/scenario.go` therefore writes the claim for real against a live `bao`: create a parent
entity, log in as a unit over AppRole, write `cloud_creds_parent_entity_id` and `cloud_creds_unit_id`
onto the login's entity alias, read a credential as that unit, and assert the plugin published the
parent through `issued/`. It runs on all eight driven subjects that keep a per-credential record
(`do-spaces-rotated` gates out: a shared credential's record was written by the rotation that minted
it, so it names no caller). It confirms empirically what `identity.ToSDKAlias` promises by
inspection, and it asserts `requested_by_lineage_source=alias_custom_metadata` rather than merely
non-empty — because a login rewrites alias `metadata` on every use, so silently falling back to that
source would substitute a volatile value for a deliberate claim and still look correct.

**What remains unproven.** That a real fleet can carry it: the assertion writes one claim for one
unit against a dev-mode server, and says nothing about the cost of one privileged identity write per
unit at scale, nor about `identity/entity/merge` making a recorded parent id vanish legitimately —
which a `live_parent` role would read as a deleted parent and refuse. Fail-closed, and not exercised.

## Summary

| Gap | Status | Tracked |
|---|---|---|
| G1 plugin never run as a plugin | closed for 7 clouds | `e2e/` |
| G2 workers not started by `Factory` | **closed** (`InitializeFunc`); liveness not asserted | KI-007 |
| G3 KI-001 still open on AWS/GCP/OCI | **closed** in code; no shared-suite guard (needs G8) | KI-001 |
| G4 core-assigned `req.ID` | partly closed | `e2e/`, remainder here |
| G5 lease semantics via core | partly closed; **found KI-008**, now fenced by the `lease` category | KI-008, `e2e/` |
| G6 RPC JSON round-trip | closed for 7 clouds e2e, all ten in the `lease` category | `e2e/`, `pkg/plugintest/lease.go` |
| G7 no `Invalidate`/`SpecialPaths`/`PeriodicFunc` | partly closed (`InitializeFunc` landed); rest open, accepted | here |
| G8 AWS/GCP/OCI not e2e-reachable | open | e2e registry skips |
| G9 `cloud_real` tag unused | **partly closed** (DO probe found KI-009 — the reference plugin cannot mint against real DO; AWS probe found KI-010 and confirmed STS honours requested TTLs exactly); eight clouds open, no CI | audit #7, [`free-account-viability.md`](free-account-viability.md), [`do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md), [`known-issues.md`](known-issues.md) |
| G10 identity metadata assumed to reach a plugin | **closed for alias `custom_metadata`** (`pkg/baotest` writes a real claim and asserts it reaches `issued/`); a real fleet has never run it | here, [`decisions.md`](decisions.md) |

Two of the three live defects this audit found (G2/KI-007, G5/KI-008) were
invisible to every pre-existing test and were found within an hour of the `e2e/`
layer existing. The third (G3) was found by reading what the new layer *could not*
reach. That is the argument for keeping all three layers rather than treating the
conformance table as sufficient.

## The harness is importable (2026-08-23)

The live-server harness now lives in **`pkg/baotest`** as an ordinary package, and
`e2e/` is a consumer of it. Before, all of it was in `e2e/`'s `_test.go` files, which
means no other module could reach it — including a separate repository holding a plugin
that has to satisfy the same contract.

That matters because a harness which cannot be imported gets copied, and a copy
diverges silently. It is the same reason the conformance suites live in
`pkg/plugintest` rather than in `conformance/`.

What an external consumer needs:

| Want | Import | Internal deps to `replace` |
|---|---|---|
| The ten conformance categories | `pkg/plugintest` | `pkg/credenvelope` |
| The ten cloud fakes | `pkg/credenvelope/fakes` | (part of the `credenvelope` module) |
| A live OpenBao with plugin binaries | `pkg/baotest` | `pkg/credenvelope` |
| The end-to-end **scenario** itself | `pkg/baotest` (`Case`, `RunScenario`) | `pkg/credenvelope` |

## The scenario is importable too (2026-08-25)

The harness (start a server, register a plugin, enable a mount) moved first; the
**scenario** — the order of the writes and every assertion over the result — followed,
as `baotest.Case` + `baotest.RunScenario`. `e2e/` is now one vocabulary file per driven
subject — nine of them, since `credential-do` contributes three — plus a registry, and
`e2e/suite_test.go` is gone.

The reason is the one the first move predicted, observed rather than reasoned about. A
separate repository wired its own end-to-end test against the same contract and asserted
six properties: the lease exists and has the right duration and renewability, the
envelope's api_version/credential_kind/minter_id, distinct credential ids, the shape
pin, revoke lowering the upstream count, and a reload still issuing. It silently omitted
the rest — that the expiration manager actually **knows** the lease (`Sys().Lookup`),
that a **second** revoke is a clean no-op (KI-002 was precisely this wedging forever),
that the envelope's `renewable` **agrees with the lease's**, that `expires_at` survives
as parseable RFC3339 and is in the future, that the role's `minter_set` reads back after
a reload, and that a refused shape pin does not mint. Nothing about it looked
incomplete; it passed.

`Case` is to this layer what `plugintest.Harness` is to conformance: a translation, not
a second implementation. It carries the three write bodies, the TTL and renewability
contract, whether revoke is hard, and a `func() int` to read the fake's count. Two
fields exist for what varies beyond a cloud's vocabulary: `Mount`/`Binary` (a separate
repository need not follow `cloud-creds/<cloud>` or `credential-<cloud>`) and
`GrantedTTLSeconds` (for an upstream that answers with a lifetime of its own rather than
the one requested — the AWS lesson, now assertable at this layer).

`baotest.Plugin` names the **Go package** to build rather than deriving it from this
repo's module path, so a caller in another module builds its own binary. `Cluster`
exposes `Client()` deliberately: the lease APIs (`Sys().Lookup/Renew/Revoke`) are the
point of the layer, and wrapping each would add nothing.

Note the Go rule this depends on: a `replace` in a *dependency's* go.mod is ignored —
only the main module's replaces count. This repo has no published tags, so a consumer
must `require` **and** `replace` every internal module in the transitive graph. The
inert replaces have been removed from every module's go.mod (321 of them, none matching
a require), so what remains is an honest statement of what each module actually needs:
`pkg/plugintest` needs exactly one.
