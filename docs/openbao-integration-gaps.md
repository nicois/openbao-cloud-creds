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
| `cloud_real` build tag | *nothing — no file carries the tag* | (intended: that the fakes resemble the real clouds) |

## The gaps

### G1 — nothing exercised a plugin *as a plugin* — CLOSED by `e2e/`

In-process tests share the test's address space with the backend, so the plugin
RPC boundary, the mount table and the expiration manager were all absent.
`make smoke-test` (`scripts/registration-smoke-test.sh`) starts a real server
but stops at `bao secrets list | grep -q "^smoke-<name>/"`.

**Closed for 7 of 10 clouds** by the `e2e/` module: config → minter set → role →
`read creds/<role>` → lease lookup → renew → revoke → `plugin reload` → re-issue,
against a plugin binary in a live dev server, with the cloud fake in the *test*
process so upstream state can be asserted directly. AWS, GCP and OCI are declared
gaps in the e2e table — see G8.

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

### G9 — `cloud_real` is a documented tag that no file carries — OPEN, tracked as audit #7

`grep -rl 'go:build cloud_real'` returns nothing; `make test-cloud-real` and the
documented `go test -tags=cloud_real ./plugins/credential-do/...` compile and run
zero tests. So the claim the fakes make — that they resemble the clouds they
stand in for — is untested, and G8's OCI signing stub proves the class of thing
that can hide behind it. The follow-up (disposable accounts, CI secrets,
record/replay so real interactions become durable fixtures) is
[`free-account-viability.md`](free-account-viability.md).

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
| G9 `cloud_real` tag unused | open, planned | audit #7, [`free-account-viability.md`](free-account-viability.md) |

Two of the three live defects this audit found (G2/KI-007, G5/KI-008) were
invisible to every pre-existing test and were found within an hour of the `e2e/`
layer existing. The third (G3) was found by reading what the new layer *could not*
reach. That is the argument for keeping all three layers rather than treating the
conformance table as sufficient.
