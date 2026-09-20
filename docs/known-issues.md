# Known Issues / Follow-ups

Issues found during live testing and subsequent audits, each with a precise root
cause and the fix. KI-001/KI-002 came out of the original multi-cloud spike's
resilience assessment (against a live raft cluster, UpCloud) and are **RESOLVED**
(fix + red-baseline regression tests); KI-005, KI-007 and KI-008 are resolved
likewise, as are KI-010, KI-011 and KI-012. KI-003, KI-004 and KI-006 are accepted,
documented risks. Resolved entries are kept for the rationale and history.

KI-012's fix is the one thing here that is **resolved but unreleased** — it landed after
v0.5.0 was tagged, so a deployment running the published modules still has the defect.

**KI-011 is the one to read for what to do when a credential leaks**, and it is
resolved with a residual worth knowing in advance: the two levers are `disabled=true`
on the role and `roles/<name>/revoke-upstream`, and on AWS, GCP and OVH there is no
second lever at all — the role's `max_ttl` is the blast radius, so it is bought before
the incident or not at all.

KI-007 and KI-008 were both found by the new `e2e/` layer (plugin binaries driven
through a live OpenBao — see [`openbao-integration-gaps.md`](openbao-integration-gaps.md)),
which is the point of that layer: neither was visible to any in-process test, and
KI-008 was visible only because *core* acted on the lease.

**KI-009 is of a different kind from everything above it.** It is not a defect in
this repo's code but a fact about DigitalOcean, and it is the most consequential
entry here: it says the reference plugin cannot issue against the real cloud. It
was found by the real-cloud layer within its first two runs, which is what that
layer is for.

It is still true, and it is no longer a dead end. The fence is specific to
DigitalOcean's *token* management — `/v2/tokens` is absent from their published spec
entirely — while `POST /v2/spaces/keys` is fully specified, `bearer_auth`, and
callable with an ordinary PAT, as a production consumer demonstrates. So there is a
credential this plugin's existing minter can mint; the API findings behind it are in
[`cloud-credential-research.md`](cloud-credential-research.md).

**As of 2026-09-15 that credential is implemented** (`credential_type=spaces_key` on a
role), which narrows KI-009 from "the plugin cannot issue" to "the plugin cannot issue a
PAT". The narrowing rests on evidence about the Spaces endpoint, not on a run of this
repo's own probe against it — `make test-cloud-real-do-spaces` is written and has not
been run, because no DO token is reachable here. Read the KI-009 entry's status block
before citing DO as a working cloud.

**KI-010 came from the same layer's second cloud, on its first run.** Where DO's
finding was about a cloud, AWS's was about this repo's code: the plugin reported a
caller's invalid request as `internal` and counted it against the minter's health.
Two clouds in, the real-cloud layer has produced one upstream blocker and one code
defect, neither reachable from a fake — a fake answers with whatever the plugin's
authors believed.

**KI-010 is also the entry to read for how a small finding should be handled.**
Asked to check for other failure modes before spending a spec revision, the audit
found it was the *mildest* of five instances of the same defect: `upstream_timeout`
was unreachable, an unreachable cloud read as `internal`, quota errors that were not
429 read as `internal`, and a mistyped `minter_set` read as `upstream_auth_failed`.
One revision fixed all of them, and the seventh conformance category
(`error-taxonomy`) found a sixth instance — OVH's classifier had no 5xx branch —
within a minute of existing.

---

## KI-001 — `config`/`username` not loaded on backend init (credential-upcloud) — [RESOLVED 2026-05-30]

**Resolved:** `Factory` now calls `loadConfig` (before `loadAllMinterSets`) to
rehydrate config-derived backend fields from storage. Turned out to affect **7
plugins**, not just UpCloud — every HTTP-fake plugin stashed a config field
(api URL, username, region, endpoints, tenant) set only in `pathConfigWrite`.
Akamai's pre-existing `loadHost` was partial (restored `host` but not `apiURL`)
and was replaced by a full `loadConfig`. Regression: the `reload` category of the
conformance table (`pkg/plugintest/reload.go`, run from `conformance/` against all
ten plugins). Originally the injected-client plugins (AWS/GCP/OCI) could not
exercise reload through their fakes and skipped it; **that residual gap is closed
as of 2026-08-21** — `Harness.Inject` re-applies the fake client to every backend
instance, including the reload, so all ten now run the category.

**Second correction (2026-08-21):** the fix itself was also incomplete. The three
injected-client plugins (**AWS, GCP, OCI**) had no `loadConfig` at all — `b.config`
plus `b.region` / `b.project` were assigned only in `pathConfigWrite`, and their
`Factory` called `loadAllMinterSets` and nothing else. The `reload` category
passed anyway because the injected fake ignores region/project and a `nil`
`b.config` is silently defaulted by nil-receiver methods
(`pkg/cloudconfig/config.go`). All three now have a `loadConfig`, called from both
`Factory` and the new `InitializeFunc` (KI-007); AWS persists
`region`/`sts_endpoint` and GCP persists `project` in a side `config_meta` entry
(the DO pattern), because `cloudconfig.PluginConfig` has no field for them, and
OCI rehydrates its region so the signing client does not silently fall back to the
default region after every failover. Found while auditing for the e2e layer and
recorded as G3 in [`openbao-integration-gaps.md`](openbao-integration-gaps.md).

**Severity:** High — breaks issuance on every plugin reload / raft failover until
`config` is re-written.

**Symptom (observed live):** after a raft leader failover (and equivalently after
any plugin reload), issuance on the now-active node fails with
`upstream_auth_failed: all minters in set "primary" are failing`, even though the
persisted minter set and its credentials are valid and unchanged. Re-writing
`cloud-creds/upcloud/config` (re-seeding) immediately fixes it.

**Root cause:** `Factory` (`plugins/credential-upcloud/backend.go`) calls
`loadAllMinterSets` to rehydrate minter sets from storage, but it does **not**
load the operational config — specifically `b.username`. `b.username` is the
UpCloud basic-auth *username* and is set **only** in `pathConfigWrite`
(`path_config.go:82`), i.e. only when `config` is written. On a fresh backend
instance (new active node after failover, or a plugin reload), `b.username` is
`""`.

The minter's `token` (the UpCloud *password*) lives in the minter set and *is*
loaded, but basic auth with username `""` + a valid password returns **HTTP 401
AUTHENTICATION_FAILED**. Each failing read records an auth error against the
minter's recovery state machine; after `AuthFailThreshold` (30s) every minter in
the set transitions to `AuthFailing`, and `selectMinter` then returns
`all minters in set … are failing`.

This is masked in unit tests because the test setup always writes `config`
before issuing.

**Proposed fix:** in `Factory`, load `config` (and `config/username`) from
`conf.StorageView` the same way `loadAllMinterSets` is loaded, so `b.username`
and `b.config` are populated on every backend instantiation — not just on
`config` write. Sketch:

```go
if conf.StorageView != nil {
    _ = b.loadConfig(ctx, conf.StorageView)        // new: sets b.config + b.username
    _ = b.loadAllMinterSets(ctx, conf.StorageView)
}
```

where `loadConfig` reads the `config` and `config/username` storage entries
written by `pathConfigWrite`.

**Cross-cloud note:** audit the other plugins for the same pattern — any backend
field set only in `pathConfigWrite` (not reloaded in `Factory`) will be empty
after a reload. (DO's minter token is self-contained in the minter set, so DO is
likely unaffected, but plugins with separate auth config like UpCloud need the
same fix.)

---

## KI-002 — revoke retries forever when the issuing minter is gone (all JIT plugins) — [RESOLVED 2026-05-30]

**Resolved:** the 6 hard-revoke plugins (do, upcloud, exoscale, azure, vultr,
akamai) now tolerate a removed issuing minter — `pathCredsRevoke` falls back to
any healthy minter in the same set via `anyHealthyMinterInSet`, and if none
remains, no-ops (logging) and releases the lease. A related bug surfaced by the
same suite: a 404 on the upstream delete (double-revoke / already-deleted) is
now treated as success rather than an error. Rationale in `docs/decisions.md`.
Regression: the `perturbation` and `revoke` categories of the conformance table,
run against every plugin from `conformance/`. (No-revoke/soft-revoke plugins —
aws, gcp, ovh, oci — were never affected: their revoke makes no upstream call.)

**Severity:** Medium — noisy failing revokes; it leaks revoke-retry work
indefinitely.

> **Correction (2026-08-21):** the original text below said the upstream
> credential "still expires via TTL, so not a security hole". That is true only
> for the clouds whose credentials carry a native expiry (Azure, UpCloud). On DO,
> Exoscale, Vultr and Akamai the issued credential has **no upstream expiry**, so
> a credential left unrevoked persists until the owner-tagged reconciler deletes
> it — which is the real backstop, and on Exoscale/Vultr needs the manual
> `/reconcile` endpoint (KI-004). The plugins' fallback log line has been
> reworded accordingly. Full per-cloud picture in
> [`ttl-semantics.md`](ttl-semantics.md).

**Symptom (observed live):** after a minter set is changed so a previously-present
minter id no longer exists (e.g. re-seeding `primary` from minters `[good]` to
`[upcloud-primary]`), in-flight leases that were issued by the now-absent minter
fail revocation forever:

```
expiration: failed to revoke lease: ... err: minter "good" not found in set "primary" attempts=N next_attempt=...
```

OpenBao keeps retrying the revoke with backoff, but it can never succeed because
the minter used to perform the upstream `DELETE` is gone.

**Root cause:** `pathCredsRevoke` (`path_creds.go`) resolves the issuing minter via
`getMinter(minterSet, minterID)` to make the upstream delete call; `getMinter`
(`path_creds.go:208`) returns `minter %q not found in set %q` when the id is
absent, and the revoke returns that error, so OpenBao reschedules it.

**Proposed fix:** when the issuing minter is gone, the upstream credential can no
longer be actively deleted by this plugin — but it will expire on its own (these
are short-lived credentials with a native or lease TTL). So revoke should treat
"minter not found" as a **successful no-op** (optionally logging a warning),
letting the lease be released cleanly. Optionally fall back to *any* healthy
minter in the same set to attempt the delete before giving up. Either way, do not
return an error that triggers infinite retry.

**Design tension to resolve:** this slightly weakens the "revoke deletes the
upstream credential" guarantee for the minter-removed case — acceptable because
TTL expiry is the real guarantee (see the envelope/lease contract), but worth a
decision note in `docs/decisions.md`.

---

## KI-003 — Azure addPassword Graph propagation lag — [DOCUMENTED-RISK 2026-05-31]

**Status:** DOCUMENTED-RISK (audit F7, 2026-05-31). Not reproducible without a
real Entra tenant; self-heals within seconds. Consuming clients should implement
transient 401 retry rather than treating it as fatal.

**Severity:** Low — self-heals automatically within seconds; affects only the
immediate post-issuance window.

**Symptom:** a freshly-issued Azure `client_secret` may fail authentication
(typically `AADSTS7000215` or similar Entra errors) for a few seconds immediately
after issuance, even though the credential was successfully created and returned
by the plugin.

**Root cause:** Microsoft Graph `addPassword` is eventually consistent across the
Entra (AAD) directory. A password credential added to an app registration may not
be visible to authentication services for a brief period (typically a few
seconds) while the change propagates across the tenant's directory replicas.

**Guidance:** consuming clients should retry a transient 401 immediately after
issuance rather than treat it as fatal. The credential WILL work once directory
replication completes. Suggested retry pattern: on the first 401 within the
first 30s of issuance, wait 1-2 seconds and retry once; if the second attempt
also 401s, treat it as a real auth failure.

**Can NOT be reproduced against the fake:** the Azure cloud-fake
(`pkg/credenvelope/fakes/azure.go`) is an `httptest.Server` with instant
in-memory state, so it has no directory-replication lag. The phenomenon is
observable only against a real Entra tenant, and then only under specific
replication topologies.

---

## KI-004 — Exoscale/Vultr background reconciler does not auto-delete orphans — [KNOWN/ACCEPTED 2026-05-31]

**Status:** KNOWN/ACCEPTED (audit F1 residual, 2026-05-31). Safe direction (leak
over delete-live-cred). Manual reconcile with `ConfirmationHold=0` still works.

**Severity:** Medium — orphaned credentials leak until manual cleanup or natural
expiry; but TTL expiry is still enforced (short-lived credentials auto-expire
on lease end via normal revoke), so it's not a security hole.

**Symptom:** the background reconciler worker does not automatically delete
orphaned upstream credentials for Exoscale and Vultr. Orphans accumulate until
they are manually cleaned via the `/reconcile` endpoint, or (if a lease still
tracks them) deleted by that lease's revoke — they do **not** expire on their own.

**Root cause:** Exoscale's `GET /v2/api-key` and Vultr's `GET /v2/users` list
APIs return no creation timestamp — only `key-id`/`name`/`role-id` for Exoscale,
and `id`/`name`/`email`/`api_enabled`/`acls` for Vultr. The fail-closed
reconciler guard (audit F1 fix, Task 3) skips entities whose age is
unconfirmable (zero `CreatedAt`) under the 1h `ConfirmationHold`, to avoid
deleting a live just-issued credential during the create-then-track window. Since
neither cloud's lister can populate `CreatedAt`, EVERY orphan has zero `CreatedAt`
and is skipped on the background worker reconcile path.

**Guidance:**
- Use the manual `/reconcile` endpoint (which uses `ConfirmationHold=0`, so it
  deletes even zero-`CreatedAt` orphans) to clean Exoscale/Vultr orphans when
  needed.
- Or accept the leak: an orphan that still has a lease will be deleted when that
  lease revokes. Note that **neither Exoscale API keys nor Vultr sub-users have a
  native upstream expiry** — an orphan with no lease behind it (the KI-002 path,
  or a lost lease) does not lapse on its own, so manual `/reconcile` is the only
  cleanup. See [`ttl-semantics.md`](ttl-semantics.md).
- The other 4 hard-revoke plugins (DigitalOcean, UpCloud, Azure, Akamai) DO have
  list-creation timestamps and their reconcilers now auto-delete confirmably-old
  orphans normally.

**Safe direction:** this is the intended safe interim behavior for clouds without
list timestamps — better to leak an orphan (which will be revoked on lease end
anyway) than to risk hard-deleting a live credential issued in the last hour.

---

## KI-005 — TTL honesty gaps (OVH sub-1h roles; Azure/UpCloud renewal) — [RESOLVED 2026-08-21]

**Resolved:** see [`ttl-semantics.md`](ttl-semantics.md) for the full per-cloud
matrix and the changes. Summary of what was wrong and what was done:

**Severity:** Medium — an unaccounted-for live credential (OVH) and a lease that
outlived its credential (Azure/UpCloud); no privilege escalation in either case.

**Symptom 1 (OVH, credential outlives lease).** With `default_ttl=15m`, the lease
ended at 15 minutes but the OAuth2 token stayed valid for the rest of its hour:
OVH's token endpoint accepts no lifetime parameter (tokens are a fixed 1h) and
OVH exposes **no token-revoke API**, so neither mechanism the other plugins use to
bound a credential's life was available. The response envelope reported the
token's real 1h `expires_at` while the lease expired at 15m, so the two
disagreed. **Fix:** `pathRoleWrite` now rejects `default_ttl`/`max_ttl` below
3600s as well as above it, pinning OVH roles to exactly 1h.

**Symptom 2 (Azure/UpCloud, lease outlives credential — an OBC-002 violation).**
Both clouds fix the credential's expiry at mint time (`endDateTime` and
`expires_in` respectively, set from the role's default TTL) and neither can extend
it, but `pathCredsRenew` handed back another full TTL on every renewal. A renewed
lease therefore named a credential that had already stopped working. **Fix:** both
refuse renewal (matching AWS/GCP/OVH/OCI) and report `renewable: false`.

**Also corrected:** the DO/Exoscale/Vultr/Akamai revoke-fallback log line claimed
the credential would "expire via TTL"; those credentials have no upstream expiry,
so the message now names the owner-tag reconciler as the backstop (see the
correction note on KI-002).

**Not changed (accepted):** OCI's soft revoke — a rotation slot's token outlives
the lease until its scheduled rotation, by design; and the revoke-failure window
on the four clouds without a native expiry, bounded by the owner-tag reconciler
rather than by time. Both are recorded as residual gaps in `ttl-semantics.md`.

---

## KI-006 — capability-probe residue and unprobed clouds — [KNOWN/ACCEPTED 2026-08-21]

Capability verification (see [`minter-capability-verification.md`](minter-capability-verification.md))
mints a throwaway credential to prove a minter can mint. Three residual gaps come
with it, all accepted deliberately.

**Severity:** Low — bounded, short-lived, never handed to a caller; no privilege
escalation.

**Gap 1 — probes leave a credential behind on AWS, GCP and OVH.** None of the
three can revoke what the probe mints (STS sessions, impersonated access tokens
and OVH OAuth2 tokens expire on their own and have no revoke API). Each probe
therefore leaves one credential in existence that nobody holds, bounded only by
the lifetime asked for: **900s** on AWS (its documented floor), **60s** on GCP,
and **1h** on OVH (fixed, no choice). The credential is never returned to a
caller and never recorded in a lease. Operators who cannot accept this set
`verify_minter_capability=false`. Accepted because the alternative is leaving
verification off on precisely the clouds whose health checks are least
informative.

**Gap 2 — a probe whose own delete fails leaks an upstream entity until the
reconciler runs.** On the revocable clouds (DO, Azure, UpCloud, Exoscale, Vultr,
Akamai) a failed delete does not fail the probe — minting was what was being
proved. The probe credential carries the `cloud-creds-<role>-probe-` owner
prefix and is never recorded in lease tracking, so it is an orphan by
construction and the owner-tag reconciler reclaims it. On Exoscale and Vultr that
reclamation is itself still manual (see KI-004), so a failed probe delete there
needs an operator to clean up.

**Gap 3 — OCI capability is taken on trust.** OCI's two-auth-tokens-per-user cap
means a probe would consume a rotation slot, so OCI returns
`capability.ErrUnsupported` and the write proceeds with the skip logged. An
incapable OCI minter is therefore still discovered at slot-provisioning time
(a real `create-auth-token` at role write / rotation) rather than by a probe.

**Related open refinement (not a regression):** a privilege 403 seen at
*issuance* time still maps to `upstream_auth_failed` and counts toward
`AuthFailing`, withdrawing a minter that is live but unusable for one role. A
distinct `minter_insufficient_privilege` code was deliberately not added (it is a
spec change to the error-code model, and probes front-load the diagnosis) — see
[`decisions.md`](decisions.md).

---

## KI-007 — background workers never start on a rehydrated backend (all ten plugins) — [RESOLVED 2026-08-21]

**Resolved:** every plugin's `Factory` now sets
`InitializeFunc: b.initialize`, and `initialize` loads config + minter sets from
`req.Storage` and then starts the workers. Core calls `InitializeFunc` on a
backend it has just built — after mount setup, an unseal, or a plugin reload —
which is exactly the set of moments the workers were being missed. Regression: the
`reload` conformance category's `InitializeRehydratesAndIssues` subtest, which
drives `Initialize` twice (an unseal after a reload does that) and then issues.

**Severity:** High — silent. Nothing fails; the plugin serves credentials
perfectly while every background guarantee is quietly absent.

**Symptom:** after a plugin reload, mount remount or raft leader failover, no
health checks run (so the minter recovery state machine never re-probes a
recovered minter, and never withdraws a failing one), no metrics are flushed, the
owner-tag reconciler never sweeps orphans, minter age/expiry warnings stop, the
retired-sweep never deletes a rotated-out minter's upstream credential, and on OCI
the rotation worker stops rotating slots — until an operator happens to re-write
`config` or a minter set.

**Root cause:** `startWorkers` was called from `pathConfigWrite` and
`pathMinterSetWrite` only. Every `backend.go` mentioned it in a comment; none
invoked it. A fresh backend instance therefore had no workers, and there was no
hook that would ever start them. Invisible to every in-process test because the
test setup always writes config, which starts the workers as a side effect.

**Why `InitializeFunc` and not `Factory`:** `Factory` also runs for constructions
that have no business making network calls (a config-less test backend, tooling),
and CLAUDE.md's rule against a config-less backend reaching the real cloud API
applies. `Initialize` runs on the active node with storage available, so
`initialize` can rehydrate first and `startWorkers` still early-returns when
`b.config == nil`. Rationale in [`decisions.md`](decisions.md).

**Residual gap:** the conformance subtest asserts the hook exists, is idempotent,
does not error, and leaves the backend able to issue. It does **not** assert worker
*liveness* (that a health check actually ran), which would need either a
clock-injection seam or a poll with a timeout in every plugin's harness. Recorded
as the residual on G2 in [`openbao-integration-gaps.md`](openbao-integration-gaps.md).

---

## KI-008 — lease advertised `renewable: true` while renewal always failed, and OpenBao revokes a lease whose renewal fails (6 plugins) — [RESOLVED 2026-08-21]

**Resolved:** the six plugins whose credential expiry is fixed at mint (**AWS,
GCP, OVH, Azure, UpCloud, OCI**) no longer register a `Renew` callback at all, so
the lease correctly advertises `renewable: false` and core refuses renewal before
any plugin code runs. Regression: the new `lease` conformance category
(`pkg/plugintest/lease.go`), which asserts the envelope and the lease agree on
both renewability and TTL, on all ten plugins.

**Severity:** High — a client following the plugin's own advertisement destroys
the credential it was trying to keep.

**Symptom (observed in the e2e layer, in core's own log):** issuing against
UpCloud/Azure/OVH returned a lease with `renewable: true`; `bao lease renew`
against it failed, and the expiration manager then **revoked the lease** — hard-
revoking the upstream credential on the clouds that hard-revoke. The client had
done nothing wrong: it read `renewable: true` and renewed.

**Root cause:** two compounding facts.

1. `framework.Secret.Renewable()` is defined as `s.Renew != nil`, and that is the
   flag copied onto the `logical.Secret`'s lease options. KI-005 had made the
   renew *callbacks* refuse (return an error) — which correctly stopped a lease
   outliving its credential — but the callbacks were still registered, so the
   lease kept saying `renewable: true`. Refusing inside the callback is invisible
   to the flag.
2. OpenBao's expiration manager treats a failed renewal as grounds to revoke the
   lease, not as a no-op. So the "safe" refusal was strictly worse than either
   honest option.

Invisible in-process: unit tests called the renew handler directly and asserted it
errored — which it did. Only a real expiration manager turns that error into a
revocation, which is why this needed the e2e layer to surface.

**Fix detail:** removing the callback (rather than keeping it and setting
`resp.Secret.Renewable = false`) is deliberate: the callback's absence is the
single source of truth the framework reads, and it cannot drift from a separately
assigned field. Each plugin carries a comment at the empty `framework.Secret`
saying why, naming that cloud's reason (STS `DurationSeconds`, GCP `lifetime`, the
fixed OVH hour, Azure `endDateTime`, UpCloud `expires_in`, an OCI slot's next
scheduled rotation). DO, Exoscale, Vultr and Akamai keep their callbacks and stay
genuinely renewable — renewal there just defers a revoke
([`ttl-semantics.md`](ttl-semantics.md)).

**Found alongside (same fix batch):** the `lease` category immediately caught a
second, quieter divergence on **AWS and GCP** — the lease was built from the
role's TTL while the envelope published the expiry the cloud actually returned, so
a 900s lease named an 899s credential. Sub-second truncation and the mint round
trip mean the lease could outlive the credential (OBC-002). Both now derive
`resp.Secret.TTL` from the upstream expiry, with a one-second floor (a zero TTL
means "use the mount default" to core, which is never what a near-expiry
credential wants).

---

## KI-009 — `POST /v2/tokens` is fenced off from PAT auth, so `credential-do` cannot mint a TOKEN against real DigitalOcean — [CONFIRMED-BLOCKER 2026-08-21, SCOPE NARROWED 2026-09-15]

**Status:** confirmed against a real account and **not fixable in this repo**. The
plugin is retained as the shape reference and for the fakes; its **token** credential
type is not presented as production-viable. See
[`decisions.md`](decisions.md) ("Why `credential-do` stays the reference
implementation even though it cannot mint").

**Scope narrowed 2026-09-15: this is about one credential TYPE, not the plugin.** A
`credential-do` role now selects `credential_type=token` (the fenced one) or a Spaces
access key — `credential_type=spaces_key` per lease, or `spaces_key_rotated` shared by a
role since 2026-09-16 — an S3-compatible credential minted through
`POST /v2/spaces/keys` — a path that is in DigitalOcean's published spec, declared
`bearer_auth`, and reported to work in production with a plain bearer PAT
([`cloud-credential-research.md`](cloud-credential-research.md)). So "credential-do cannot
issue against real DO" is no longer the right summary; "credential-do cannot issue a
PAT" is. Everything below about the fence itself stands unchanged, and the fence is
still what the real-cloud probe pins.

**What has NOT been verified:** that `POST /v2/spaces/keys` answers *this* repo's
bearer PAT. The evidence for it is a published spec plus another service's production
use, and the contradicting evidence is DigitalOcean's own product docs plus an earlier
real-account 404 — the same spec-versus-docs contest KI-009 itself settled the other
way. `make test-cloud-real-do-spaces` exists to settle it and has not been run (no DO
token is reachable from the development environment). If that probe answers 403 from
`Edge-Gateway`, this entry's original scope was right after all and the plugin has
nothing it can mint; the probe says so in those words.

That gap is not hypothetical. Re-reading DO's *published* spec on 2026-09-15 — the one
check that needs no credential — found the Spaces listing unpaginated in both the fake
and the client, which against real DO would have shown the reconciler **20 of up to
200** keys, on the one credential type with no upstream expiry to fall back on
(fixed; [`decisions.md`](decisions.md), "Why the Spaces listing pages"). Two sides
written from one reading of a spec agree with each other whatever the spec says, so
treat every remaining Spaces field name and status code as of that provenance until the
probe runs.

**Re-verified 2026-08-31, and the fence is NOT origin-dependent.** The same PAT was
used from two different network origins in the same minute: `/v2/regions` answered
`200` with `X-Response-From: service` from both, and `/v2/tokens` answered `403`
with `X-Response-From: Edge-Gateway` from both. This closes a plausible hope —
that token management might be opened up for particular egress addresses, the way
some vendors do — and it is worth having closed, because it was the one remaining
way `credential-do` could have become production-viable without DigitalOcean
changing anything. It cannot. The refusal is a property of the auth type and the
route, exactly as first recorded, and no network arrangement affects it.

**Severity:** Highest here — the reference implementation's hot path does not work
upstream. Contained, though: it affects one cloud, and the failure is a clean
`403` at minter-set/role **write** time (the capability probe), not a silent
mis-issue at read time.

**Symptom.** With a **full-access** DigitalOcean PAT — one that reads
`/v2/account`, `/v2/projects`, `/v2/droplets`, `/v2/databases`, `/v2/apps`,
`/v2/kubernetes/clusters` and more, all `200` — every token-management call is
refused:

| Call | Status | `X-Response-From` |
|------|--------|-------------------|
| `GET /v2/account` (and the other reads above) | **200** | `service` |
| `GET /v2/tokens` | 403 | **`Edge-Gateway`** |
| `POST /v2/tokens` | 403 | **`Edge-Gateway`** |
| `GET /v2/tokens/scopes` | 403 | **`Edge-Gateway`** |
| the same paths **unauthenticated** | 401 | `Edge-Gateway` |

Body in every case: `{"id": "Forbidden", "message": "You are not authorized to
perform this operation"}`.

**Root cause, and why the header is the whole finding.** A bare 403 is ambiguous:
it could mean "this credential lacks a privilege", which a differently-privileged
credential would fix. DigitalOcean states which layer answered in
`X-Response-From`, and the answers separate cleanly — working calls are answered by
a `service`, every `/v2/tokens*` call by `Edge-Gateway`. The refusal is therefore
made by DO's gateway **before** any service weighs the token's privileges: the path
is not exposed to bearer-PAT authentication at all. The 401s on the same paths when
unauthenticated show the gateway does authenticate first and then refuses the route,
so this is routing, not authorization.

Consequently **no PAT can mint** — not a scoped one (which also fails DO's own
scope-listing call), not a full-access one. This supersedes the intermediate
conclusion drawn from the first probe run, which had only a scoped PAT to work with
and read its 403 as a privilege verdict ("a DO minter must be a full-access PAT").
It isn't; there is no such thing as a mint-capable PAT.

**Consistent with what was already known** and, in hindsight, predicted by it:
`POST /v2/tokens` is absent from DigitalOcean's public OpenAPI spec, and DO
documents PAT creation as a control-panel flow (D1 in
[`do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md)). The
endpoint is what the control panel itself uses, and the control panel does not
authenticate with a PAT — it holds a session. The undocumented-dependency risk this
repo accepted has simply already come true.

**What is affected**

- **Mint** (`doClient.CreateToken`, `path_creds.go`) — the plugin's reason to exist.
- **Revoke** (`DELETE /v2/tokens/{id}`) — untestable, and moot: nothing is minted.
- **Reconciler** (`doClient.ListTokens`) — `GET /v2/tokens` is fenced too, so
  orphan reclamation cannot see upstream state either. Note the owner-tag safety
  invariant is unharmed: it never deletes what it cannot list.
- **Health check** (`GET /v2/account`) — unaffected; the one DO call that works.
- Everything cloud-agnostic — envelope, leases, recovery state machine, minter
  sets, metrics, conformance, e2e — is unaffected, because the fake stands in for
  the cloud in all of it.

**No headless alternative exists *for a PAT*.** OAuth tokens (`doo_v1_`) are
documented and scopable but require interactive user authorization, so they cannot be
minted by a plugin (already recorded as the rejected alternative under D1). DO offers
no headless way to issue a short-lived DigitalOcean **API** credential.

*Revised 2026-09-15:* this paragraph used to dismiss Spaces keys in the same breath, on
two grounds that no longer hold together. They are indeed a different credential type —
but "out of scope" was a judgement about object storage as a *product substrate* (per-
customer isolation at ~100k services, where the 100-bucket-per-account cap binds), not
about whether this plugin may issue one; and their API-issuability, recorded as
contested, is now supported by a published spec entry plus another service's production
use of a bearer PAT. So a Spaces key **is** the headless alternative, for a different
credential shape, and the plugin issues it. The distinction to keep: the fence closes
DigitalOcean's own API to headless issuance; it says nothing about the S3 API.

**How this is pinned, and what would tell us it changed**

- `plugins/credential-do/real_cloud_test.go` (`make test-cloud-real-do`) asserts
  the fence: `/v2/account` 200 from `service` as the control, then `GET`/`POST`
  `/v2/tokens` 403 from `Edge-Gateway`. **A failure there is good news** — the
  unexpected-`201` path is fully written (assert `token.id` and
  `token.access_token`, use the credential, delete it, confirm it stops working)
  and fails with a message saying so, so a world-change is loud instead of
  silently rotting the plugin further.
- `plugins/credential-do/fake_parity_test.go` keeps the recorded evidence honest in
  ordinary credential-free `go test`: the recordings must still show the
  `service`-vs-`Edge-Gateway` contrast the conclusion rests on.
- The capability probe (`capability.go`, `forbiddenMintHint`) turns the upstream
  403 into this diagnosis at minter-set/role write time, because DO's own message
  sends an operator hunting for a privilege that does not exist.

**Deliberately NOT done**

- **Deleting the plugin.** It is the shape every other plugin follows and the
  origin of the DO fake, which the conformance and e2e layers depend on. Removing
  it would delete working, load-bearing test infrastructure to make a point about
  one cloud.
- **Faking the fence in `pkg/credenvelope/fakes/do.go`** so the whole suite goes
  red. The fakes model an upstream that behaves; making the default DO fake refuse
  every mint would turn ten plugins' worth of cloud-agnostic coverage off to
  restate one cloud's fact. The fake's `SetForbidCreate` knob already exercises the
  403 path, and its body is now byte-for-byte DO's.
- **A `read`-time guard rejecting DO issuance outright.** The capability probe
  already refuses at write time with an explanation, which is the earlier and more
  informative place; a second hard-coded refusal would also have to be undone by
  hand the day DO changes.

## KI-010 — an STS `ValidationError` is reported to clients as `internal`, and counted against the minter (credential-aws) — [RESOLVED 2026-08-22]

**Resolved 2026-08-22**, and the fix is much wider than the finding — auditing the
whole error vocabulary for the same defect turned up four more instances of it, all
worse. See "What the audit found" below.

**Status:** found by the AWS real-cloud probe on the day that layer was built. Low
severity in steady state, misleading exactly when it fired.

**What happens.** `classifyAWSError` (`path_creds.go`) matches error text for
`AccessDenied`/`403`, `ExpiredToken`/`InvalidClientTokenId`/`401` and
`Throttling`/`429`, and falls through to `http.StatusInternalServerError` for
everything else. AWS's `ValidationError` is in that everything-else, so:

- the client receives `error_code: internal` — "the plugin broke, maybe retry" —
  for a failure AWS itself labels `<Type>Sender</Type>`, i.e. permanent and the
  caller's fault;
- the recovery state machine takes a `RecordError` for it, so repeated reads count
  faults against a minter whose credential is entirely healthy.

Recorded fixture (`plugins/credential-aws/testdata/cloud-real/POST_AssumeRole_400.json`,
from a real STS call):

```xml
<Error>
  <Type>Sender</Type>
  <Code>ValidationError</Code>
  <Message>1 validation error detected: Value '43201' at 'durationSeconds' failed
  to satisfy constraint: Member must have value less than or equal to 43200</Message>
</Error>
```

**Why it matters more than a mislabelled error.** This is the *surfacing behaviour*
of the `MaxSessionDuration` gap. A role TTL is validated against STS's documented
900s–43200s range at role write, and the capability probe pins its own request to
the 900s floor (it cannot revoke what it mints), so **neither check can see a target
IAM role whose `MaxSessionDuration` is below the role's TTL**. That configuration
passes every write-time gate and then fails every issuance with the response above
— reported as `internal`, while the minter is slowly marked unhealthy. An operator
gets the least informative available signal for a purely declarative mistake.

**Why it was not simply fixed.** Mapping `ValidationError` to `400` changes nothing
client-visible on its own: `ClassifyUpstream` mapped 400 through `default` to
`ErrInternal` too. Surfacing it honestly needed a **new `error_code`**, which is a
spec change — so it was recorded rather than made silently, and then done properly.

## What the audit found

Asked to consider other failure modes before touching the vocabulary (so one spec
revision would do), the sweep found KI-010 was the *mildest* of five instances of the
same defect — a real failure mode collapsing into `internal`:

1. **`upstream_timeout` was unreachable.** Its only occurrences repo-wide were in its
   own unit test. Every plugin sets a 30s HTTP client timeout; a client-side timeout
   carries **no status code** by construction; nothing inspected the error; so the most
   retryable failure in the system was reported as `internal`. The README and this
   RFC both advertised it as a code clients could distinguish.
2. **Cloud unreachable or 5xx → `internal`.** 43 call sites returned status `0` on
   transport failure. A cloud being down was indistinguishable from a plugin bug.
   Worse, the three string-matching classifiers (AWS/GCP/OVH) had **no 5xx branch at
   all** — found by the new conformance category on its first run, against OVH.
3. **Non-401/403/404/429 4xx → `internal`** — KI-010's own family.
4. **Quota errors that were not HTTP 429 → `internal`**, so AWS's `LimitExceeded` (the
   2-key cap rotation depends on) missed `upstream_quota_exceeded`.
5. **Configuration errors reported as upstream errors** — a mistyped `minter_set` came
   back as `upstream_auth_failed`, sending the operator to the cloud.

Two further contract defects, neither a classification bug:

6. **`consent_required` was never emitted** by any code path — specified, dead.
7. **166 write-path error responses carried no `error_code` at all**, while API-002
   claimed "all error responses include `error_code`".

**Also settled: `api_version` cannot version the error vocabulary.** A code travels in
the error *string*; an error response carries no envelope; `api_version` exists only
inside an envelope, i.e. only on success. Bumping it would announce the change on the
one class of response where the change never appears. So the vocabulary is **additive**
with a documented rule — clients must treat an unrecognised code as `internal` — and
`api_version` stays `"2"`, continuing to mean the envelope's shape and nothing else.

## The fix

- **Four new codes**: `upstream_unavailable`, `upstream_request_invalid`,
  `config_invalid`, `unsupported`. Each earns its place by the test that a client
  would act differently on it; `upstream_conflict` was considered and declined
  because entity names are plugin-generated, so a 409 is a plugin bug or a quota.
- **`credenvelope.Classify(status, err)`** replaces status-only classification: when
  there is no status it inspects the error, which is what makes `upstream_timeout`
  reachable at last. The three per-cloud classifiers now return
  `credenvelope.StatusNone` for "unrecognised" instead of a synthetic 500, and gained
  5xx, quota and validation signatures (as ordered tables, not if-chains).
- **`IndictsMinter` splits the two consumers.** One integer used to drive both what
  the client is told and whether the minter is held responsible; they need different
  partitions. `StateMachine.RecordUpstream(status, err, at)` is now the single entry
  point and drops non-credential failures before they reach the state machine, so a
  caller's bad request can no longer walk a healthy minter toward `AuthFailing`.
- **Every write path carries a code** (166 call sites), and `logical.ErrorResponse` is
  **forbidden by lint** outside `pkg/credenvelope` — the contract is now a property of
  the build rather than of reviewer attention.
- **`consent_required` removed.** Nothing ever emitted it, so no client can have seen it.
- **A seventh conformance category, `error-taxonomy`**, over all ten plugins: no cloud
  can opt out, and the cases needing a knob print why they are unexercised instead of
  silently skipping.

**What is pinned now**

- `plugins/credential-aws/fake_parity_test.go` asserts AWS's envelope shape
  (`<Code>ValidationError</Code>`, `<Type>Sender</Type>`) and the current
  classification, so a change to either is deliberate and tells the reader to update
  this entry.
- `plugins/credential-aws/real_cloud_test.go` declares the `MaxSessionDuration` gap
  rather than skipping it, and takes an optional `CLOUDREAL_AWS_LOWCAP_ROLE_ARN`
  naming a role capped below the role TTL, which turns the declaration into a live
  assertion. The minter's IAM grant is deliberately assume-only, so it cannot create
  that role itself.

**Still open, deliberately: the `MaxSessionDuration` gap itself.** The *reporting* is
fixed — an operator now gets `upstream_request_invalid` and the minter is left alone —
but a target role capped below a role's TTL still passes every write-time gate. Closing
that needs the plugin to read the target role's `MaxSessionDuration` (`iam:GetRole`) at
role write, which costs another IAM grant on the minter and only works same-account.
Tracked here rather than fixed; the real-cloud probe declares it and
`CLOUDREAL_AWS_LOWCAP_ROLE_ARN` turns the declaration into a live assertion.

---

## KI-011 — a leaked credential could not be invalidated en masse, and deleting the role stopped nothing — [RESOLVED 2026-09-16, RESIDUAL on AWS/GCP/OVH/OCI]

**Status:** RESOLVED 2026-09-16 (two operator levers, a ninth conformance category
fencing them, and an e2e pass over the wire). The residual is a property of four
clouds rather than of this code, and is stated below.

**Severity:** High — the whole point of short-lived credentials is bounding the
damage of one leaking, and the mount had no way to act on a leak faster than the
credentials' own expiry. On DO, Exoscale, Vultr and Akamai, whose credentials have
**no upstream expiry at all**, "faster than expiry" means "at all".

**Symptom:** an operator believes credentials this mount issued are in the wrong
hands, and knows the role they were issued from. Their available actions were:
revoke leases one at a time (only for leases they can enumerate — an incident hands
you a role name, not lease ids), or delete the role. Deleting the role **reads as
containment and achieves nothing**: the lease core keeps every live lease renewable,
and every credential already issued keeps working. On the four clouds above it keeps
working indefinitely, because the lease revoke that would have deleted it upstream is
now attached to a role that no longer exists.

**Root cause:** two levers were missing, and one of them was missing invisibly.

1. `disabled` was honoured at issuance on all ten plugins — the stored role carried
   the field and `pathCredsRead` refused on it with `role_disabled` — but **no role
   write path accepted it**, so the control an operator would reach for first was
   unreachable through the API. A field that is read but not writable looks exactly
   like a working switch in a code review.
2. Nothing addressed "delete what this role has already issued". The mount had the
   information all along: every hard-revoking plugin writes an `active-*/` tracking
   record per issued credential, naming the role — the same records the reconciler
   and the capacity counter read. They were simply not reachable by role name.

**The fix.**

- **`disabled` is settable on all ten role write paths.** It needs nothing but the
  flag, and works while the cloud is refusing to mint, because that is the situation
  it is for.
- **`roles/<name>/revoke-upstream`** on all ten plugins (six acting, four refusing).
  `mode=dry_run` first, reporting the count and arming nothing. A normal write arms a
  durable `purge/<role>` intent whose cutoff is the arm time, runs one bounded pass
  inline and returns progress; the `upstream-purge` worker on the active node
  continues in bounded passes across a restart or failover. Both operations answer in
  one schema on every cloud. It works on an already-disabled role, deliberately —
  close the tap, then empty the bucket, without re-opening issuance in between.
- **A ninth conformance category, `containment`**, over every subject: twelve cases,
  including the disabled-role purge (proven to catch its defect by injecting the
  refusal into one plugin) and the refusal on a cloud that cannot delete. `pkg/baotest`
  drives the dry run, the purge and the progress read over real HTTP.

Rationale for every part of that shape — the cutoff, the pacing that is deliberately
not the reconciler's, why a purge bypasses `loadRole` — is in
[`decisions.md`](decisions.md).

**Residual, and it is the part to read before planning an incident response.**

- **AWS, GCP and OVH have no lever.** Nothing deletes an STS session, a GCP
  impersonation token or an OVH OAuth2 token: the credential expires and that is all.
  So the role's `max_ttl` **is** the blast radius (AWS ≤12h, GCP ≤12h, OVH exactly
  1h), and the only action available during an incident is having stopped the next
  one. If a shorter blast radius is wanted on those clouds, it has to be bought in
  advance by setting a shorter `max_ttl` — there is nothing to buy it with afterwards.
- **OCI's lever is a different endpoint.** A phased-rotation credential belongs to a
  slot and is shared by every client that has read it, so containment is
  `rotate-slot/<role>/<slot_index>`, which replaces it now for all of them.
- On all four, `revoke-upstream` **refuses** with `unsupported` and names that cloud's
  own remedy. A success reporting zero deletions was the alternative and is the
  dangerous one: mid-incident it reads as "nothing was out there".
- **A purge sees only what this mount tracked.** A credential whose tracking record
  was lost (the KI-002 path, a storage failure between mint and track) is invisible to
  it, and remains the owner-tag reconciler's job. Credentials created in the account by
  anything else were never in scope.

## KI-012 — a failed rotation returned no credential, while a working one sat in storage (`credential-do`, `spaces_key_rotated`) — [RESOLVED 2026-09-21]

**Status:** RESOLVED 2026-09-21 (fallback inside a bounded window, two conformance
cases and one per-plugin test, each confirmed by injecting the defect it describes).
Present in v0.4.0 and v0.5.0; the fix is **unreleased** as of this entry.

**Severity:** Medium, and higher than it looks. The credential was fine — issued,
non-expiring, and already in the client's hands. What had failed was this mount's
ability to mint its *successor*, and the read turned that into a total denial for
every reader of the role, repeated on every read, for as long as the fault lasted.
Not High only because `rotation_period` is measured in days, so the window in which
an upstream fault can land on a due key is small.

**Symptom:** a `credential_type=spaces_key_rotated` role whose key had reached its
rotation age, on a mount that could not reach DigitalOcean (or whose minter had been
rejected), answered `creds/<role>` with an upstream error and **no credential** —
while `shared-spaces-keys/<role>` held a valid key that every other reader was
already using successfully. A client that had refreshed a minute earlier held a
working credential; the same client refreshing now got nothing.

**Root cause:** the read path treated "this key must be replaced" as a single
condition. `serveSharedSpacesKey` called `rotationReason`, and on any non-empty
reason attempted a rotation whose error response it returned verbatim. There was no
notion of a key that was *due* but still serviceable, so the only two outcomes were
a replacement or a refusal — and the key already in storage, which DigitalOcean does
not expire, was never considered.

**Fix:** `rotationReason` returns a typed `rotationCause`, and only `causeAge` falls
back to serving the existing key. The window is bounded by
`sharedSpacesKey.servableUntil`, the earlier of `minted_at + rotation_period` (the
promise that field already makes — which is why no new role field was added) and
`deadline()` (past which no positive TTL can be issued without a lease outliving its
credential). The response carries a `Warnings` entry naming the rotation error and
the moment the key stops being served; past the window the read is refused with the
rotation's own error code. Retrying is the lifecycle worker's job, as it already was.

**Deliberately NOT part of the fallback:** `causeGrants`. A key whose grants no
longer match the role carries privilege an operator has just revoked, and serving it
because the replacement failed would undo that narrowing on the exact path used to
reduce blast radius — and misreport it, since the envelope renders `scope` from the
role rather than from the key. `causeUnminted` has nothing to serve at all.

**Tests:** `rotation/AnOverdueCredentialIsStillServedWhileTheRotationFails` and
`rotation/PastTheAgeTheRolePromisesTheReadIsRefused` in `pkg/plugintest`, plus
`TestRotatedSpacesCreds_NarrowedGrantsAreNotServedWhenRotationFails` in the plugin
(the shared suite cannot express it: grants are DigitalOcean's own vocabulary).
Reverting the fallback fails the first, unbounding the window fails the second, and
allowing `causeGrants` through fails the third — all three verified, not assumed.

**Residual:** the fallback's trigger is modelled by the fake, not observed. Minting
a Spaces key has never been exercised against the real API (KI-009 fenced the token
path; `testdata/cloud-real/` holds `/v2/account` and `/v2/tokens` only), so how
DigitalOcean actually refuses a create — and therefore which classifier branch the
fallback runs behind — rests on the published specification.
