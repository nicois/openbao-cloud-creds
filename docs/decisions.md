# Design decisions

Short notes on choices that aren't obvious from the [techrfc](techrfc.md) and would otherwise need to be re-derived from scratch.

## Why a thin uniform-envelope plugin per cloud (not one super-plugin, not pure SDK wrappers)

Considered three approaches:

1. **One super-plugin** with a cloud-selector field. Rejected: a panic in any cloud's code would take down credential issuance for all clouds, and the binary would link every cloud's SDK (large surface, much larger blast radius for a CVE in any one SDK).
2. **Pure cloud SDK wrappers, no envelope.** Rejected: clients have to branch on cloud type to parse responses, which defeats the entire goal.
3. **Thin per-cloud plugin behind a uniform envelope.** Chosen. Plugin failures are isolated by OS-level process boundary (OpenBao plugins run as separate processes); each binary links only its own SDK; clients dispatch on `cloud` only when they actually need cloud-specific keys, not for envelope fields.

## Why minter validation is `(≥1 never_expires) OR (≥2 with ≥7d gap)`

Two failure modes drove this rule:

- **Single expiring minter** — when it expires, credential issuance stops. The plugin can't seamlessly rotate to a different minter because there isn't one. Rejected at config load.
- **Two expiring minters that expire close together** — both could expire in the same operator-attention window, defeating the point of having two. Rejected unless the gap is ≥7 days.
- **`never_expires=true` as escape hatch** — relaxes both rules because a permanent fallback by definition doesn't run out. The expectation is operators set this only for credentials that genuinely don't expire (e.g., AWS IAM access keys absent organizational rotation policy). A Prometheus alert on `expires_in_seconds < 14d` doesn't fire for `never_expires` minters, so onboarding review must catch any abuse.

## Why metrics are keyed on `entity_id`, not OpenBao role name

The metric exists to answer "is this cloud entity safe to delete?" — that's a question about a cloud entity, not a logical role. The same cloud entity (e.g., a single IAM role ARN) can back multiple OpenBao roles with different scopes. Keying on the OpenBao role would make a stale metric for one role hide active use through another, leading to deletion of an entity that's actually in use.

So `entity_id` is the cloud-side identity an operator might delete:
- AWS: IAM role ARN being assumed (via STS)
- GCP: SA email being impersonated
- Azure: parent app registration (NOT the per-lease client secret)
- DO: the minter PAT (NOT the per-lease minted token)
- UpCloud / Exoscale / Vultr / Akamai / OVH: the minter credential (NOT the per-lease issued credential)
- OCI: the user whose auth-token slots are rotated

## Why per-node metrics with eventual consistency, not single-writer

OpenBao plugin storage writes go through raft consensus. A naive "every read writes a `last_access_at` timestamp" design would put raft consensus on the credential-issuance hot path — unacceptable both for latency (50–200ms per write in multi-cloud topologies) and for write amplification.

Instead each plugin instance accumulates accesses in memory and flushes a per-node-tagged keyspace every 15 minutes. Conflict-free — each node owns its own keyspace. The query API merges across nodes and reports a `staleness_seconds` field so callers know how fresh the answer is. This trades strong consistency for one cheap raft write per node per flush interval.

## Why phased rotation (rather than a credential pool, or pure JIT for everything)

Considered three approaches for clouds without native short-TTL primitives:

1. **JIT for every cloud** — would work for DO, doesn't work for clouds whose token-creation API is rate-limited, slow, or absent. Doesn't generalize.
2. **Credential pool** (M pre-provisioned credentials, hand out the next available) — solves rate limits but the TTL semantics are dishonest: a pool credential has the same lifetime as the longest-lived item in the pool, not the time until it's rotated out.
3. **Phased rotation** — N slots, each rotated on schedule with phase offsets so ages stagger across [0, T). Read handler hands out the freshest slot; the lease's `expires_at` is exactly that slot's next-rotation time. TTL is honest, no rate-limit risk on the hot path, and rotation is fully scheduled.

Phased rotation is essentially a pool with rotation discipline, where the discipline is what makes the TTL honest.

## Why DO is the reference implementation (not AWS)

DO is the simplest cloud that exercises every load-bearing piece of the design:

- Has a JIT-capable native API (`POST /v2/tokens`) — but see the 2026-08-21 correction below: this endpoint is *undocumented*
- Has revocation (`DELETE /v2/tokens/{id}`) — likewise undocumented
- Has no native short-TTL primitive (so the plugin owns the TTL contract)
- The cloud SDK is small
- Test accounts are cheap

It was chosen as the reference precisely because it owns the full lifecycle (envelope, lease tracking, recovery, reconciler, metrics) with nothing delegated upstream — every load-bearing piece gets exercised.

> **Correction (2026-08-21):** "Has a JIT-capable native API" overstated the case. DO's `POST /v2/tokens` / `DELETE /v2/tokens/{id}` are **not public documented API** — DigitalOcean's public OpenAPI spec has no `/v2/tokens` path and DO documents PAT creation as control-panel-only, so the reference implementation depends on a control-panel-internal endpoint with no stability contract. Notably, `docs/object-storage-credential-audit.md` rejected DO Spaces *for exactly this reason*; the two positions were inconsistent. We keep DO as the reference — the endpoint works, it is what the control panel itself uses, and the documented OAuth alternative needs interactive authorization so cannot mint headlessly — but the dependency is now stated wherever the endpoint appears, and verifying it is the first item of the deferred real-cloud pass (#7). Full findings: [`docs/do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md).

> **Correction (2026-05-30):** This section originally argued AWS was a poor reference because "most of the credential lifecycle is delegated to the upstream OpenBao `aws` engine." That premise turned out false — OpenBao's AWS engine only supports IAM-user `iam_tags` (no STS `session_tags`), and there is no OpenBao GCP or Azure engine at all. As a result AWS/GCP/Azure were built as full JIT plugins calling the cloud APIs directly, with the same lifecycle machinery as DO. DO remains the reference for being the simplest, but the "delegate to upstream engine" distinction no longer applies to any cloud. See `docs/cloud-credential-research.md`.

## Why minter sets (named, role-bound) rather than one flat minter list per cloud

The original model had a single per-cloud minter list in `config`, and any role drew from any healthy minter (the multiple-minter mechanism existed only for rotation/failover). That forces **one maximally-privileged minter per cloud**, which breaks down for three reasons:

- **Capability separation is real on some clouds.** An Azure service principal authorized to manage app registration A (via `addPassword`) typically has no rights on app B; Akamai/Linode API-client creation is scoped per group/contract. Different role classes genuinely require different privileged minting credentials — a single minter cannot mint them all.
- **Operational separation.** Operators want discrete minting credentials per purpose (e.g. a backup-issuing minter distinct from an admin-issuing one), rotated and owned independently.
- **Audit provenance.** When an issued credential is misused, you want to trace which minting credential produced it.

So minters are grouped into named **sets** (`minter-sets/<name>`), each independently validated by the OBC-006 rule, and every role carries a **required** `minter_set`. Issuance mints only from the bound set — deliberately **no cross-set failover**, because the whole point is isolation: a compromise or misconfiguration of set A's minters cannot issue set B's credentials. The issuing set+minter are stamped into `metadata.minter_set`/`minter_id` (which bumped the envelope to api_version 2) and lease internal_data. The reconciler is the one exception: it cleans orphaned upstream entities across all sets by owner-tag, since orphan cleanup is a mount-wide safety property, not a per-role one.

Operators achieve least-privilege by granting each set's minters only the upstream rights its bound roles need. For capability isolation without sets, multiple mounts would also work, but sets keep it within one mount and make provenance first-class.

## Why revoke tolerates a missing issuing minter and an already-deleted credential (KI-002)

Hard-revoke plugins delete the upstream credential on lease revoke using the
minter that issued it. Two cases broke this: (a) the issuing minter was removed
from its set after issuance (re-seed), so the plugin could not build a client to
delete; (b) the credential was already deleted (double revoke), so the upstream
delete returned 404. Both previously returned errors, which OpenBao retries
forever.

Decision: (a) revoke falls back to any healthy minter in the same set, and if
none remains, treats revoke as a successful no-op (logged); (b) a 404/not-found
on the upstream delete is treated as success. This weakens the "revoke always
performs the upstream delete" property in these edge cases, which is acceptable
because the real guarantee is TTL expiry — every issued credential has a bounded
lifetime. A clean no-op lets the lease release rather than accumulating infinite
failed retries.

## Why a strict golangci-lint v2 config (the "slow-accretion" smell set)

The repo adopted a deliberately strict `.golangci.yml` (v2, ~20 linters:
complexity — gocyclo/gocognit/cyclop/funlen/nestif/maintidx; magic-numbers and
repeated-literals — mnd/goconst; duplication — dupl/gocritic; dead/comment-rot —
unused/unparam/ineffassign/wastedassign/godox/godot/predeclared; plus a tuned
revive ruleset), pinned to golangci-lint v2.12.2 and run per-module in CI.

Decision: enforce it across every module with zero `//nolint` suppressions.
Rationale: with one plugin per cloud and ten near-parallel plugins, the failure
mode is *drift* — a helper that subtly diverges, a magic number that means
something different in one cloud, copy-paste that rots. The complexity and
duplication linters fire on exactly that drift, which is what pushed the
genuinely-shared code into `pkg/` (telemetry, metricspath, localexpiry) instead
of ten copies. The no-nolint rule is load-bearing: when a linter fires, the fix
is to restructure (extract a helper, name a constant, drop a dead param), not to
suppress — suppressions are where drift hides. Carried-forward exceptions live
in the config itself (not inline), e.g. the `(io.Closer).Close` errcheck
exclusion and `revive`'s disabled `unused-parameter`/`unused-receiver` for the
SDK-mandated handler signatures. Test files are excluded from the
complexity/literal linters (test code legitimately repeats literals and is
structurally loose). See `docs/superpowers/specs/2026-05-31-golangci-config-upgrade-design.md`.

## Why minter rotation retires with a grace period instead of deleting immediately

Minter sets are loaded into memory only at `Factory` construction and on a
minter-set write — there is no periodic reload. On a raft cluster the rotate
request is served by exactly one node; the other nodes keep the old minter in
their in-memory snapshot until they next reload (failover, restart, or a
subsequent minter-set write). If rotation deleted the old upstream credential
the moment it minted and swapped in the successor, every other node would still
be trying to mint with a credential that no longer exists upstream — issuance
would wedge cluster-wide (the KI-001 class of "the surviving node holds stale
config" failure).

Decision: rotation is grace-separated. `RotateMinter` mints the successor,
validates the prospective set, health-checks the successor, swaps it in, and
marks the old minter retired by stamping `RetiredAt` — but does **not** delete
the old upstream credential. A separate retired-sweep deletes the upstream
credential only after `minter_retire_grace` has elapsed (default 7d, which must
exceed the worst-case node-reload interval). The retired minter is excluded from
new-issuance selection (`selectMinter` skips it) and from set validation
immediately, so it stops being a live issuance path at once, but it stays
upstream-alive for the grace window so stale-snapshot nodes can keep minting
until they reload. The sweep is keyed off `RetiredAt`, deliberately separate
from the conservative owner-tag orphan reconciler.

## Why role TTLs are bounded at write time, and why OVH roles are pinned to exactly 1h

A lease TTL is a promise about a credential. The plugin can keep that promise two
ways: ask the cloud for a credential whose native lifetime *equals* the TTL
(AWS `DurationSeconds`, GCP `lifetime`, Azure `endDateTime`, UpCloud `expires_in`),
or hard-revoke at lease end (DO, Exoscale, Vultr, Akamai). Where the cloud offers
neither, the TTL is unenforceable — and an unenforceable TTL is worse than an
error, because the operator believes a credential died when it did not.

Decision: reject at role-write time any TTL the cloud cannot honour, rather than
accept it and diverge at issue time.

- **Upper bounds** (AWS 43200s, GCP 43200s, UpCloud 8760h, OVH 3600s) turn a
  guaranteed upstream 4xx at read time into a clear config error at write time.
- **Lower bounds** exist only where the cloud has a documented minimum (AWS STS:
  900s) or where a shorter TTL would be *dishonest* (OVH). We do **not** invent
  floors for clouds that document none — Azure, GCP, UpCloud, DO, Exoscale, Vultr
  and Akamai all honour arbitrarily short TTLs, either by shortening at mint or by
  revoking.
- **OVH is pinned to exactly 3600s.** Its OAuth2 token endpoint takes no lifetime
  parameter (tokens are a fixed hour) and OVH publishes no token-revoke API, so
  *neither* mechanism is available. `default_ttl=15m` used to end the lease at 15
  minutes while the token stayed valid for the remaining 45 — with the envelope's
  `expires_at` (the token's real expiry) contradicting the lease. Since the only
  TTL OVH can honour is 1h, that is the only TTL a role may declare.

The same reasoning drove making Azure and UpCloud leases non-renewable: both fix
the credential's expiry at mint and cannot extend it, so renewing granted a lease
that outlived its own credential. Refusing renewal (as AWS/GCP/OVH/OCI already
did) keeps the envelope's `renewable` field truthful.

OCI is the deliberate exception in the other direction: phased rotation means a
slot's token outlives the lease until its scheduled rotation. The lease never
overstates validity — TTL is clamped to the time until that slot's next rotation —
but the credential is not destroyed at lease end. That is the accepted cost of the
only strategy OCI's 2-token-per-user quota permits. Full matrix in
`docs/ttl-semantics.md`.

## Why minter capability is probed, not inferred (and why probes default on)

A health check answers "is this credential live?"; issuance needs "may this
credential mint what this role asks for?" No cloud in scope lets us ask the
second question directly:

- **No introspection.** DO has no scope-introspection API (scopes are fixed at
  creation and never reported back). UpCloud does not report `can_create_tokens`
  on the account endpoint. Akamai's `GET /api-clients/self` reports grants, but
  what a client may *delegate* is a separate matter.
- **The health call is deliberately unprivileged.** AWS answers
  `sts:GetCallerIdentity` for any valid signature — no policy needs to permit it
  — so it cannot fail for a permissions reason. GCP's self-signed-JWT exchange
  proves only that the minter SA's own key is live; impersonation is
  `roles/iam.serviceAccountTokenCreator` **on each target SA**.
- **The privilege is per-role, not per-minter.** Azure `addPassword` needs
  ownership of *that* app registration; Vultr refuses to grant a sub-user an ACL
  the creating key lacks; Exoscale must be allowed to grant *that* role-id.

Considered inferring capability from a role/scope comparison instead of calling
the cloud. Rejected: it means reimplementing each cloud's authorization model
locally, and being wrong in the permissive direction produces exactly the bug we
are trying to prevent (a config write that passes and a credential read that
403s). The only trustworthy oracle is the cloud itself.

Decision: probe by minting. Create a credential with the same request shape a
real issuance would use, then delete it — at minter-set write, at role write, and
before a rotation commits.

**Default on.** The failure this prevents is silent (a healthy-looking minter),
delayed (until the first read), misattributed (it lands on a caller, not on the
operator who caused it), and hard to diagnose from the far end (an upstream 403
with no local explanation). A verification that is off by default would be
enabled exactly by the operators who already know the failure mode. The cost is
one throwaway credential per distinct `(minter, mint shape)` at configuration
time, which is bounded and paid on a cold path. `verify_minter_capability=false`
is the escape hatch, and it is named in every rejection message so a probe that
cannot succeed in a particular environment is not a dead end.

**Probing at role write is not just symmetry.** It stops an operator defining a
role whose minting key is unsuitable, and its side effect is deliberate: a minter
set must exist and demonstrably work before roles can bind to it, which pins the
configuration order (`config` → `minter-sets` → `roles`) instead of leaving the
sequence to chance.

**Every active minter is probed, not one.** Minter selection picks arbitrarily
among a set's selectable minters, so a single incapable minter makes issuance
fail *intermittently* — the harder failure to diagnose — rather than not at all.

## Why probe cost is accepted on the three clouds that cannot revoke

AWS, GCP and OVH cannot revoke what a probe mints (STS sessions, access tokens
and OVH OAuth2 tokens all expire on their own and have no revoke API). A probe on
those clouds therefore *leaves a credential in existence that nobody holds*.

Decision: accept it, and bound it by asking for the shortest lifetime the cloud
accepts — AWS's documented 900s floor, 60s on GCP, and OVH's fixed 1h (no choice
there). The probe credential is never returned to a caller, never recorded in a
lease, and (where the cloud names credentials at all) carries the owner-tag
prefix. The alternative — skipping verification on precisely the clouds whose
health checks are the *least* informative (`GetCallerIdentity` requires no
policy; GCP's health call cannot see impersonation grants at all) — would leave
the biggest gap unverified. Operators for whom even a 900s unheld session is
unacceptable turn probes off explicitly.

For the same reason, a *failed delete* never fails a probe on the revocable
clouds: minting was what was being proved, and the probe credential's name
carries the `cloud-creds-<role>-probe-` owner prefix, so the owner-tag reconciler
reclaims it (probes are never recorded in lease tracking, so they are orphans by
construction).

## Why OCI is not capability-probed

OCI caps a user at **two** auth tokens. That cap is the entire reason the OCI
plugin uses phased rotation rather than JIT. A probe would have to consume one of
those two tokens, so it would either fail in the steady state (both slots already
provisioned) or, worse, succeed by displacing a slot a live lease is drawing
from. Verification would break issuance in order to prove issuance works.

Decision: OCI's checks return `capability.ErrUnsupported`, which `Verify` counts
as *skipped* rather than failed — the set/role write proceeds and the
operator-facing log records the skip. The uniform hooks still exist on the OCI
plugin (including the shared precondition that a named minter set must exist
before a role binds to it), so the surface stays uniform across all ten plugins;
only the probe itself is absent. OCI also needs it least: slot provisioning is
itself a real `create-auth-token` call made at role-write/rotation time, so an
incapable minter already surfaces as a failed provision to the operator who
configured it — which is the outcome probes buy elsewhere.

## Why an Akamai rotation successor inherits the incumbent's grants verbatim

Akamai's rotation successor is a *new api client*, not a new credential for an
existing one, so its grants have to be stated at creation. The first
implementation constructed an Identity-Management-only grant — enough for the
successor to manage api clients, and therefore enough to rotate again — which
quietly narrowed the minter on every rotation: after one rotation the set's
minter could no longer delegate the `apiAccess` its bound roles hand out, while
still passing `GET /api-clients/self` forever.

Decision: read the incumbent's own `apiAccess`/`groupAccess` (`GetSelf`) and
replicate them onto the successor, upgrading only the Identity Management api to
READ-WRITE so the successor can rotate in turn. If the incumbent's own grants
cannot be read, the rotation **fails closed** rather than falling back to a
constructed grant — a successor with unknown grants is exactly the thing being
prevented. `rotation_params.group_id` remains an explicit override for the case
where the incumbent reports no group access of its own.

This is also the sharpest case for the pre-commit capability probe: the copy can
still come back narrower than the incumbent (a group the authorizing user has
since lost, an api removed from them), and only a probe mint detects that before
the successor is swapped in.

## Why a runtime `minter_insufficient_privilege` error code was NOT added

The companion proposal was to distinguish a privilege 403 seen at *issuance* time
with a new `minter_insufficient_privilege` error code, and to stop such a 403
dragging the minter's recovery state machine to `AuthFailing`.

Decision: excluded from this work. Two reasons. It is a **spec change** — a new
`error_code` is a contract change for every client and requires a techrfc
revision, which is explicitly out of scope for a verification feature. And probes
largely remove the need: the privilege gap is now diagnosed at configuration time
by the operator who caused it, leaving a runtime privilege 403 as the residual
case of a privilege revoked upstream *after* configuration.

The residual behaviour is therefore unchanged and conservative-but-blunt: such a
403 maps to `upstream_auth_failed` and counts toward `AuthFailing`, withdrawing a
minter that is live but unusable for *this* role and may still be usable for
others. That remains an open refinement, recorded here so it is not mistaken for
a closed gap.

## Why cloud-agnostic tests live in one conformance table, not ten plugin files

Ten near-identical plugins mean every invariant is stated ten times. That is
survivable for *behaviour* (a shared `pkg/` helper fixes it) but not for *tests*:
a missing test looks exactly like a passing one, so coverage drifts silently and
per-cloud regressions accumulate one plugin at a time. The historical evidence is
in this repo — KI-001 (config not reloaded in `Factory`) turned out to affect 7
plugins, not the 1 it was reported against, and the reload suite that caught it was
`t.Skip`ped on 3 plugins for a reason nobody was re-reading.

Decision: every invariant that is *about the plugin's own state* — persist,
refuse, not-persist, not-delete, survive reload, tolerate double revoke — is
written once in `pkg/plugintest` as a suite parameterized by `plugintest.Harness`,
and applied to all ten plugins from a single `registry` table in the test-only
`conformance/` module. `pkg/plugintest` still imports no plugin (every plugin
imports it), so `conformance/` is where the two meet; being test-only, it does not
weaken per-plugin module isolation. Five categories today: `reload`,
`perturbation`, `revoke`, `capability`, `reconciler-safety`.

Three properties are load-bearing, and each is enforced by a test rather than by
convention:

1. **Registration is mandatory.** `TestEveryPluginIsRegistered` reads `../plugins`
   from disk and fails in both directions, so a new plugin cannot ship without
   entering the table.
2. **Every category is applied to every plugin.** `ValidateHarness` fails a
   harness that neither wires a category's required fields nor declares it in
   `Harness.Skips`. Adding a category therefore cannot land half-applied: it must
   be wired or explicitly waived on all ten.
3. **Gaps are declared, not buried.** A category that genuinely does not apply is
   `Harness.Skips[category] = "<why, about the cloud>"`, printed by
   `TestConformanceMatrix` as one reviewable line. An empty reason is rejected.
   There are five such gaps and each is a fact about the cloud — aws/gcp/ovh
   reconcile prunes only local tracking entries (`pkg/localexpiry`) because an STS
   session, an impersonation token and an OAuth2 token are not listable upstream
   entities; OCI cannot be capability-probed (2-token cap) and its in-process fake
   cannot plant a foreign token.

What deliberately did **not** move: the cloud's own vocabulary. Mint shapes, ACL
and apiId strings, deny knobs on the fakes, and anything touching unexported
symbols stay per-plugin. A harness adapter reads as a translation of the cloud into
the shared vocabulary — `DenyMint`/`AllowMint` are just two function values —
which is what makes it possible to state the assertion once. This reverses the
earlier "not added" position in `docs/minter-capability-verification.md`, which
correctly observed that *making* a minter incapable is per-cloud but wrongly
concluded that the *consequences* were too.

A side effect worth its own note: the ten `resilience_test.go` files are deleted,
and the AWS/GCP/OCI reload skip is gone. Those three skipped reload only because
the old per-plugin harness re-ran `Factory` without re-injecting the fake client;
`Harness.Inject` is applied to every backend instance, including the reload, so the
skip was an artifact of the harness rather than a property of the cloud. Prefer
suspecting the harness over accepting a skip.

The philosophy is written up for future sessions in `AGENTS.md`, which is the file
to read before adding a test, a category, or a plugin.

## Why a non-renewable secret registers *no* `Renew` callback (rather than refusing inside one)

KI-005 stopped six plugins handing back a fresh TTL for a credential whose expiry
was fixed at mint, by making their `pathCredsRenew` return an error. That was the
right intent and the wrong mechanism, and the difference cost the client its
credential.

`framework.Secret.Renewable()` is defined as `s.Renew != nil`, and that value is
what `Response()` copies onto the lease. A registered callback that always errors
therefore still advertises `renewable: true`. Worse, OpenBao's expiration manager
treats a **failed renewal as grounds to revoke the lease** — so a client that read
the plugin's own advertisement and renewed had its credential hard-revoked on the
clouds that hard-revoke. Refusing politely inside the callback was strictly worse
than either honest alternative (KI-008).

Two fixes were available: drop the callback, or keep it and assign
`resp.Secret.Renewable = false`. Dropping it wins because the callback's absence is
the *single* source of truth the framework reads — there is no second field to
drift out of sync, and core refuses the renewal before any plugin code runs, so the
plugin cannot get it wrong at a later date. Each affected plugin keeps a comment at
its now-empty `framework.Secret` naming that cloud's reason (STS `DurationSeconds`,
GCP `lifetime`, OVH's fixed hour, Azure `endDateTime`, UpCloud `expires_in`, an OCI
slot's next scheduled rotation), because an empty struct literal invites someone to
"helpfully" add the callback back.

DO, Exoscale, Vultr and Akamai keep their callbacks: their credentials have no
upstream expiry, so renewal genuinely means "defer the revoke", which works.

The invariant is now fenced for all ten plugins by the `lease` conformance
category, which asserts the envelope and the lease agree — the two structures are
built in the same handler from the same inputs and nothing but a test keeps them
honest.

## Why AWS and GCP derive the lease TTL from the upstream expiry, not the role TTL

Both clouds return the expiry they actually granted (STS may grant less than the
requested `DurationSeconds`; the mint round trip itself consumes wall-clock). The
envelope published that real expiry while the lease was built from the role's TTL,
so a 900s lease could name an 899s credential — a lease outliving its credential,
which is exactly what techrfc OBC-002 forbids, and a client watching the lease
would keep using a dead credential for the difference.

The lease is now built from the same number the envelope publishes. A one-second
floor (`minLeaseTTL`) is applied deliberately: a zero `TTL` means "use the mount
default" to core, which for a near-expiry credential is the worst possible reading
of "expired".

This was found by the `lease` category within minutes of it existing, on the two
clouds whose expiry is echoed back by the API rather than chosen by the plugin —
which is a good argument for asserting agreement between structures rather than
asserting each structure separately.

## Why background workers start in `InitializeFunc`, not in `Factory`

`startWorkers` was reachable only from `pathConfigWrite` and `pathMinterSetWrite`,
so a backend that OpenBao built any other way — a plugin reload, a mount remount,
an unseal, a raft leader failover — served credentials perfectly while running no
health checks, flushing no metrics, sweeping no orphans, warning about no expiring
minters, and (on OCI) rotating no slots. Silent, and indefinite: nothing recovered
until an operator happened to re-write config (KI-007).

`Factory` looks like the obvious place and is not. It also runs for constructions
that must not touch the network — a config-less test backend, tooling — and this
repo has an explicit rule against a config-less backend reaching the real cloud
API (now that capability probes exist, that rule has teeth). `InitializeFunc` is
the hook core calls precisely once per backend instance, on the active node, after
mount setup / unseal / reload, with storage available. So `initialize` rehydrates
config and minter sets first and then starts the workers, and `startWorkers` still
early-returns on `b.config == nil` for the case where nothing has been configured
yet.

It must be idempotent, because an unseal after a reload calls it again; the
`reload` conformance category drives it twice and then issues, for that reason.
What is *not* asserted is worker liveness — that a health check actually ran —
which needs a clock seam or a bounded poll per harness. Recorded as the residual on
G2 in `docs/openbao-integration-gaps.md` rather than left as an implied guarantee.

## Why there is an `e2e/` layer at all, given a ten-plugin conformance table

The conformance table drives `logical.Backend` in-process. That is the right place
for almost everything, and `AGENTS.md` says so. But two production facts are
structurally outside it: the plugin runs as a **separate process** (so `resp.Data`
and the lease's `internal_data` are JSON on the wire, not the Go values the test
handed back), and **core** owns the mount table, the expiration manager, plugin
reload and `req.ID`. An in-process test cannot be wrong about those; it simply
cannot see them.

The evidence settled it: within an hour of `e2e/` existing it found two live
defects (KI-007, KI-008), neither of which any in-process test could have caught,
and KI-008 only because a real expiration manager acted on the lease. Auditing what
the new layer *could not* reach then found a third (KI-001 still open on
AWS/GCP/OCI).

The layer is deliberately kept thin and its findings are pushed *down*: when e2e
finds something, the regression guard ships in `pkg/plugintest` where it runs on
all ten plugins in milliseconds. e2e is for discovery and for the boundary itself,
not for fencing. Clouds it cannot reach (AWS/GCP/OCI, which inject clients instead
of talking to an HTTP endpoint) are declared in its registry the same way
`Harness.Skips` declares conformance gaps — a gap that prints is a gap someone can
act on.

Above it sits one more layer, planned but unbuilt: real clouds via CI secrets,
whose purpose is proving the fakes resemble what they stand in for
(`docs/free-account-viability.md`). The `cloud_real` build tag is currently carried
by no file, and that is recorded as a gap rather than described as coverage.
