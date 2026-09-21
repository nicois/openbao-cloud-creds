# AGENTS.md — how to work on this repo

`CLAUDE.md` describes *what* this repo is (ten OpenBao credential plugins, two strategies, per-cloud facts). This file describes *how* to change it without eroding it. Read both.

The whole risk profile of this repo comes from one shape: **ten near-identical plugins**. Every invariant is stated ten times, so a fix lands in one plugin and silently misses nine, and an absent test looks exactly like a passing one. Everything below exists to make absence loud.

## The rule: conformance first

**Before writing a per-plugin test, ask whether the thing you are asserting is cloud-agnostic. If it is, it belongs in `pkg/plugintest` and runs against all ten plugins from `conformance/`.**

An invariant is cloud-agnostic when it is about *what the plugin must do to its own state* — persist, refuse, not persist, not delete, survive a reload, tolerate a second revoke. Almost every regression that has actually bitten this repo was of that kind (KI-001 config-not-reloaded, KI-002 revoke-wedged-forever, health-mistaken-for-capability). None of them were about a cloud's wire format.

An invariant is cloud-specific when it is about *the shape of the upstream call* — the mint payload, the URL, the error body, the signing scheme, an unexported helper. Those stay in the plugin's own package.

```
pkg/plugintest/     the shared suites. Parameterized by Harness. Imports NO plugin.
conformance/        the table. One entry per plugin, one Harness adapter per cloud.
plugins/<x>/*_test  only what is true of <x> alone.
```

`pkg/plugintest` must never import a plugin (that would be an import cycle, since every plugin imports `pkg/plugintest`). The `conformance/` module is where the two meet; it is test-only, so plugin-module isolation still holds.

## The thirteen categories

`plugintest.AllCategories()` is the list. Each is one shared suite over one `Harness`:

| Category | What it protects |
|---|---|
| `reload` | config written by `pathConfigWrite` is re-read by `Factory`, `InitializeFunc` rehydrates + starts workers idempotently (KI-001, KI-007), and a persisted minter set that is invalid or from a newer schema is refused rather than loaded fail-open (A29, A30) |
| `lease` | the response envelope and the lease core acts on agree — renewability and TTL — `internal_data` survives JSON (KI-008), the declared `SecretType`/`LeaseInternalDataKeys`/`CredentialKeys`/`ScopeKind`/`CredentialKind` are what the plugin actually emits, and a caller may PIN the credential shape it can parse — a mismatch is refused before anything is minted (A28, A30) |
| `perturbation` | a lease survives its minter disappearing mid-life (KI-002 class) |
| `revoke` | revoke is idempotent; a second revoke is a clean no-op; and a revoke that *cannot* succeed (an `internal_data` key a newer binary renamed) releases the lease instead of retrying forever |
| `capability` | the mint-then-delete probe rejects an incapable minter at *write* time, leaves no residue, respects `verify_minter_capability=false`, skips disabled roles, reuses a recent verdict rather than re-minting, and is refused while the cloud is throttling us (A29) |
| `minter-visibility` | a minter's recovery state is durable and readable from the minter-set endpoint, so an operator can see WHICH minter is failing (A25, A27) |
| `reconciler-safety` | the reconciler never touches an entity outside the owner-tag scheme, `dry_run` deletes nothing, two mounts sharing one cloud account never reclaim each other's live credentials (A19), and `/reconcile` answers in the one uniform schema (A28) |
| `error-taxonomy` | every error a client can receive carries a code from `credenvelope.AllCodes()`, and the code says what the client should *do* |
| `containment` | the two levers an operator has when issued credentials have leaked: `disabled=true` is settable through the role's own write path and stops issuance at once (with nothing but the flag, and while the cloud refuses to mint), and `roles/<name>/revoke-upstream` deletes what the role already issued — on an already-disabled role, dry-running without deleting, idempotently, leaving the role issuing, in one uniform report — and *refuses* with `unsupported` where the cloud cannot delete an issued credential |
| `rotation` | a credential SHARED by every reader and replaced on the plugin's own schedule: a read re-serves rather than mints, the lease is non-renewable and cannot outlast the overlap, one lease ending deletes nothing, an overdue credential is replaced on the next read, and the replaced one keeps working through the overlap and is gone afterwards |
| `provenance` | WHO obtained a credential: the tracking record carries the caller core resolved (`requested_by_token_accessor`, `requested_by_entity_id`), a caller supplying those fields itself does NOT get them recorded, and a role may set `require_caller_identity` to refuse a caller this mount cannot name — before a minter is selected, so a refusal leaves no orphan |
| `inventory` | the `issued/` listing: every outstanding credential appears keyed by its upstream id with the role and the caller that obtained it, a revoked one leaves, the cursor pages without losing or repeating an entry, an over-large page is refused — and **no credential material appears**, asserted against the material actually issued rather than against a list of field names, because this endpoint is the one place a tracking record becomes public |
| `lineage` | WHOSE unit obtained a credential: the record carries the caller's PARENT (`requested_by_parent_entity_id`, `requested_by_unit_id`, `requested_by_lineage_source`) read only from the identity store — not from anything the request can carry, which is narrower than "nothing a client can write": see the approle caveat in `pkg/lineage`'s package doc — a caller supplying its own parent is refused not served AND is not recorded either, a role may set `require_caller_lineage` to demand one and reports it back on a read, and a parent entity an operator has DISABLED stops issuance at once — with no role write, no config write and no worker tick between the two reads, which is the whole point of `live_parent` |

`error-taxonomy` is the second category **no cloud may opt out of** (its `requires`
returns nothing, like `lease`, `provenance`, `inventory` and `lineage`). Individual cases that need a knob — a mint refusal, a
forced upstream status — skip themselves *with a printed reason*, so a cloud lacking a
knob still gets the cases that need none. It earned its place on its first run by
finding that OVH's error classifier had no 5xx branch at all, so a cloud returning 500
still read as `internal`. Two rules come with it:

- **An `error_code` is added only if a client would act differently.** Four actions
  exist — retry now, retry later, fix config and don't retry, page a human. A code that
  does not change one of those is documentation, not protocol.
- **`api_version` does not version the error vocabulary, and cannot.** A code travels in
  the error string; an error response carries no envelope; `api_version` lives only
  inside an envelope, so it is absent from exactly the responses codes appear in. The
  vocabulary is additive, clients must treat an unknown code as `internal`, and
  `api_version` keeps meaning one thing: the envelope's shape.

`lease` is the third category **no cloud may opt out of**: it needs no cloud-specific
`Harness` field, so a skip could only ever mean "this plugin lies to its clients".
Its load-bearing assertion is renewability, because `framework.Secret.Renewable()`
is `(Renew != nil)` and OpenBao **revokes a lease whose renewal fails** — so a
`Renew` callback that only ever returns an error still advertises `renewable=true`
and destroys the credential a client tried to keep. The only way to say "not
renewable" is to register no callback. Never "fix" a renewability failure by
assigning `resp.Secret.Renewable = false`; remove the callback.

`containment` requires only `RolePath`, so effectively no cloud opts out; the cases that
need an issued credential to delete gate themselves on `ExpectsHardRevoke` and print why.
Two of its assertions exist because the *natural* implementation breaks them. A purge built
on the plugin's own role loader answers an operator's second call with `role_disabled`,
leaving them to re-enable the role — reopening issuance mid-incident — to destroy what
leaked; hence `RevokingUpstreamWorksOnADisabledRole`, which was proven to catch exactly that
by injecting the refusal into one plugin and watching the case fail. And on a cloud that
cannot delete an issued credential, the endpoint must **refuse** rather than report zero
deletions: a clean report is what a responder reads as containment. When adding a cloud, the
question to answer is which lever it has — deletion, a rotation slot, or nothing but the
role's `max_ttl` — because the refusal has to name it.

`rotation` is the opposite shape: **one subject runs it and eleven declare it a gap**, and that
is the correct distribution rather than an under-wired category. Where every read mints, the
lease that read a credential owns it outright, so there is nothing held in common to replace on
a schedule and no window in which a replaced credential must keep working — the skip reason is
one fact about the lifecycle, shared by ten of the eleven rather than paraphrased ten times.
(OCI declares its own: it *does* share a credential and *does* replace it on a schedule, but two
auth tokens per user is the whole budget, so a rotation deletes the slot's credential as it
replaces it and there is no overlap to assert.) Its four `Harness` seams —
`ForceRotationDue`, `ForcePastRotationCeiling`, `ForceOverlapExpired`,
`SweepRetiredCredentials` — **backdate the stored
deadlines and then make the ordinary call**, deliberately: the periods are days, and a fake
clock would prove the suite's own arithmetic instead of the plugin's, while the stored deadline
is the same durable state a restart rehydrates. The category also carries two facts the
per-lease categories conflate — see the `ExpectsHardRevoke`/`DeletesIssuedCredentials` note in
[`docs/decisions.md`](docs/decisions.md); a lease ending and an operator purging are different
questions the moment a credential is shared.

**Durability of an issued credential is settled and documented** — see
[`docs/decisions.md`](docs/decisions.md) ("Durability of an issued credential, and where orphans
come from"). Short version: core persists the lease synchronously before the client sees anything,
and revokes through the plugin if that write fails, so no plugin needs to arrange it. What a plugin
IS responsible for is the `active-*/` tracking record — and revoking immediately if that write
fails, which the `revoke` category now asserts via `Harness.TrackingPrefix` — the same field the
`provenance` and `inventory` categories read, so it is load-bearing on the no-revoke clouds too. Note the prefixes are
not uniform across clouds; declaring the wrong one yields a green test that asserts nothing.

Adding a category means: a `Run<X>Suite` in `pkg/plugintest`, an entry in the `suites` registry in `conformance.go` naming the `Harness` fields it needs, and then every harness in the table — twelve subjects across ten clouds — either wiring those fields or declaring the gap. That last step is the point — a new category cannot land half-applied.

## The layer above: `e2e/`

`e2e/` (build tag `e2e`, `make test-e2e`) builds each plugin binary, registers it
in a live `bao server -dev`, and drives it over HTTP: config → minter set → role →
issue → lease lookup → renew → revoke → `bao plugin reload` → re-issue. The cloud
fake runs in the *test* process, so upstream state is still directly assertable.

It exists for the things the in-process table structurally cannot see: the plugin
**process** boundary (everything JSON-round-trips), and OpenBao **core** (mount
table, expiration manager, plugin lifecycle, core-assigned `req.ID`). Both live
defects it found — workers never starting on a rehydrated backend, and the
renewability lie above — were invisible to every in-process test.

The scenario itself is **`baotest.RunScenario`** in
[`pkg/baotest/scenario.go`](pkg/baotest/scenario.go), not in this module. `e2e/` is a
registry plus one vocabulary file per driven subject, each returning a `baotest.Case`: the
three write bodies, the TTL and renewability contract, whether the plugin tracks each issued
credential (`TracksIssuedCredentials`, which is what makes the `issued/` inventory assertable over
HTTP), what a lease ending and an operator's
purge each do to the credential, whether the credential is shared, and a `func() int` reading
the fake's count. `Case` is to this layer exactly what `plugintest.Harness` is to conformance.

Adding a cloud therefore means writing a `Case`, never writing assertions. If you find
yourself adding an assertion to a case file, it belongs in `pkg/baotest/scenario.go`
where every consumer gets it — the reason it moved there is that a second
repository wrote its own version and quietly omitted a third of the checks
([`docs/openbao-integration-gaps.md`](docs/openbao-integration-gaps.md), "The scenario
is importable too").

Rules of thumb:

- **An invariant that can be expressed in-process belongs in `pkg/plugintest`,
  not here.** e2e is slow (a server per cloud), needs `bao` on `PATH`, and is the
  wrong place to fence a regression. When e2e finds something, the fix ships with a
  conformance assertion — that is how the `lease` category came to exist.
- Clouds that cannot be reached are **declared in the e2e registry**, same
  discipline as `Harness.Skips`: AWS/GCP/OCI inject clients rather than talking to
  an HTTP endpoint, so they have nothing to point at a fake (G8 in
  [`docs/openbao-integration-gaps.md`](docs/openbao-integration-gaps.md)). The
  matrix prints the gap rather than covering seven clouds and implying ten.
- Above e2e sits the real-cloud layer, whose purpose is proving the fakes are
  realistic; planned in
  [`docs/free-account-viability.md`](docs/free-account-viability.md) and started on
  **DigitalOcean and AWS** (`plugins/credential-do/real_cloud_test.go` and
  `plugins/credential-aws/real_cloud_test.go`, the two files carrying `cloud_real`,
  run by `make test-cloud-real-do` / `make test-cloud-real-aws`). Do not cite the tag
  as coverage for the other eight clouds. Rules for adding one: it must **fail, not
  skip**, when its credential env var is missing (the build tag is the opt-in, so a
  run that passes without credentials proves nothing); it must confine itself to
  the owner-tag prefix and sweep leftovers; it must drive the **plugin's own
  client**, so response decoding is under test; and it must record every response
  through the fail-closed scrubber, because a real-cloud run is only worth its
  credentials if it leaves credential-free evidence behind. Recordings are
  committed to a public repo, so the scrubber refuses to write **anything** bearing
  a credential *or* the account's identity (an email address fails the write; UUIDs
  are replaced) — a real account answers with more than protocol.
  Its failure messages carry the interpretation — which statuses are conclusive
  about the endpoint and which only about privilege — since that is the difference
  between a finding and a wall of 403s. When a probe *settles* its question,
  rewrite it to **pin the answer** rather than deleting it or leaving it red: the DO
  probe now asserts the fence it found (KI-009) and fails loudly, with instructions,
  if DigitalOcean ever lifts it. A permanently-failing real-cloud test teaches
  people to ignore the layer.
- **A recording is only worth having if something asserts on it.** DO's are replayed
  against the fake by `plugins/credential-do/fake_parity_test.go`, an ordinary
  credential-free test: it drives the fake to the same state and compares bodies, so
  the fake cannot drift back to inventing friendlier errors than the real cloud
  sends. A recording that is neither asserted nor listed in `unassertable` **with a
  reason about the fake's design** fails that test — the same discipline as
  `Harness.Skips`. That test earns its keep: it failed the moment AWS's recordings
  landed, because the 400 was unasserted, and asserting it is what produced KI-010.
- **Inject the recorder through a seam production code already has.** AWS's probe
  passes an `sts.Options` mutator to the per-call variadic the `STSClient` interface
  already exposes, so the plugin's own client, credentials, signing and decoding are
  all under test with nothing added for the test's benefit. Reach for a new exported
  seam only when there is genuinely no existing one.
- **An injected-client plugin cannot have body-level fake parity** (AWS, GCP, OCI —
  G8: there is no HTTP fake to replay against). Assert at the level that *is* shared
  instead: `plugins/credential-aws/fake_parity_test.go` holds `fakeSTSClient` to the
  set of response elements real STS sends, which still catches the bug class that
  matters — the plugin reading a field the cloud does not send, or the fake
  populating one it does not. Do not let "no HTTP fake" become "no parity check".

## Non-negotiables

1. **A new plugin is not complete until it is in `registry` in `conformance/conformance_test.go`.** `TestEveryPluginIsRegistered` reads `../plugins` from disk and fails both ways (on disk but unregistered; registered but not on disk).
2. **Never write `t.Skip` for a category.** Declare it in `Harness.Skips` with a reason that says why the invariant does not apply *to that cloud*. `ValidateHarness` rejects an empty reason, an unknown category name, and a category that is neither wired nor declared. `TestConformanceMatrix` prints every declared gap as one line, so gaps are reviewable in one place instead of buried in ten files.
3. **A skip reason must be about the cloud, not about effort.** "AWS reconcile prunes local tracking entries only, STS sessions are not upstream entities" is a reason. "not wired up yet" is a TODO pretending to be a reason — wire it instead.
4. **Fix a bug in all ten, or in the shared suite.** If you fix a plugin and cannot express a test for it in `pkg/plugintest`, say why in the commit message. Nine other plugins probably have the same bug.
5. **Never build an error response without a code.** `credenvelope.ErrorResponse`
   takes an `ErrorCode` as its first argument, so it cannot be called without one, and
   `logical.ErrorResponse` is **forbidden by lint** (`forbidigo`) outside
   `pkg/credenvelope`. That is deliberate: 166 code-less responses accumulated while the
   rule was only a convention, and a missing code is invisible in review — it looks
   exactly like a message that happens to lack a prefix. If a new code is genuinely
   needed, add it to `AllCodes()` and to the tables in `docs/techrfc.md` and
   `docs/design.md` in the same change.
6. **Cloud fakes go in `pkg/credenvelope/fakes/`, never mocks.** Deny knobs there are deliberately *sticky* (they model a standing upstream authorization state) and must be *mint-only* where the cloud's health check is a different endpoint — that asymmetry is the whole point of the capability category. Restore them with `t.Cleanup`; a fake server is shared by every subtest in a category.
7. **`context.Background()` does not appear in a test.** Use `t.Context()`: it is cancelled when the test ends, so a hung upstream call or a worker that outlives its test fails loudly instead of hanging or leaking into the next test. Two exceptions, both explicit: work inside `t.Cleanup` needs `context.WithoutCancel(...)`, because `t.Context()` is *already* cancelled by the time cleanups run (that is what makes the DO probe's token deletion still happen); and a fake's handler should pass the caller's `ctx` through rather than mint a new one. The only legitimate `context.Background()` in the repo is each plugin's `baseCtx` root in `backend.go` — a worker's lifetime is the backend's, and the contexts available where workers start are request contexts core cancels on return. That is commented at all ten sites; don't "tidy" it away, and don't add an eleventh root.
8. **A persisted struct with lifecycle fields embeds `cloudconfig.Versioned`, stamps it on every write, and checks it on every load.** Everything here mutates by read-struct → change a field → write the WHOLE struct back, and `encoding/json` drops fields it does not know — so a binary that predates a field silently *erases* it. On a minter set that is A13 all over again by version skew (dropping `retired`/`retired_at` un-retires a rotated-out minter and cancels the sweep that was going to delete its upstream credential). `CheckSchema` refuses an entry from a *newer* schema rather than downgrading it; an absent or older version is fine. `MinterSet` and `PluginConfig` carry it today, and the reload category proves both halves — an unknown field must survive, and issuance must not proceed from an entry this binary cannot safely rewrite.
9. **The lease contract is declared as data, not inferred.** `Harness.SecretType` and `Harness.LeaseInternalDataKeys` pin the two strings an upgrade can rename with nothing else noticing: `framework.Secret.Type` is how core routes a revoke back to a callback, and an `internal_data` key is how revoke finds what to delete. Renaming either orphans every live lease. And a revoke that cannot possibly succeed — a key that is absent will be absent on every retry — must release the lease rather than return an error, because OpenBao retries a failed revoke forever (KI-002's wedge, reached by version skew).
10. **A harness must inject its fake through `Harness.Inject`, not by calling `Factory` itself.** `Inject` is re-applied on every backend instance, including the reload the `reload` category performs. Injected-client plugins (AWS, GCP, OCI) used to skip `reload` for exactly this reason; that skip is gone and must not come back.

## Where per-cloud vocabulary lives

Keep the cloud's own words in the cloud's own files. A harness adapter should read as a translation, not as a second implementation:

- mint shapes, ACL/scope/apiId strings, role field names → `conformance/harness_<cloud>_test.go` consts
- tests that touch unexported symbols → the plugin's internal test package (`capability_test.go` is internal in 8 of 10 plugins for this reason)
- anything asserting on an upstream request body or error payload → the plugin, not the shared suite

## Practicalities

```bash
go test -race github.com/nicois/openbao-cloud-creds/...   # everything (use full paths; ./... does not cross the workspace)
make test-conformance                                     # the matrix, then the table under -race
make test-e2e                                             # plugin binaries in a live `bao server -dev` (needs `bao` on PATH)
make lint                                                 # golangci-lint v2 over every module incl. conformance and (tagged) e2e
make build-standalone                                     # every module under GOWORK=off — how a consumer outside this checkout builds it
make install-hooks                                        # core.hooksPath -> .githooks (history + release-tag guards)
make check-release-tags VERSION=v0.5.0                    # after tagging: every module tagged, at one commit, annotated
```

**Releasing.** The set is tagged in lockstep, `<module dir>/vX.Y.Z` for every directory under
`pkg/` and `plugins/` holding a `go.mod` (32 today) — and a tag cannot be corrected once pushed,
only superseded, because the module proxy caches a version's content permanently. The guards sit
on both sides of the tag, because neither half is checkable at the same moment:

| when | what | where |
|---|---|---|
| every commit | every internal require names ONE version | `TestEveryModuleAgreesOnOneVersion` (conformance) |
| every commit | every module builds with no workspace | `make build-standalone` in CI |
| before `git push --tags` | the whole tag set exists, at one commit, annotated | `.githooks/pre-push` |
| after the tags are pushed | the same, unskippable | the `release-tags` CI job |

The last two call `make check-release-tags`, which derives the module list from disk, so a module
added since the last release cannot be left out silently. The CI job re-fetches for two minutes
before failing: `git push --tags` starts one run per tag, and the earliest of them legitimately
begin before their siblings' refs exist.

Note what CI on the release commit itself cannot tell you: every module reaches its siblings
through `replace ../<sibling>`, so a stale require is invisible in this checkout and authoritative
outside it. That is why the require-version test exists at all, and why `build-standalone` runs
with `GOWORK=off` rather than trusting a green workspace build.

Lint applies to `pkg/plugintest` as **non-test** code: `revive function-length [60,0]`, `funlen 80/50`, `revive max-public-structs [5]`, `gocyclo 15`. Long suites get split into named helpers, one per assertion — which reads better anyway. Zero `//nolint` in this repo; keep it that way.

A **build-tagged module is invisible to plain `golangci-lint`**, which is why `make lint` runs a second pass with `--build-tags=e2e` over `TAGGED_LINT_DIRS`. Add any future tagged module to that variable, or its code is unlinted while looking covered. CI calls `make lint` rather than keeping its own module list, because that copy had already drifted.

Do not add dependencies to `conformance/go.mod` to reach a cloud SDK type. Export a test seam from the plugin instead (see `credentialaws.NewSwitchableSTSClient`), so the SDK stays inside the module that already depends on it.
