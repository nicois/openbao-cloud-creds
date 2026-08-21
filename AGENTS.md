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

## The five categories

`plugintest.AllCategories()` is the list. Each is one shared suite over one `Harness`:

| Category | What it protects |
|---|---|
| `reload` | config written by `pathConfigWrite` is re-read by `Factory` (KI-001 class) |
| `perturbation` | a lease survives its minter disappearing mid-life (KI-002 class) |
| `revoke` | revoke is idempotent; a second revoke is a clean no-op |
| `capability` | the mint-then-delete probe rejects an incapable minter at *write* time, leaves no residue, respects `verify_minter_capability=false`, and skips disabled roles |
| `reconciler-safety` | the reconciler never touches an entity outside the owner-tag scheme, and `dry_run` deletes nothing |

Adding a category means: a `Run<X>Suite` in `pkg/plugintest`, an entry in the `suites` registry in `conformance.go` naming the `Harness` fields it needs, and then ten harnesses that either wire those fields or declare the gap. That last step is the point — a new category cannot land half-applied.

## Non-negotiables

1. **A new plugin is not complete until it is in `registry` in `conformance/conformance_test.go`.** `TestEveryPluginIsRegistered` reads `../plugins` from disk and fails both ways (on disk but unregistered; registered but not on disk).
2. **Never write `t.Skip` for a category.** Declare it in `Harness.Skips` with a reason that says why the invariant does not apply *to that cloud*. `ValidateHarness` rejects an empty reason, an unknown category name, and a category that is neither wired nor declared. `TestConformanceMatrix` prints every declared gap as one line, so gaps are reviewable in one place instead of buried in ten files.
3. **A skip reason must be about the cloud, not about effort.** "AWS reconcile prunes local tracking entries only, STS sessions are not upstream entities" is a reason. "not wired up yet" is a TODO pretending to be a reason — wire it instead.
4. **Fix a bug in all ten, or in the shared suite.** If you fix a plugin and cannot express a test for it in `pkg/plugintest`, say why in the commit message. Nine other plugins probably have the same bug.
5. **Cloud fakes go in `pkg/credenvelope/fakes/`, never mocks.** Deny knobs there are deliberately *sticky* (they model a standing upstream authorization state) and must be *mint-only* where the cloud's health check is a different endpoint — that asymmetry is the whole point of the capability category. Restore them with `t.Cleanup`; a fake server is shared by every subtest in a category.
6. **A harness must inject its fake through `Harness.Inject`, not by calling `Factory` itself.** `Inject` is re-applied on every backend instance, including the reload the `reload` category performs. Injected-client plugins (AWS, GCP, OCI) used to skip `reload` for exactly this reason; that skip is gone and must not come back.

## Where per-cloud vocabulary lives

Keep the cloud's own words in the cloud's own files. A harness adapter should read as a translation, not as a second implementation:

- mint shapes, ACL/scope/apiId strings, role field names → `conformance/harness_<cloud>_test.go` consts
- tests that touch unexported symbols → the plugin's internal test package (`capability_test.go` is internal in 8 of 10 plugins for this reason)
- anything asserting on an upstream request body or error payload → the plugin, not the shared suite

## Practicalities

```bash
go test -race github.com/nicois/openbao-cloud-creds/...   # everything (use full paths; ./... does not cross the workspace)
make test-conformance                                     # the matrix, then the table under -race
make lint                                                 # golangci-lint v2 over every module incl. conformance
```

Lint applies to `pkg/plugintest` as **non-test** code: `revive function-length [60,0]`, `funlen 80/50`, `revive max-public-structs [5]`, `gocyclo 15`. Long suites get split into named helpers, one per assertion — which reads better anyway. Zero `//nolint` in this repo; keep it that way.

Do not add dependencies to `conformance/go.mod` to reach a cloud SDK type. Export a test seam from the plugin instead (see `credentialaws.NewSwitchableSTSClient`), so the SDK stays inside the module that already depends on it.
