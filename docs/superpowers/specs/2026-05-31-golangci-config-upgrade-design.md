# golangci-lint Config Upgrade — Design Spec

**Status:** Approved (2026-05-31)
**Goal:** Adopt the stricter `qualcheck/.golangci.yml` ("slow accretion" smell config) as this repo's lint config, reconciled with this repo's deliberate existing exclusions, and bring all 17 modules to **0 lint issues**.

## Background

The repo's current `.golangci.yml` enables 9 linters (errcheck, govet, staticcheck, unused, ineffassign, misspell, unconvert, unparam, revive) and is clean. The target config (`/home/claude-aiven-2/code/qualcheck/.golangci.yml`, golangci-lint **v2**) adds ~16 more linters grouped into four "code-smell" families: growth/complexity (gocyclo, gocognit, cyclop, funlen, nestif, maintidx), boolean/flag/enum params (revive ruleset, mnd, goconst, exhaustive), copy-paste (dupl, dupword, gocritic), and dead/comment-rot (unused, unparam, ineffassign, wastedassign, godox, godot, predeclared).

Running the target config verbatim across all 17 modules (6 `pkg/` + 10 plugins + `pkg/plugintest`) with golangci-lint v2.12.2 produced **965 findings**. After applying the reconciliations in Section 1, **~434 production findings** remain to fix by hand.

## Decisions taken (from brainstorming)

- **Config policy:** carry forward this repo's deliberate exclusions (not strict-verbatim).
- **mnd/goconst scope:** full — introduce named constants for every magic number and repeated literal in **production** code.
- **Complexity refactors:** refactor to comply (behavior-preserving), not threshold-tuning.
- **Execution:** plan properly via writing-plans → subagent-driven-development, on a worktree branch, same as audit batches 1 & 2.

## Section 1 — Config reconciliation

The adopted `.golangci.yml` = the qualcheck config **plus** these carried-forward deltas:

1. **Keep `formatters: [gofmt, goimports]`** (present in current config, absent from qualcheck).
2. **Keep `run: timeout: 5m`** (from current config).
3. **Re-add `errcheck.exclude-functions`** for `(io.Closer).Close` and `(net/http.ResponseWriter).Write`. All 29 `errcheck` findings are `resp.Body.Close()`; this matches the existing deliberate decision and clears them.
4. **Disable revive rules `unused-parameter` and `unused-receiver`** by appending `{name: unused-parameter, disabled: true}` and `{name: unused-receiver, disabled: true}` to the qualcheck `revive.rules` list. These conflict with OpenBao SDK handler signatures (`func(ctx context.Context, req *logical.Request, d *framework.FieldData)`) where unused params are mandatory and documentary. Clears 111 findings.
5. **Extend the test-file exclusion** from qualcheck's `[funlen, gocyclo, gocognit, dupl, maintidx]` to additionally include `goconst, mnd, revive, cyclop`. Test code legitimately repeats literals and is structurally complex. Clears ~414 test findings.

**Confirmed config semantics:** the qualcheck config supplies an explicit `revive.rules` list, which *replaces* revive's default rule set. Therefore `exported` and `package-comments` (disabled in the current config) do not fire under the new config and need no explicit disable. Verified empirically with golangci-lint v2.12.2.

The final config file is otherwise the qualcheck file byte-for-byte (same linters, same settings, same thresholds, same `gocritic` tags with `hugeParam` disabled).

## Section 2 — Remediation phasing

All work happens on one worktree branch. CI lint will be red until the final phase completes, so the new config and all fixes land together before merge.

Within each phase, work **module-by-module in dependency order** (`pkg/` modules before plugins), so each commit is self-contained and the targeted linter family reaches 0 in that module. Per-module isolation matches how CI lints (per-module loop) and respects the module-isolation invariant in `docs/decisions.md`.

### Phase 0 — Config reconciliation
Replace `.golangci.yml` with the reconciled config (Section 1). Commit. Expect CI red until later phases land; that is intentional and the branch is not merged mid-flight.

### Phase 1 — Mechanical quick wins (low risk, behavior-preserving)
Clear the small high-confidence categories:
- **gocritic** (25): `httpNoBody` ×19 → pass `http.NoBody` instead of `nil` to `http.NewRequest(WithContext)`; plus `unnamedResult` ×3, `paramTypeCombine` ×2, `ifElseChain` ×1.
- **godot** (1): add the missing period to a declaration doc comment.
- **revive** residual (11, after unused-* disabled): `cyclomatic`/`cognitive-complexity` overlap with Phase 4 (handle there); `function-result-limit` (9) and `max-public-structs`/`unhandled-error`/`confusing-naming`/`identical-branches`/`deep-exit`/`flag-parameter`/`argument-limit` as they appear — fix or, where the signature is SDK-mandated, handle case-by-case.
- **dupword / wastedassign / predeclared / ineffassign / unconvert / misspell**: any stragglers (0 observed but re-verify).

### Phase 2 — Magic numbers (`mnd`, 191)
Introduce named constants. Two dominant families:
- **HTTP status codes** (`200, 201, 204, 401, 403, 429`, etc.) → stdlib `net/http.StatusOK`, `StatusNoContent`, `StatusUnauthorized`, `StatusForbidden`, `StatusTooManyRequests`, … (no new consts needed).
- **Time/duration values** (`900, 3600, 21600, 604800` = 15m/1h/6h/7d in seconds; `30, 24, 10`, …) → `time.Duration` consts or reuse existing named defaults (e.g. `DefaultConfig` in `pkg/cloudconfig` already names several). Where a literal is a seconds-count fed to a duration, prefer `time.Duration` arithmetic (`7 * 24 * time.Hour`).
- Config ignores `0, 1, 2`; remaining incidental numerics (buffer sizes, bit widths) get a descriptive const at point of use.

### Phase 3 — Repeated literals (`goconst`, 188)
Introduce package-level consts for repeated strings/numbers in production code:
- Per-plugin literals (mount-path fragments, field names like `"minters"`, `"mode"`, `"reconcile"`, `"default"`) → a `consts.go` (or alongside existing path constants) in that plugin's package.
- Only lift a literal into a `pkg/` module if 2+ modules share the **exact same semantic constant**; otherwise keep it per-plugin (module-isolation invariant). Default to per-plugin.

### Phase 4 — Complexity & duplication refactors (the only behavior-touching phase)
~19 prod functions across `funlen` (8), `gocognit` (3), `dupl` (3), `nestif` (2), `gocyclo` (1), plus revive `cyclomatic`/`cognitive-complexity` overlaps:
- **Behavior-preserving extract-method / flatten-nesting / dedup only.** No logic changes.
- Re-run `go test -race` for the touched module after each function.
- `exhaustive` (1): a non-exhaustive enum switch — treat as a **real** finding; add the missing case(s). If a default-less switch is genuinely intentional, this is the one place a single justified `//nolint:exhaustive` with a rationale comment may be added (flagged for user review if it arises).

### Phase 5 — Final verification
Full-workspace gate (Section 3). Confirm 0 issues in all 17 modules and green `-race`.

## Section 3 — Verification, risk, success criteria

**Per-phase verification:**
- After each module's edits: `golangci-lint run --config <repo>/.golangci.yml ./...` in that module → 0 issues for the targeted family.
- After each phase: workspace `go build github.com/nicois/openbao-cloud-creds/...` + `go test -race github.com/nicois/openbao-cloud-creds/...` green.
- Constant substitutions (`200 ≡ http.StatusOK`, named const ≡ its literal) are semantically equivalent → near-zero behavioral risk. The complexity refactors (Phase 4) carry the real risk and get the most test scrutiny.

**Risk areas:**
- Phase 4 refactors are the only control-flow changes; mitigated by extract-only refactors, per-function `-race` runs, and each plugin's existing resilience-test harness.
- `exhaustive` may surface a genuinely unhandled enum case — handle as a real fix.
- Constant placement: keep per-plugin to avoid introducing new cross-module coupling.

**Success criteria:**
1. The reconciled `.golangci.yml` is the repo's sole lint config.
2. `golangci-lint run` passes with **0 issues** in all 17 modules.
3. `go build` + `go test -race` green across the workspace.
4. `make lint` (per-module loop) and CI's lint job pass.
5. **No new `nolint` directives** introduced — fixes, not suppression — except at most one justified `//nolint:exhaustive` with rationale (subject to user review).
6. CI's `govulncheck` and registration-smoke-test jobs unaffected.

**Out of scope:**
- Changing qualcheck's linter *selection* (adopted wholesale, minus the reconciled exclusions).
- The deferred audit items #5 (reconciler convergence) and #7 (cross-plugin de-dup).
- Test-file complexity/literal cleanup (excluded by config).

## Appendix — Measured baseline (golangci-lint v2.12.2, target config verbatim)

965 total findings. By linter (prod / test):

| Linter | prod | test | total |
|---|---|---|---|
| goconst | 188 | 347 | 535 |
| mnd | 191 | 0 | 191 |
| revive | 96 | 67 | 163 |
| errcheck | 21 | 8 | 29 |
| gocritic | 22 | 3 | 25 |
| funlen | 8 | 0 | 8 |
| gocognit | 3 | 0 | 3 |
| dupl | 3 | 0 | 3 |
| cyclop | 0 | 3 | 3 |
| nestif | 2 | 0 | 2 |
| godot | 1 | 0 | 1 |
| gocyclo | 1 | 0 | 1 |
| exhaustive | 1 | 0 | 1 |

revive sub-rules: unused-parameter 74, unused-receiver 37, cyclomatic 36, function-result-limit 9, cognitive-complexity 5, unhandled-error 1, max-public-structs 1.

**After Section 1 reconciliation — ~434 prod findings remain** (mnd 191, goconst 188, gocritic 25, revive 11, funlen 8, gocognit 3, dupl 3, nestif 2, gocyclo 1, godot 1, exhaustive 1), concentrated in `pkg/credenvelope` (62) and the 10 plugins (32–43 each); `pkg/{cloudconfig,reconciler,metrics,recovery}` carry ≤5 each; `pkg/worker` and `pkg/plugintest` are already clean.
