# golangci-lint Config Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adopt the stricter `qualcheck/.golangci.yml` (reconciled with this repo's deliberate exclusions) and bring all 17 modules to 0 lint issues.

**Architecture:** Phase 0 swaps in the reconciled config (CI lint goes red, expected). Phases 1–4 then clear ~434 production findings module-by-module: mechanical quick wins, magic-numbers→named-consts, repeated-literals→consts, and behavior-preserving complexity refactors. Each module reaches `golangci-lint run → 0 issues` and the workspace stays `go test -race` green throughout.

**Tech Stack:** Go 1.26.x workspace (`go.work`, per-module `go.mod`), golangci-lint **v2.12.2**, OpenBao SDK v2.

**Reference spec:** `docs/superpowers/specs/2026-05-31-golangci-config-upgrade-design.md`

---

## How to work this plan

- **Worktree:** all work on one branch (created by the execution skill). Never touch `main`. Confirm `git branch --show-current` before every commit.
- **Per-module commands** (golangci-lint does NOT span `go.work`):
  ```bash
  export PATH="$(go env GOPATH)/bin:$PATH"
  (cd <module-dir> && golangci-lint run ./...)      # MUST be the REPO's reconciled .golangci.yml
  ```
  golangci-lint auto-discovers `.golangci.yml` by walking up from the module dir to the repo root, so after Task 1 every module uses the reconciled config automatically — do NOT pass `--config`.
- **Workspace build/test** (use full module path, NOT `./...`):
  ```bash
  go build github.com/nicois/openbao-cloud-creds/...
  go test -race github.com/nicois/openbao-cloud-creds/...
  ```
- **Definition of done for a module:** `golangci-lint run ./...` in that module prints `0 issues.` and the workspace test suite is green.
- **No new `//nolint`** except the single `exhaustive` case in Task 4 (and only if justified there).

---

## Shared Conventions (referenced by every task — read once)

These patterns are applied repeatedly. Each task below names its findings and points here for the *how*.

### C1 — HTTP status codes (`mnd`)

Replace integer HTTP status literals with `net/http` constants (add `"net/http"` to imports if absent). No new constants are defined — these are stdlib.

| literal | constant |
|---|---|
| 200 | `http.StatusOK` |
| 201 | `http.StatusCreated` |
| 204 | `http.StatusNoContent` |
| 400 | `http.StatusBadRequest` |
| 401 | `http.StatusUnauthorized` |
| 403 | `http.StatusForbidden` |
| 404 | `http.StatusNotFound` |
| 429 | `http.StatusTooManyRequests` |
| 500 | `http.StatusInternalServerError` |

Example:
```go
// before
if resp.StatusCode == 200 {
// after
if resp.StatusCode == http.StatusOK {
```

### C2 — TTL / duration seconds (`mnd`)

The recurring numbers `900, 3600, 21600, 86400, 604800` are second-counts used as `framework.FieldSchema` `Default:` values (the SDK's `TypeDurationSecond` expects integer seconds). Define a named `const` block, in seconds, with a duration comment, in the file that declares the schema (usually `path_config.go` or `path_roles.go`). Per-plugin (do NOT lift to `pkg/`).

```go
const (
	defaultLeaseTTLSeconds = 900     // 15m
	maxLeaseTTLSeconds     = 21600   // 6h
	oneHourSeconds         = 3600    // 1h
	oneDaySeconds          = 86400   // 24h
	sevenDaysSeconds       = 604800  // 7d
)
```
Only define the consts a given module actually needs (don't add unused ones — `unused` linter will flag them). Use the existing naming if the module already names a duration nearby. For `mnd` hits that are genuine durations in Go code (not schema seconds), prefer `time` arithmetic, e.g. `7 * 24 * time.Hour` instead of a magic `604800`.

### C3 — Other recurring numerics (`mnd`)

- `5` (retry/backoff counts, e.g. `maxRetries`), `10` (`MaxDeletesPerPass`-style), `30` (timeout seconds), `24` (hours/day), `16`, `8`, `64`, `100`, `1000`, `5000`: define a descriptive `const` at point of use with a comment, e.g. `const httpClientTimeoutSeconds = 30`. Config already ignores `0, 1, 2`.
- If the value already has a named field default elsewhere (e.g. `pkg/cloudconfig.DefaultConfig` sets `MaxDeletesPerPass: 10`), reference that path's constant rather than inventing a new one only when it's genuinely the same semantic value and importing is clean; otherwise a local const is fine.

### C4 — Repeated string literals (`goconst`)

Two kinds:

1. **Schema field names / cloud identifiers** repeated across a plugin (`"minter_set"`, `"cloud"`, `"role"`, `"name"`, `"cloud_creds"`, and the cloud's own name like `"do"`/`"aws"`): define package-level consts in a new `consts.go` in that plugin package:
   ```go
   package credentialdo

   const (
       cloudName       = "do"
       fieldMinterSet  = "minter_set"
       fieldCloud      = "cloud"
       fieldRole       = "role"
       fieldName       = "name"
       ownerTagPrefix  = "cloud_creds"   // matches owner-tag scheme; reuse existing if present
   )
   ```
   **Check first** whether the plugin already defines any of these (e.g. an existing cloud-name const or owner-tag constant) — reuse it, don't duplicate. The `workerErrorHandler` added in the audit-batch2 work already hardcodes the cloud string; point it at `cloudName` too if that removes a goconst occurrence.
2. **JSON field keys in `pkg/credenvelope`** (`"error"`, `"message"`, `"access_token"`, `"name"`, `"account"`, `"code"`, etc.): these are response/parse keys in the cloud-fake and parsing code. Define consts in the file that uses them (per-cloud file under `pkg/credenvelope/`), e.g. `const jsonKeyError = "error"`. Keep them in the file that owns them.

Use the const everywhere the literal appeared (goconst counts occurrences across the package; all must be replaced to clear it).

### C5 — `function-result-limit` (revive) — the 4-return `selectMinter`

Every plugin has a helper like:
```go
func (b *backend) selectMinter(setName string) (setID, minterID string, client *doClient, err error) {
```
returning 4 values (limit is 3). Introduce a small named result struct in the same file and return it + error:
```go
type selectedMinter struct {
	setID    string
	minterID string
	client   *doClient   // the plugin's client type
}

func (b *backend) selectMinter(setName string) (selectedMinter, error) {
	...
	return selectedMinter{setID: id, minterID: mid, client: c}, nil
}
```
Update all call sites (usually one, in `pathCredsRead`). This is behavior-preserving. The client field type differs per plugin (`*doClient`, `*awsClient`, …).

### C6 — `pathCredsRead` too long (`funlen`)

Each plugin's `pathCredsRead` exceeds 80 lines. Extract cohesive blocks into helpers (behavior-preserving, same package, same `b` receiver). Natural seams, in order of appearance:
1. **role load + validation** → `func (b *backend) loadRole(ctx, req, roleName string) (*<plugin>Role, *logical.Response, error)` (returns an error-envelope response for not-found/disabled, or the role).
2. **mint call + envelope build** → keep in `pathCredsRead` or extract `func (b *backend) buildCredsResponse(...)`.
Re-run the plugin's tests after extraction. Do NOT change observable behavior (same responses, same error codes, same lease data).

### C7 — gocritic

- `httpNoBody` (×16): in `http.NewRequest`/`http.NewRequestWithContext` calls passing `nil` as the body for GET/DELETE, pass `http.NoBody` instead.
  ```go
  // before
  http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
  // after
  http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
  ```
- `unnamedResult` (×3): functions returning multiple same-type results (e.g. `(string, int, error)`) — add names to the result params in the signature: `(token string, expiresIn int, err error)`.
- `paramTypeCombine` (×2): adjacent params of the same type — combine, e.g. `(a string, b string)` → `(a, b string)`.
- `ifElseChain` (×1, `pkg/cloudconfig/minter.go:51`): convert the if/else-if chain to a `switch`.

### C8 — godot (×1)

`plugins/credential-akamai/edgegrid.go:24` — add a trailing period to the declaration doc comment.

---

## Task 1: Reconcile and install the config (Phase 0)

**Files:**
- Modify: `/.golangci.yml` (repo root — full replacement)

- [ ] **Step 1: Replace `.golangci.yml` with the reconciled config**

Write the repo-root `.golangci.yml` to exactly this content:

```yaml
# golangci-lint v2 config tuned for "slow accretion" code smells.
# Adopted from qualcheck/.golangci.yml, reconciled with this repo's deliberate
# exclusions (see docs/superpowers/specs/2026-05-31-golangci-config-upgrade-design.md).
# Run with: golangci-lint run   (golangci-lint v2.x)

version: "2"

run:
  timeout: 5m

formatters:
  enable:
    - gofmt
    - goimports

linters:
  default: standard

  enable:
    # Family 1: growth / complexity drift
    - gocyclo
    - gocognit
    - cyclop
    - funlen
    - nestif
    - maintidx
    # Family 2: boolean/flag params & enums
    - revive
    - mnd
    - goconst
    - exhaustive
    # Family 3: copy-paste & near-duplication
    - dupl
    - dupword
    # Family 4: dead / orphaned & comment rot
    - unused
    - unparam
    - ineffassign
    - wastedassign
    - godox
    - godot
    - predeclared
    - gocritic

  settings:
    errcheck:
      exclude-functions:
        - (io.Closer).Close
        - (net/http.ResponseWriter).Write
    gocyclo:
      min-complexity: 15
    gocognit:
      min-complexity: 20
    cyclop:
      max-complexity: 15
      package-average: 8.0
    funlen:
      lines: 80
      statements: 50
      ignore-comments: true
    nestif:
      min-complexity: 4
    maintidx:
      under: 20
    mnd:
      checks: [argument, case, condition, operation, return, assign]
      ignored-numbers: ["0", "1", "2"]
    goconst:
      min-len: 3
      min-occurrences: 3
      numbers: true
    exhaustive:
      default-signifies-exhaustive: true
    dupl:
      threshold: 100
    godox:
      keywords: [TODO, FIXME, HACK, BUG, OPTIMIZE]
    godot:
      scope: declarations
      capital: false
    gocritic:
      enabled-tags:
        - diagnostic
        - style
        - opinionated
        - performance
      disabled-checks:
        - hugeParam
    revive:
      rules:
        - name: argument-limit
          arguments: [5]
        - name: function-result-limit
          arguments: [3]
        - name: flag-parameter
        - name: function-length
          arguments: [60, 0]
        - name: cognitive-complexity
          arguments: [20]
        - name: cyclomatic
          arguments: [15]
        - name: max-public-structs
          arguments: [5]
        - name: unused-parameter
          disabled: true
        - name: unused-receiver
          disabled: true
        - name: deep-exit
        - name: unhandled-error
          arguments: ["fmt.Printf", "fmt.Println"]
        - name: confusing-naming
        - name: identical-branches

  exclusions:
    generated: lax
    rules:
      - path: _test\.go
        linters: [funlen, gocyclo, gocognit, dupl, maintidx, goconst, mnd, revive, cyclop]
```

- [ ] **Step 2: Validate the YAML and the config loads**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
python3 -c "import yaml; yaml.safe_load(open('.golangci.yml')); print('yaml ok')"
(cd pkg/worker && golangci-lint run ./...)   # pkg/worker is already clean → must print "0 issues."
```
Expected: `yaml ok`, and `pkg/worker` reports `0 issues.` (proves the config parses and an already-clean module passes — `golangci-lint config verify` is not relied upon).

- [ ] **Step 3: Capture the baseline finding count (for tracking, not a gate)**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
for d in pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/worker pkg/plugintest \
         plugins/credential-akamai plugins/credential-aws plugins/credential-azure plugins/credential-do \
         plugins/credential-exoscale plugins/credential-gcp plugins/credential-oci plugins/credential-ovh \
         plugins/credential-upcloud plugins/credential-vultr; do
  n=$( (cd "$d" && golangci-lint run ./... 2>/dev/null) | grep -c ':' )
  echo "$n  $d"
done
```
Expected: nonzero counts for credenvelope and the plugins; 0 for worker/plugintest. (Informational.)

- [ ] **Step 4: Commit**

```bash
git add .golangci.yml
git commit -m "build(lint): adopt qualcheck golangci config, reconciled with repo exclusions"
```

---

## Task 2: Small `pkg/` modules to zero

**Files:**
- Modify: `pkg/metrics/*.go` (mnd:3 ×1)
- Modify: `pkg/recovery/state.go` (exhaustive at :73)
- Modify: `pkg/reconciler/reconciler.go` (max-public-structs)
- Modify: `pkg/cloudconfig/minter.go:51` (gocritic ifElseChain), plus cloudconfig mnd (15,6,24,10)

- [ ] **Step 1: See the exact findings**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
for d in pkg/metrics pkg/recovery pkg/reconciler pkg/cloudconfig; do
  echo "=== $d ==="; (cd "$d" && golangci-lint run ./...)
done
```

- [ ] **Step 2: Fix `pkg/recovery` exhaustive (`state.go:73`)**

`RecordError`'s `switch sm.state` is missing the `Missing` case. The enum is `Healthy, TransientFailing, AuthFailing, Missing`. Read the function and the surrounding cases. Add an explicit `case Missing:` arm. Determine the correct behavior: when already in `Missing` state and an error is recorded, the credential is gone — recording another upstream error should leave it `Missing` (the `RecordMissing()` method is the authority for entering `Missing`). Add:
```go
	case Missing:
		// Already known-missing; an upstream error does not change that.
		// State only leaves Missing via a successful RecordSuccess.
```
If reading the code shows a different intended behavior, implement that instead — the point is an explicit, correct arm, not a silent default. Do NOT add `//nolint` here unless, after reading, a `default:`-less exhaustive switch is genuinely intended; if so, add `//nolint:exhaustive // <one-line reason>` and note it in the task report for user review.

- [ ] **Step 3: Fix `pkg/cloudconfig` ifElseChain + mnd**

`minter.go:51`: convert the if / else-if chain to a `switch` (see C7). For the mnd hits (15, 6, 24, 10) read each site and name the constant per C2/C3 (these are likely the `DefaultConfig` duration/count defaults — `15` (min for FlushInterval?), `6` (hours), `24` (hours), `10` (MaxDeletesPerPass)). Prefer `time` arithmetic for the durations (e.g. `15 * time.Minute`) and a named `const defaultMaxDeletesPerPass = 10` for the count, matching whatever `DefaultConfig` already expresses.

- [ ] **Step 4: Fix `pkg/metrics` mnd (3) and `pkg/reconciler` max-public-structs**

- metrics: name the single `3` literal per C3 (read the site; likely a `SplitN` count or similar — a descriptive local const).
- reconciler `max-public-structs` (>5 exported structs in the package): this is a package-level revive count at `reconciler.go:1`. Read the package's exported structs. Do NOT merge types just to satisfy the count if they're legitimately separate. Resolve by either (a) un-exporting structs that need not be public (preferred if any are only used within the package), or (b) if all 6+ are genuinely part of the public API, this is a real API-surface signal — un-export the ones not referenced outside `pkg/reconciler` (grep the other modules for each type name to decide). Document which were un-exported in the commit message.

- [ ] **Step 5: Verify each module is clean + workspace green**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
for d in pkg/metrics pkg/recovery pkg/reconciler pkg/cloudconfig; do
  (cd "$d" && gofmt -w . && golangci-lint run ./...) && echo "OK $d" || echo "FAIL $d"
done
go build github.com/nicois/openbao-cloud-creds/... && go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -20
```
Expected: each prints `0 issues.`; build OK; all tests pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/metrics pkg/recovery pkg/reconciler pkg/cloudconfig
git commit -m "refactor(pkg): clear lint findings in metrics, recovery, reconciler, cloudconfig"
```

---

## Task 3: `pkg/credenvelope` to zero (62 findings)

**Files:**
- Modify: `pkg/credenvelope/*.go` (mnd HTTP+time; goconst JSON keys)
- Modify: `pkg/credenvelope/fakes/{exoscale,upcloud,vultr}.go` (dupl ×3)

Findings: mnd — `1000(×3), 401(×3), 400(×3), 201(×3), 404(×3), 204(×3), 200(×3), 3600(×2), 5000, 100`. goconst — `'error'(×3), 'message'(×3), 'access_token'(×3), 'name'(×3), 'account'(×3), 'code'(×2), 'error_description'(×2)` + several single-occurrence (which won't trip the ×3 threshold; ignore those). dupl — 3 blocks in `fakes/`.

- [ ] **Step 1: See the findings**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
(cd pkg/credenvelope && golangci-lint run ./...)
```

- [ ] **Step 2: Fix mnd (HTTP codes via C1, the `3600` via C2, others via C3)**

Replace `200/201/204/400/401/404` with `http.StatusOK/Created/NoContent/BadRequest/Unauthorized/NotFound` (C1). The `3600` is one hour in seconds — name it `const oneHourSeconds = 3600 // 1h` or use `int(time.Hour.Seconds())` at the site. `1000`/`5000`/`100` — read each site (likely ms timeouts or sizes); name per C3.

- [ ] **Step 3: Fix goconst (JSON keys via C4 part 2)**

For each literal hitting ≥3 occurrences (`error`, `message`, `access_token`, `name`, `account`, `code`, `error_description`), define a const in the file that owns the parsing/response (e.g. `const jsonKeyError = "error"`) and replace all occurrences. Group related keys into a single `const (...)` block per file.

- [ ] **Step 4: Resolve the 3 `dupl` findings in `fakes/`**

The duplicated blocks are `fakes/exoscale.go:143-166` ≈ `fakes/upcloud.go:151-174` ≈ `fakes/vultr.go:141-164` (a near-identical HTTP-handler/response snippet). **Read all three blocks first.** Per CLAUDE.md the cloud-fakes are deliberately independent test scaffolding, so weigh:
  - **Preferred:** if the duplicated block is a mechanical helper (e.g. "write a JSON error response with status + body"), extract a single unexported helper in a shared `fakes/respond.go` (e.g. `func writeJSONError(w http.ResponseWriter, status int, code, msg string)`) and call it from all three. This is genuine de-dup, not coupling of the fakes' behavior.
  - **Fallback:** if extraction would entangle three intentionally-separate fakes (their shapes only coincidentally match), do NOT contort them — add a narrowly-scoped exclusion to `.golangci.yml` for `dupl` on `pkg/credenvelope/fakes/` with a comment, and note it for user review. Decide by reading; default to extraction if it yields a clean, single-responsibility helper.

- [ ] **Step 5: Verify clean + workspace green**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
(cd pkg/credenvelope && gofmt -w . && golangci-lint run ./...) && echo OK
go build github.com/nicois/openbao-cloud-creds/... && go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -20
```
Expected: `0 issues.`; build OK; tests pass (the fakes are used by every plugin's tests — a behavior change here breaks many tests, so green tests confirm the de-dup was safe).

- [ ] **Step 6: Commit**

```bash
git add pkg/credenvelope
git commit -m "refactor(credenvelope): named consts for HTTP/JSON literals; de-dup fake responders"
```

---

## Task 4: `credential-do` to zero (reference module — fully worked)

DO is the reference plugin; this task is the worked template. Findings: mnd `30(×2), 200(×2), 900(×2), 10(×2), 5(×2), 201, 204, 21600, 24, 604800, 3600`; goconst `'minter_set'(×3), 'cloud'(×2), 'role'(×2), 'scopes'(×2), 'name'(×2), 'cloud_creds'`; funlen `pathCredsRead`; function-result-limit `selectMinter`.

> Note: a `×2` goconst occurrence does NOT trip the `min-occurrences: 3` threshold by itself — only literals reaching 3 occurrences are reported. `'minter_set'` (×3) is the one certain goconst hit; verify the live list in Step 1 and only constify what the linter actually reports.

**Files:**
- Create: `plugins/credential-do/consts.go`
- Modify: `plugins/credential-do/path_config.go` (TTL seconds), `path_creds.go` (funlen, function-result-limit), `do_client.go`/`health_check.go` (HTTP codes), `telemetry.go` (cloud-name const reuse)

- [ ] **Step 1: See the exact findings**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
(cd plugins/credential-do && golangci-lint run ./...)
```

- [ ] **Step 2: Create `consts.go` and constify goconst literals (C4 part 1)**

First grep for any existing cloud-name/owner-tag const to reuse:
```bash
grep -rn '"do"\|cloud_creds\|owner' plugins/credential-do/*.go | grep -i const
```
Create `plugins/credential-do/consts.go` with ONLY the consts the linter reported (drop any unused — the `unused` linter will flag them):
```go
package credentialdo

const (
	cloudName      = "do"
	fieldMinterSet = "minter_set"
)
```
Replace every reported literal occurrence (`"do"`, `"minter_set"`, etc.) with the const, including in `telemetry.go`'s `workerErrorHandler` (point the cloud label at `cloudName`).

- [ ] **Step 3: Constify mnd — HTTP codes (C1) and TTL seconds (C2)**

In `path_config.go`, the `Default: 900` / `Default: 21600` schema values → a const block at top of the file:
```go
const (
	defaultLeaseTTLSeconds = 900   // 15m
	maxLeaseTTLSeconds     = 21600 // 6h
)
```
and reference them: `Default: defaultLeaseTTLSeconds`. In `do_client.go`/`health_check.go`, replace `200/201/204` with `http.StatusOK/Created/NoContent` (add `"net/http"` import). For the remaining numerics (`30` timeout, `10`, `5`, `24`, `3600`, `604800`) read each site and name per C2/C3 (e.g. `const httpTimeoutSeconds = 30`, `const sevenDaysSeconds = 604800 // 7d`).

- [ ] **Step 4: Fix `function-result-limit` on `selectMinter` (C5)**

In `path_creds.go`, change `selectMinter` to return a `selectedMinter` struct + error and update its call site in `pathCredsRead`:
```go
type selectedMinter struct {
	setID    string
	minterID string
	client   *doClient
}

func (b *backend) selectMinter(setName string) (selectedMinter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	states, ok := b.minterSets[setName]
	if !ok {
		return selectedMinter{}, fmt.Errorf("upstream_auth_failed: minter set %q not loaded", setName)
	}
	// ... existing selection logic, returning selectedMinter{...} on success
}
```
Update the caller to use `sel, err := b.selectMinter(...)` then `sel.client`, `sel.setID`, `sel.minterID`.

- [ ] **Step 5: Fix `funlen` on `pathCredsRead` (C6)**

Extract the role load+validation block into a helper:
```go
func (b *backend) loadRole(ctx context.Context, req *logical.Request, roleName string) (*doRole, *logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, nil, err
	}
	if entry == nil {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName), nil
	}
	var role doRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, nil, err
	}
	if role.Disabled {
		return nil, credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName), nil
	}
	return &role, nil, nil
}
```
and in `pathCredsRead`:
```go
	role, errResp, err := b.loadRole(ctx, req, roleName)
	if err != nil || errResp != nil {
		return errResp, err
	}
```
If still >80 lines, extract a second cohesive block (mint + envelope build). Behavior must be identical.

- [ ] **Step 6: Verify clean + tests green**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
(cd plugins/credential-do && gofmt -w . && golangci-lint run ./...) && echo OK
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-do/... 2>&1 | tail -20
```
Expected: `0 issues.`; DO tests pass (including `resilience_test.go` and `concurrency_test.go`).

- [ ] **Step 7: Commit**

```bash
git add plugins/credential-do
git commit -m "refactor(do): named consts + extract loadRole/selectMinter to clear lint (reference)"
```

---

## Tasks 5–13: Remaining JIT plugins to zero

Each of these nine plugins follows the **exact Task 4 recipe** (consts.go via C4, HTTP codes via C1, TTL seconds via C2, other numerics via C3, `selectMinter`→struct via C5, `pathCredsRead` extraction via C6, plus the plugin's gocritic/godot items). Per plugin: run `golangci-lint run ./...` to get the live finding list, apply the conventions, verify `0 issues.` + that plugin's tests green, commit. The per-plugin specifics below list what differs from DO.

For every task in this group the steps are:
1. `(cd plugins/credential-<X> && golangci-lint run ./...)` — read the live findings.
2. Apply C1–C8 as the findings dictate (create `consts.go` with `cloudName = "<X>"` + the reported field-name consts; HTTP codes; TTL const block; `selectMinter`→`selectedMinter{... client *<X>Client}`; extract `loadRole` from `pathCredsRead`; fix listed gocritic).
3. `(cd plugins/credential-<X> && gofmt -w . && golangci-lint run ./...)` → `0 issues.`
4. `go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-<X>/...` → green.
5. `git add plugins/credential-<X> && git commit -m "refactor(<X>): named consts + extract helpers to clear lint"`

### Task 5: `credential-upcloud`
- Findings: mnd `200(×2), 900(×2), 10(×2), 30(×2), 5(×2), 21600, 24, 604800, 3600, 201, 204`; goconst `'upcloud'(×3), 'minter_set'(×3)` (+ `username`,`cloud`,`role`,`name` if they reach 3 — verify live); funlen `pathCredsRead` (84); function-result-limit `path_creds.go:184`; **gocritic `paramTypeCombine` at `upcloud_client.go:49`** (C7).
- Client type for C5: `*upcloudClient` (confirm the real type name via grep).

### Task 6: `credential-vultr`
- Findings: mnd `200(×2), 900(×2), 10(×2), 30(×2), 5(×2), 21600, 24, 8, 604800, 3600, 201, 204`; goconst `'vultr'(×3), 'minter_set'(×3)`; funlen `pathCredsRead` (92); function-result-limit `path_creds.go:193`; **gocritic `httpNoBody` at `vultr_client.go:88,105,130`** (C7).
- The extra `8` magic number: read `path_creds.go:72` (a length/comparison) and name it.

### Task 7: `credential-exoscale`
- Findings: mnd `200(×3), 30(×2), 900(×2), 10(×2), 5(×2), 21600, 24, 604800, 3600`; goconst `'exoscale'(×3), 'minter_set'(×3)`; funlen — none reported (verify); function-result-limit `path_creds.go:178`; **gocritic `paramTypeCombine` at `exoscale_client.go:51`** (C7).

### Task 8: `credential-azure`
- Findings: mnd `5(×3), 200(×3), 30(×2), 10(×2), 204, 900, 21600, 24, 604800, 3600, 86400`; goconst `'azure'(×3), 'minter_set'(×3)`; funlen `pathCredsRead` (94); function-result-limit `path_creds.go:201`. The extra `86400` = 1 day → `const oneDaySeconds = 86400 // 24h` (C2).

### Task 9: `credential-aws`
- Findings: mnd `900(×2), 5(×2), 21600, 24, 10, 64, 200, 403, 401, 429, 500, 604800, 30, 3600`; goconst `'aws'(×3), 'minter_set'(×3)` (+ `'us-east-1'(×2)` — only if it reaches 3); funlen `pathCredsRead` (110 — likely needs TWO extractions per C6); function-result-limit `path_creds.go:193`. HTTP codes `403/401/429/500` via C1. The `64` — read the site (likely a key/byte length) and name it.
- **Note:** AWS injects its client (per CLAUDE.md AWS/GCP/OCI skip the reload resilience category). The `selectMinter` struct refactor (C5) still applies.

### Task 10: `credential-gcp`
- Findings: mnd `5(×2), 3600(×2), 900, 21600, 24, 10, 200, 403, 401, 429, 500, 16, 604800, 30`; goconst `'gcp'(×3), 'minter_set'(×3)`; funlen `pathCredsRead` (81) AND **`getAccessToken` in `iam_client.go:61` (99)** — extract a cohesive block from `getAccessToken` too (e.g. request-build vs response-parse); function-result-limit `path_creds.go:153`; HTTP codes via C1; `16` — read site and name.

### Task 11: `credential-ovh`
- Findings: mnd `3600(×3), 5(×2), 900, 21600, 24, 10, 200, 401, 403, 429, 500, 16, 604800, 30`; goconst `'ovh'(×3), 'minter_set'(×3)`; funlen `pathCredsRead` (83); function-result-limit `path_creds.go:161`; **gocritic `unnamedResult` at `token_client.go:45,106`** (C7 — name the `(string, int, error)` results).

### Task 12: `credential-akamai`
- Findings: mnd `30(×2), 200(×2), 3(×2), 900(×2), 10(×2), 5(×2), 201, 204, 16, 21600, 24, 8, 604800, 3600`; goconst `'akamai'(×3), 'minter_set'(×3)`; funlen `pathCredsRead` (115 — likely TWO extractions); function-result-limit `path_creds.go:222`; **godot at `edgegrid.go:24`** (C8); **revive `unhandled-error` at `edgegrid.go:88`** (`io.Writer.Write` result dropped — wrap: `if _, err := w.Write(...); err != nil { return ... }`, or assign to `_` only if truly safe — read the context; this is a real dropped error in EdgeGrid signing, prefer handling it).

### Task 13: `credential-oci` (heaviest — phased-rotation plugin)

OCI is the only non-JIT plugin and has the largest complexity burden. **This task is bigger than the others — budget accordingly.**

**Files:**
- Create: `plugins/credential-oci/consts.go`
- Modify: `path_reconcile.go` (gocognit 46), `workers.go` (gocognit 24 + 44), `path_roles.go` (gocyclo 16, nestif ×2), plus mnd/goconst.

- [ ] **Step 1: Live findings** — `(cd plugins/credential-oci && golangci-lint run ./...)`.
- [ ] **Step 2: mnd + goconst** — mnd `5(×2), 401, 1000, 900, 21600, 3600, 24, 10, 604800, 30`; goconst `'oci'(×3), 'role'(×3), 'Name of the role'(×3), 'slot_index'(×3), 'minter_set'(×3)`. Create `consts.go` (`cloudName="oci"`, `fieldRole="role"`, `fieldSlotIndex="slot_index"`, `fieldMinterSet="minter_set"`, `descRoleName="Name of the role"`); apply C1/C2/C3.
- [ ] **Step 3: Refactor `pathReconcile` (gocognit 46, `path_reconcile.go:33`)** — read the function; extract the per-slot reconcile body and the orphan-detection loop into helpers (`func (b *backend) reconcileSlot(...)`, `func (b *backend) findOrphans(...)`). Note the spec/audit also flagged OCI's inline reconcile as diverging from `pkg/reconciler` (audit #5) — **do NOT do the #5 convergence here** (out of scope); only reduce cognitive complexity via behavior-preserving extraction. Remove any dead code encountered (e.g. `now := time.Now(); _ = now`) since `wastedassign`/`ineffassign` will flag it.
- [ ] **Step 4: Refactor `rotationWorker` (gocognit 24, `workers.go:86`) and `reconcileWorker` (gocognit 44, `workers.go:138`)** — extract cohesive inner blocks into named helpers. These are periodic-worker bodies; preserve exact behavior (the resilience tests exercise them).
- [ ] **Step 5: Refactor `pathRoleWrite` (gocyclo 16, `path_roles.go:85`) and the two `nestif` blocks (`path_roles.go:162,228`)** — flatten nesting via early-returns / guard clauses; extract validation. The `nestif` at `:162` (`if selErr == nil`) and `:228` (`if entry != nil`) — invert conditions to return early and de-indent.
- [ ] **Step 6: Verify** — `(cd plugins/credential-oci && gofmt -w . && golangci-lint run ./...)` → `0 issues.`; `go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-oci/...` → green (OCI has `resilience_test.go` covering rotation/reconcile — these MUST pass; they guard the refactor).
- [ ] **Step 7: Commit** — `git add plugins/credential-oci && git commit -m "refactor(oci): named consts + decompose reconcile/rotation/role workers to clear lint"`.

---

## Task 14: Full-workspace verification (Phase 5)

**Files:** none (verification only).

- [ ] **Step 1: Every module reports 0 issues**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
fail=0
for d in pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/worker pkg/plugintest \
         plugins/credential-akamai plugins/credential-aws plugins/credential-azure plugins/credential-do \
         plugins/credential-exoscale plugins/credential-gcp plugins/credential-oci plugins/credential-ovh \
         plugins/credential-upcloud plugins/credential-vultr; do
  out=$( (cd "$d" && golangci-lint run ./... 2>&1) )
  echo "$out" | grep -q '0 issues' || { echo "FAIL $d"; echo "$out" | tail -5; fail=1; }
done
[ $fail -eq 0 ] && echo "ALL MODULES CLEAN"
```
Expected: `ALL MODULES CLEAN`.

- [ ] **Step 2: `make lint` (the per-module CI loop) passes**

```bash
make lint
```
Expected: `0 issues.` for every module, exit 0.

- [ ] **Step 3: Build + race tests green**

```bash
go build github.com/nicois/openbao-cloud-creds/...
go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -30
```
Expected: build OK; every package `ok` (no FAIL).

- [ ] **Step 4: Confirm no stray `//nolint` introduced**

```bash
git diff main..HEAD | grep -nE '^\+.*nolint' || echo "no nolint added"
```
Expected: either `no nolint added`, or only the single justified `exhaustive`/`dupl-fakes` exclusion from Task 2/3 (flag it in the report for user review).

- [ ] **Step 5: Final commit if any verification-driven tidy was needed** (otherwise skip)

```bash
git add -A && git commit -m "chore(lint): final verification tidy" || echo "nothing to commit"
```

---

## Self-review notes (for the executor)

- **CI impact:** the repo's `.github/workflows/ci.yml` lint job runs the same per-module loop as `make lint`; once Task 14 is green locally, CI lint will be green. The new config does not change the `govulncheck` or smoke-test jobs.
- **Ordering dependency:** Task 3 (`pkg/credenvelope`) before the plugin tasks, because the fakes de-dup changes shared test scaffolding all plugins import — verify plugin tests after, not before. The `pkg/` tasks (2,3) before plugin tasks generally, since a shared const lifted to `pkg/` (rare) would need to exist first.
- **If a plugin defines no `selectMinter`/no `pathCredsRead` over 80 lines:** skip C5/C6 for it — only fix what the live linter reports. The per-plugin finding lists above are from the baseline run; always trust the live `golangci-lint run` output over the list.
