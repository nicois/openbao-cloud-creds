# Audit-2 Effort 4b: Minter Self-Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Operator-initiated rotation of long-lived minter credentials: a uniform `rotate` endpoint on all 10 plugins, real `RotateMinter` for the 6 feasible clouds (Azure ref, UpCloud, AWS, Akamai, GCP, Exoscale), clear "not supported" rejection for DO/OVH/Vultr/OCI, with grace-based retirement so a rotation never wedges cluster-wide issuance.

**Architecture:** Shared `cloudconfig` data-model + validation changes apply to all 10. Each feasible plugin's minter client gains a `RotateMinter` method (new per-cloud API call producing a mint-capable successor). A per-plugin `rotate` endpoint runs the shared orchestration: validate-would-still-validate → mint successor → health-check successor → swap (append successor active, mark old retired+RetiredAt) → persist+reload. `selectMinter` skips retired minters everywhere. A retired-sweep (reconcile cadence, feasible clouds) deletes the upstream old credential after `RetiredAt + grace`, keyed strictly off `RetiredAt` — separate from the conservative orphan reconciler.

**Tech Stack:** Go 1.26.1 workspace; OpenBao SDK v2.5.1; golangci-lint v2.12.2; cloud-fakes in `pkg/credenvelope/fakes/`.

**Spec:** `docs/superpowers/specs/2026-06-01-audit2-minter-rotation-design.md`

**CRITICAL EXECUTION CONSTRAINTS (these bit prior efforts):**
- Work ONLY in the effort's worktree. Prefix every bash call with `cd <worktree> && ...` and READ each file (absolute worktree path) immediately before editing it — bash cwd resets between calls; stray edits have landed in the main checkout before.
- ZERO new `//nolint`. **goconst trap (verified):** internal-package (`package credential<x>`) test literals count PACKAGE-WIDE and trip goconst on PRODUCTION files even though `_test.go` is in the golangci exclusions — hoist any repeated test literal (config path, field names, minter token key) to a package-scoped `const`, reusing whatever each plugin's existing internal tests already declare (e.g. `minterTokenKey`).
- Lint MUST use the v2 binary at `/home/claude-aiven-2/code/qualcheck/bin/golangci-lint` (PATH `golangci-lint` is v1, fails on v2 config). `<v2> cache clean` before linting.
- Full module path for go commands: `github.com/nicois/openbao-cloud-creds/...` (NOT `./...`).
- After each task, verify the main checkout is clean: `git -C /home/claude-aiven-2/code/openbao-cloud-creds status --short | grep -v '.claude'` returns nothing.
- NO new envelope `error_code`; the unsupported-cloud rejection is a plain `logical.ErrorResponse`.

---

## File Structure

**Shared (Task 1):**
- `pkg/cloudconfig/minter.go` — `Minter` gains `Retired bool`, `RetiredAt time.Time`, optional `RotationParams map[string]string`; `ValidateMinterSet` excludes retired minters; a new `ActiveMinters([]Minter) []Minter` helper.
- `pkg/cloudconfig/config.go` — `PluginConfig.MinterRetireGrace` + `DefaultConfig` default.

**Per-plugin selection skip (Task 2, all 10):**
- each plugin's `path_creds.go` (or `slots.go` for OCI) — `selectMinter`/`anyHealthyMinter*`/`selectMinterForSet` skip `Retired` minters.

**Azure reference (Task 3):**
- `plugins/credential-azure/azure_client.go` — `RotateMinter` method.
- `plugins/credential-azure/path_minter_sets.go` — `rotate` path + `pathMinterSetRotate` handler + the shared orchestration helper.
- `plugins/credential-azure/path_config.go` — `minter_retire_grace` config field.
- `plugins/credential-azure/workers.go` + a new `minter_retire.go` — the retired-sweep.
- `plugins/credential-azure/backend.go` — a `rotateSweepMu sync.Mutex` to serialize rotate vs. sweep.
- tests.

**5 real replicas (Tasks 4-8):** UpCloud, AWS, Akamai, GCP, Exoscale — same shape, per-cloud `RotateMinter` + wrinkles.

**4 stubs (Task 9):** DO, OVH, Vultr, OCI — `rotate` endpoint returns "not supported"; `minter_retire_grace` field + retired-skip still added (uniform).

**Verify + docs (Task 10).**

---

## Task 1: `pkg/cloudconfig` — data model + validation + grace

**Files:**
- Modify: `pkg/cloudconfig/minter.go`
- Modify: `pkg/cloudconfig/config.go`
- Test: `pkg/cloudconfig/minter_test.go` (append), `pkg/cloudconfig/config_test.go` (append)

- [ ] **Step 1: Write failing tests** — append to `pkg/cloudconfig/minter_test.go`:

```go
func TestValidateMinterSet_ExcludesRetired(t *testing.T) {
	// A set valid ONLY because of a retired never_expires minter must FAIL:
	// validation considers active minters only.
	minters := []Minter{
		{ID: "old", NeverExpires: true, Retired: true, RetiredAt: time.Now()},
		{ID: "new", ExpiresAt: time.Now().Add(48 * time.Hour)},
	}
	// active = just "new" (one expiring minter) -> invalid (needs >=2 or a never_expires)
	if err := ValidateMinterSet(minters); err == nil {
		t.Fatal("expected validation to fail when only active minter is a single expiring one")
	}
}

func TestValidateMinterSet_ActiveNeverExpiresPasses(t *testing.T) {
	minters := []Minter{
		{ID: "old", NeverExpires: true, Retired: true, RetiredAt: time.Now()},
		{ID: "new", NeverExpires: true},
	}
	if err := ValidateMinterSet(minters); err != nil {
		t.Fatalf("active never_expires minter should satisfy the rule: %v", err)
	}
}

func TestActiveMinters_FiltersRetired(t *testing.T) {
	minters := []Minter{
		{ID: "a"},
		{ID: "b", Retired: true},
	}
	active := ActiveMinters(minters)
	if len(active) != 1 || active[0].ID != "a" {
		t.Fatalf("ActiveMinters = %v, want [a]", active)
	}
}
```
Append to `pkg/cloudconfig/config_test.go`:
```go
func TestDefaultConfig_MinterRetireGraceDefaultsToMinMinterGap(t *testing.T) {
	if got := DefaultConfig("do").MinterRetireGrace; got != MinMinterGap {
		t.Fatalf("MinterRetireGrace = %v, want MinMinterGap", got)
	}
}
```
(Check the existing config_test.go package clause — it's `package cloudconfig_test`, so reference `cloudconfig.DefaultConfig`/`cloudconfig.MinMinterGap`. The minter_test.go may be internal `package cloudconfig` — match whatever is there; if internal, drop the package qualifier.)

- [ ] **Step 2: Run to verify failure**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/pkg/cloudconfig/ 2>&1 | tail`
Expected: FAIL — `Retired`/`RetiredAt`/`ActiveMinters`/`MinterRetireGrace` undefined.

- [ ] **Step 3a: Implement the Minter fields + helper** in `pkg/cloudconfig/minter.go`

Add to the `Minter` struct (after `CreatedAt`):
```go
	Retired        bool              `json:"retired,omitempty"`
	RetiredAt      time.Time         `json:"retired_at,omitempty"`
	RotationParams map[string]string `json:"rotation_params,omitempty"`
```
Add the helper (before `ValidateMinterSet`):
```go
// ActiveMinters returns the non-retired minters. Retirement is a soft state set
// by rotation; retired minters stay in the set (and upstream-alive) during the
// grace window but are excluded from validation and new-issuance selection.
func ActiveMinters(minters []Minter) []Minter {
	active := make([]Minter, 0, len(minters))
	for _, m := range minters {
		if !m.Retired {
			active = append(active, m)
		}
	}
	return active
}
```
Change `ValidateMinterSet` to validate active minters only. At the top of the function body, replace the loop's input: keep the signature `func ValidateMinterSet(minters []Minter) error`, but operate on `active := ActiveMinters(minters)`. Specifically change the first lines:
```go
func ValidateMinterSet(minters []Minter) error {
	active := ActiveMinters(minters)
	if len(active) == 0 {
		return fmt.Errorf("minter set must not be empty")
	}

	hasNeverExpires := false
	var expiring []Minter

	for _, m := range active {
		// ... unchanged body, iterating `active` ...
```
(Replace the two `minters` references inside — the `len(minters)==0` guard and the `range minters` — with `active`. Leave the rest identical.)

- [ ] **Step 3b: Implement the config field** in `pkg/cloudconfig/config.go`

Add to `PluginConfig` (after `MinterExpiryWarn`):
```go
	MinterRetireGrace time.Duration `json:"minter_retire_grace"`
```
And in `DefaultConfig` (after `MinterExpiryWarn: MinMinterGap,`):
```go
		MinterRetireGrace: MinMinterGap,
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/pkg/cloudconfig/ 2>&1 | tail`
Expected: PASS — all new + pre-existing (the existing `ValidateMinterSet` tests have no retired minters, so `ActiveMinters` is a no-op for them; they stay green).

- [ ] **Step 5: Lint + commit**

```bash
cd <worktree>
/home/claude-aiven-2/code/qualcheck/bin/golangci-lint cache clean
(cd pkg/cloudconfig && gofmt -w . && /home/claude-aiven-2/code/qualcheck/bin/golangci-lint run ./... 2>&1 | tail -4); echo "exit ${PIPESTATUS[0]}"
git add pkg/cloudconfig/
git commit -m "$(printf 'feat(cloudconfig): Minter retired state + RotationParams + MinterRetireGrace; validation excludes retired (audit2 #9)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```
Expected: 0 issues.

---

## Task 2: `selectMinter` skips retired minters (all 10 plugins)

**Files (Modify, ×10):** each plugin's selection sites — `path_creds.go` (`selectMinter`, `anyHealthyMinter`, `anyHealthyMinterInSet`, `getMinter`) for the 9 JIT plugins; `slots.go` (`selectMinterForSet`, `anyHealthyMinter`) for OCI.

The selection guard today is `if ms.sm.Selectable(now) {`. Add a retired check: `if !ms.minter.Retired && ms.sm.Selectable(now) {`. A retired minter must never be chosen for NEW issuance (it stays upstream-alive only so other nodes don't wedge during the grace).

- [ ] **Step 1: Write a failing test (DO representative)** — `plugins/credential-do/retired_skip_test.go` (internal `package credentialdo`):

```go
package credentialdo

import (
	"context"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestSelectMinter_SkipsRetired(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	bk := b.(*backend)
	storage := config.StorageView

	if resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{"do_api_url": srv.URL},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config: %v %v", err, resp)
	}
	// two never_expires minters, then mark minter-1 retired in-memory
	if resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-1", minterTokenKey: "dop_v1_a", "never_expires": true},
			map[string]interface{}{"id": "minter-2", minterTokenKey: "dop_v1_b", "never_expires": true},
		}},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set: %v %v", err, resp)
	}

	bk.mu.Lock()
	bk.minterSets["default"]["minter-1"].minter.Retired = true
	bk.mu.Unlock()

	for i := 0; i < 10; i++ {
		sel, err := bk.selectMinter("default", time.Now())
		if err != nil {
			t.Fatalf("selectMinter: %v", err)
		}
		if sel.minterID == "minter-1" {
			t.Fatal("retired minter-1 must never be selected")
		}
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (retired minter-1 sometimes selected, since selection is map-order random).

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/plugins/credential-do/ -run TestSelectMinter_SkipsRetired -count=5 2>&1 | tail`
Expected: FAIL (minter-1 selected on some iteration).

- [ ] **Step 3: Implement across all 10.** For each plugin, READ the file then change every selection guard from `if ms.sm.Selectable(now) {` to `if !ms.minter.Retired && ms.sm.Selectable(now) {`. Sites per plugin:
  - 9 JIT plugins `path_creds.go`: `selectMinter`, `anyHealthyMinter`, `anyHealthyMinterInSet` (azure/do/etc. have all three; some have `getMinter` which is a direct lookup — leave `getMinter` AS-IS since revoke must still reach a retired minter's client if needed).
  - OCI `slots.go`: `selectMinterForSet`, `anyHealthyMinter`.
  - Confirm via grep: `grep -rn 'Selectable(now)' plugins/*/*.go | grep -v _test` — every SELECTION site (not the `getMinter` direct lookup) gets the `!ms.minter.Retired &&` prefix.

- [ ] **Step 4: Run the DO test — expect PASS**, then full plugin build.

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/plugins/credential-do/ -run TestSelectMinter_SkipsRetired -count=5 2>&1 | tail && go build github.com/nicois/openbao-cloud-creds/...`
Expected: PASS; build OK.

- [ ] **Step 5: Lint all 10 + commit**

```bash
cd <worktree>
GL=/home/claude-aiven-2/code/qualcheck/bin/golangci-lint; "$GL" cache clean
for p in do aws gcp azure ovh upcloud exoscale vultr akamai oci; do (cd plugins/credential-$p && gofmt -w . && "$GL" run ./... >/dev/null 2>&1) && echo "0: $p" || echo "ISSUES: $p"; done
git add plugins/credential-*/ && git commit -m "$(printf 'feat: selectMinter skips retired minters for new issuance, all 10 plugins (audit2 #9)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```
Expected: 0 issues all 10.

---

## Task 3: Azure reference — RotateMinter + rotate endpoint + retired-sweep

This is the REFERENCE for the 5 real replicas. Get it clean.

**Files:**
- Modify: `plugins/credential-azure/azure_client.go` (add `RotateMinter`)
- Modify: `plugins/credential-azure/backend.go` (add `rotateSweepMu sync.Mutex`)
- Modify: `plugins/credential-azure/path_minter_sets.go` (add `rotate` path + handler + orchestration)
- Modify: `plugins/credential-azure/path_config.go` (add `minter_retire_grace` field — mirror 4a's `minter_expiry_warn`)
- Create: `plugins/credential-azure/minter_retire.go` (the retired-sweep worker)
- Modify: `plugins/credential-azure/workers.go` (register the sweep, or fold into reconcileWorker)
- Test: `plugins/credential-azure/minter_rotation_test.go`

**Azure minter encoding (verified):** the minter `Token` is `clientID:clientSecret` (`newClientForMinter` splits on `:`). `addPassword` needs the **app object ID** — carry it in the minter's `RotationParams["app_object_id"]` (set when the minter-set is written; the rotate handler reads it). The successor token is `clientID:<new secretText>`.

- [ ] **Step 1: Write the failing test** — `plugins/credential-azure/minter_rotation_test.go` (internal `package credentialazure`).

The test must cover: (a) rotate happy-path — successor minted via fake `addPassword`, validated, swapped in, old marked retired, set still valid, `selectMinter` returns a non-retired minter; (b) rotate rejected when retiring breaks validation; (c) rotate rejected when the successor health-check fails; (d) config round-trip of `minter_retire_grace`; (e) retired-sweep deletes the upstream old secret + drops it from the set after `RetiredAt + grace` (injected clock), and does NOT before grace.

READ `plugins/credential-azure/cooldown_internal_test.go` and `minter_observability_test.go` first for the exact Factory + fake-server + HandleRequest pattern, the fake server name (`fakes.NewAzureServer()`), the config fields (`tenant_id`/`graph_endpoint`/`login_endpoint`), and the minter token format. Build the test on those. Use a fake clock by calling the sweep helper with an explicit `now time.Time` parameter (the sweep function MUST take `now` for testability — see Step 4).

Write concrete assertions (full code, no placeholders) mirroring the spec's success criteria. Hoist repeated literals to consts to avoid goconst.

- [ ] **Step 2: Run — expect FAIL** (`RotateMinter`/rotate path/`minter_retire_grace`/sweep undefined).

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/plugins/credential-azure/ -run 'TestMinterRotation|TestRetireSweep|TestRotateConfig' 2>&1 | tail`

- [ ] **Step 3: Implement `RotateMinter`** in `azure_client.go`:

```go
// RotateMinter mints a successor SP secret on the same app registration (the
// successor authenticates as the same service principal, inheriting addPassword
// rights). appObjectID comes from old.RotationParams["app_object_id"].
func (c *azureClient) RotateMinter(ctx context.Context, old cloudconfig.Minter) (cloudconfig.Minter, error) {
	appObjectID := old.RotationParams["app_object_id"]
	if appObjectID == "" {
		return cloudconfig.Minter{}, fmt.Errorf("minter %s missing rotation_params.app_object_id", old.ID)
	}
	displayName := "cloud-creds-minter-" + old.ID
	// Successor secret valid 2y by default; mirror the existing issuance endDate logic.
	endDate := time.Now().Add(2 * 365 * 24 * time.Hour)
	pw, status, err := c.AddPassword(ctx, appObjectID, displayName, endDate)
	if err != nil {
		return cloudconfig.Minter{}, fmt.Errorf("addPassword failed (status %d): %w", status, err)
	}
	clientID := strings.SplitN(old.Token, ":", 2)[0]
	return cloudconfig.Minter{
		ID:             old.ID + "-rot-" + rotationSuffix(),
		Token:          clientID + ":" + pw.SecretText,
		CreatedAt:      time.Now(),
		NeverExpires:   old.NeverExpires,
		ExpiresAt:      endDate, // or keep old's expiry policy; pick per the minter's kind
		RotationParams: old.RotationParams, // successor keeps the same app_object_id + keyId for retire
	}, nil
}
```
Add a `rotationSuffix()` helper (package-level, used by all feasible plugins' equivalents — but per per-plugin-module isolation, define it per plugin): `func rotationSuffix() string { return strconv.FormatInt(time.Now().UnixNano(), 36) }`. The successor must also record the new secret's `keyId` (from `pw.KeyId`) in `RotationParams["key_id"]` so the retire-sweep can `removePassword` the OLD one — wait: it's the OLD minter that must be removed, so the OLD minter needs ITS keyId. Ensure minters created via the normal minter-set write also get `key_id` in RotationParams if known, OR the sweep uses the app to remove by the old secret. **Implementer note:** Azure `removePassword` needs the OLD secret's keyId; if the original operator-provided minter has no recorded keyId, the sweep cannot removePassword it precisely. Handle by: when rotating, record the successor's keyId; for the retire-sweep of a minter that HAS a keyId in RotationParams, removePassword by that keyId; if it has none (operator-provided original with unknown keyId), the sweep logs a warning and leaves the upstream secret for manual cleanup (still drops it from the set after grace so issuance isn't affected). Document this clearly.

- [ ] **Step 4: Implement the rotate endpoint + orchestration + sweep.** (Full code per the spec's Manual-endpoint section.) Key requirements:
  - Add `rotate` path: `Pattern: "minter-sets/" + framework.GenericNameRegex("name") + "/rotate"`, field `minter_id` (TypeString, required), UpdateOperation → `b.pathMinterSetRotate`.
  - Orchestration steps 1-6 from the spec, under `b.rotateSweepMu.Lock()`. Validate-would-still-validate via `cloudconfig.ValidateMinterSet` on the prospective set. Health-check the successor via a client built from its token. Persist set + `loadMinterSet` + emit a `minter_rotated` metric.
  - The retired-sweep `func (b *backend) sweepRetiredMinters(ctx, storage, now time.Time) error` in `minter_retire.go`: for each set, for each minter with `Retired && now.After(RetiredAt.Add(grace))`, removePassword the upstream secret (best-effort per the keyId note), drop it from the set, persist+reload. Take `now` as a param for testability. Register it in the reconcile worker (call `b.sweepRetiredMinters(ctx, storage, time.Now())` at the end of `reconcileWorker`).
  - `minter_retire_grace` config field in `path_config.go` (mirror 4a `minter_expiry_warn`: const `defaultMinterRetireGraceSeconds = 604800`, field, parse, render).
  - `rotateSweepMu sync.Mutex` in `backend.go` struct + init.

- [ ] **Step 5: Run tests — expect PASS**, then lint.

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/plugins/credential-azure/ 2>&1 | tail` then lint azure with the v2 binary (cache clean). Expected: PASS, 0 issues, no nolint.

- [ ] **Step 6: Commit** `plugins/credential-azure/` with message `feat(azure): minter self-rotation (RotateMinter + rotate endpoint + retired-sweep) (audit2 #9)` + the Co-Authored-By trailer.

---

## Tasks 4-8: real replicas — UpCloud, AWS, Akamai, GCP, Exoscale

Each replicates Task 3's structure (rotate endpoint + orchestration + `minter_retire_grace` field + retired-sweep + `rotateSweepMu`), with a per-cloud `RotateMinter` + the spec's per-cloud wrinkle. One task (one commit) per plugin. READ the plugin's existing client + minter encoding + fake server first.

### Task 4: UpCloud
- `RotateMinter`: `POST /1.3/account/tokens` with `can_create_tokens: true` (the client's `createTokenRequest` already has the field — `upcloud_client.go`). Successor token = the returned token value. Old retired → sweep deletes via `DELETE /1.3/account/tokens/{id}` (the old token's upstream ID; record it in RotationParams["token_id"] at rotation, and from the minter-set write where known).
- Fake: `fakes.NewUpCloudServer()`.

### Task 5: AWS
- `RotateMinter`: `iam:CreateAccessKey` for the same user. **Guard:** first list the user's keys; if 2 exist, return an error that the orchestration surfaces as "minter user already has 2 access keys; free a slot or wait for the retirement sweep" (reject, no state change). Successor token = `accessKeyId:secretAccessKey`. Sweep deletes the OLD key via `DeleteAccessKey` (old's accessKeyId, in RotationParams).
- AWS is an INJECTED-client plugin. **Verified:** its existing injected client is `stsClientFn STSClientFactory` — that's the *issuance* (AssumeRole) client, NOT a key-management client. Minter rotation needs a SEPARATE injected IAM client for `CreateAccessKey`/`DeleteAccessKey`/`ListAccessKeys`, built from the minter access key. Add a new `iamMinterClientFn` factory + interface (mirror the `stsClientFn` pattern in `backend.go:34` + `testing.go:16`) + a fake impl in the test. The minter token is `accessKeyId:secretAccessKey`; the IAM client authenticates with those.

### Task 6: Akamai
- `RotateMinter`: resolve the Identity-Management `apiId` via `GET /identity-management/v3/users/{username}/allowed-apis` (username from RotationParams["username"]), then `POST /identity-management/v3/api-clients` with `clientType:"CLIENT"` + that apiId at `READ-WRITE` + `createCredential=true`. Successor token = the returned credentials. Sweep deletes the OLD client via `DELETE .../api-clients/{clientId}`.
- Fake: `fakes.NewAkamaiServer()` — extend it to handle the allowed-apis + create-client + delete-client endpoints if not present (READ the fake first).

### Task 7: GCP
- `RotateMinter`: `projects.serviceAccounts.keys.create` for the same SA. **Org-policy handling:** if the create fails with a `iam.disableServiceAccountKeyCreation`-style policy error, return an error the orchestration surfaces as "minter rotation disabled by GCP org policy iam.disableServiceAccountKeyCreation; rotate out-of-band or request a policy exemption". Successor token = the new key JSON. Sweep deletes the OLD key via `keys.delete`.
- GCP is INJECTED-client. **Verified:** its existing `iamClientFn`/`IAMCredentialsClient` (`backend.go:38,48`) is the *impersonation* (`generateAccessToken`) client, NOT a key-management client. Minter rotation needs a SEPARATE injected client for `serviceAccounts.keys.create`/`.delete`, built from the minter SA JSON. Add a new factory + interface (mirror `iamClientFn`) + fake impl. Successor token = the new key JSON.

### Task 8: Exoscale
- `RotateMinter`: `POST /v2/api-key` with `role-id` = the minter's key-management role (from RotationParams["role_id"]). Successor token = returned `key:secret`. Sweep deletes the OLD key via `DELETE /api-key/{id}`.
- Fake: `fakes.NewExoscaleServer()`.

**Each Task 4-8:** mirror Task 3's test coverage (happy-path, reject-breaks-validation, successor-health-check-fail, config round-trip, sweep-after-grace). Build + race + lint clean, no nolint, main clean, one commit per plugin.

---

## Task 9: stubs — DO, OVH, Vultr, OCI

These get the UNIFORM API (rotate endpoint + `minter_retire_grace` field; the retired-skip from Task 2 already applies) but `RotateMinter` is NOT implemented — the rotate endpoint returns a clear rejection without state change.

**Files (×4):** `path_minter_sets.go` (rotate path + handler that rejects), `path_config.go` (`minter_retire_grace` field for uniformity).

- [ ] For each of do/ovh/vultr/oci: add the `rotate` path (same pattern as Task 3) whose handler immediately returns:
```go
return logical.ErrorResponse("minter rotation is not supported for %s; rotate this minter out-of-band", cloudName), nil
```
(no envelope error_code; before any state change). Add the `minter_retire_grace` config field for a uniform config surface (it's harmless — the sweep never runs on these clouds since nothing is ever marked retired). Add a test asserting the rotate endpoint returns the "not supported" error and does NOT mutate the set.

- [ ] Build + lint + commit (one commit covering the 4 stubs, or one each — implementer's choice; main clean).

---

## Task 10: Full-workspace verification + mark #9 resolved

- [ ] **Step 1: full gate** (build / `go test -race` / lint all 21 dirs with v2 binary cache-cleaned / nolint count / `make smoke-test`). If anything fails, STOP and report BLOCKED.

```bash
cd <worktree>
go build github.com/nicois/openbao-cloud-creds/... && echo "build OK"
go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | grep -E 'FAIL|^ok |panic' | tail -25
GL=/home/claude-aiven-2/code/qualcheck/bin/golangci-lint; "$GL" cache clean
fail=0; for d in pkg/cloudconfig pkg/credenvelope pkg/credenvelope/fakes pkg/localexpiry pkg/metrics pkg/metricspath pkg/plugintest pkg/reconciler pkg/recovery pkg/telemetry pkg/worker plugins/credential-akamai plugins/credential-aws plugins/credential-azure plugins/credential-do plugins/credential-exoscale plugins/credential-gcp plugins/credential-oci plugins/credential-ovh plugins/credential-upcloud plugins/credential-vultr; do (cd "$d" && "$GL" run ./... >/dev/null 2>&1) && echo "0: $d" || { echo "ISSUES: $d"; fail=1; }; done
echo "lint: $([ $fail -eq 0 ] && echo CLEAN || echo ISSUES)"
git diff main..HEAD | grep -cE '^\+.*nolint'
make smoke-test 2>&1 | tail -4
```

- [ ] **Step 2: mark #9 RESOLVED** in `docs/audit-2026-06-01.md` — change the `## 9.` heading from `[PARTIALLY RESOLVED ...]` to `[RESOLVED 2026-06-01]` and add an Effort-4b note:
> **Resolved (Effort 4b — self-rotation):** Uniform `POST cloud-creds/<cloud>/minter-sets/<set>/rotate` endpoint on all 10 plugins. Real `RotateMinter` (mint successor → health-check → swap → mark retired with `RetiredAt`; upstream old credential deleted by a retired-sweep after `minter_retire_grace`, default 7d — grace-separated so a rotation never wedges other raft nodes' in-memory minter snapshots) for Azure, UpCloud, AWS (make-before-break at the 2-key limit), Akamai (per-account apiId), GCP (org-policy-aware error), Exoscale (minter role-id). DO/OVH/Vultr/OCI reject with a clear "rotation not supported, rotate out-of-band" message (verified infeasible: DO has no token-creation scope; OVH OAuth2 grant; Vultr single key; OCI phased + quota). `selectMinter` skips retired minters on all 10; the retired-sweep is keyed off `RetiredAt`, separate from the conservative orphan reconciler. Real-cloud validation (disposable accounts + record/replay) is the deferred #7 follow-up.

- [ ] **Step 3: update `docs/decisions.md`** with a short note on the grace-based cross-node-safe retirement rationale (no cross-node reload signal → grace must exceed worst-case node-reload interval; default 7d). Verify main clean, commit.

---

## Self-review notes (for the executor)

- **Spec coverage:** Task 1 (data model + validation + grace), Task 2 (retired-skip ×10), Task 3 (Azure ref: RotateMinter + endpoint + sweep), Tasks 4-8 (5 real replicas), Task 9 (4 stubs), Task 10 (gate + docs). All spec success criteria covered.
- **Type consistency:** `Minter.Retired`/`RetiredAt`/`RotationParams`; `ActiveMinters([]Minter) []Minter`; `PluginConfig.MinterRetireGrace`; `minter_retire_grace` (field, seconds); `defaultMinterRetireGraceSeconds = 604800`; `RotateMinter(ctx, cloudconfig.Minter) (cloudconfig.Minter, error)`; `sweepRetiredMinters(ctx, storage, now)`; `rotateSweepMu`; `minter_rotated` (metric). Used identically across tasks.
- **Known hazards:**
  - goconst on internal-test literals (hoist to consts; reuse existing per-plugin consts).
  - The Azure `removePassword`-needs-old-keyId subtlety (Task 3 Step 3) — the implementer must handle minters whose keyId is unknown (operator-provided originals) by dropping from the set after grace + warn-logging rather than failing the sweep. The SAME class of issue applies per-cloud (the sweep needs the OLD credential's upstream ID): RotationParams must carry the deletable ID; for operator-provided originals without it, drop-from-set-after-grace + warn.
  - INJECTED-client plugins (AWS, GCP) need new methods on their injected client interface + fake impls — more work than the HTTP-fake clouds; READ how each injects its client in existing tests.
  - The sweep mutates the set under `rotateSweepMu` AND the reconcile worker runs it — ensure no deadlock with `b.mu` (take `b.mu` only inside helper calls, never across the sweep body holding `rotateSweepMu`, mirroring OCI's `rotateReconcileMu` discipline in `slots.go:163`).
- **DRY/YAGNI:** the orchestration helper is structurally identical across the 6 feasible plugins but lives per-plugin (per the per-plugin-module isolation convention — do NOT extract into a shared pkg that would couple the plugin modules). The `rotationSuffix()` helper is duplicated per plugin (trivial).
