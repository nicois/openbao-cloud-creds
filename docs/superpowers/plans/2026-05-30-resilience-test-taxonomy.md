# Resilience Test Taxonomy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a shared resilience test harness and three test categories (reload, mid-lease perturbation, revoke-resilience) to all 10 plugins, using them to expose KI-001/KI-002 as failing tests and then fixing both.

**Architecture:** A new `pkg/plugintest` module provides generic, `Harness`-parameterized category runners that re-instantiate a backend from persisted storage and perturb state mid-lease. Each plugin gets a `resilience_test.go` wiring its Factory/fake. Tests land first (red, proving the bugs), then KI-001 (config not reloaded on init) and KI-002 (revoke errors when minter gone) are fixed (green).

**Tech Stack:** Go 1.26.1, OpenBao SDK v2.5.1 (`logical.Factory`, `logical.TestBackendConfig`, `logical.InmemStorage`), golangci-lint v2.

**Reference spec:** `docs/superpowers/specs/2026-05-30-resilience-test-taxonomy-design.md`. Bugs: `docs/known-issues.md`.

---

## Task 1: pkg/plugintest — shared resilience harness

**Files:**
- Create: `pkg/plugintest/go.mod`
- Create: `pkg/plugintest/harness.go`
- Create: `pkg/plugintest/reload.go`
- Create: `pkg/plugintest/perturbation.go`
- Create: `pkg/plugintest/revoke.go`
- Modify: `go.work`

- [ ] **Step 1: Initialize the module**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds
mkdir -p pkg/plugintest
cd pkg/plugintest && go mod init github.com/nicois/openbao-cloud-creds/pkg/plugintest
```
Add `./pkg/plugintest` to the `use (` block in `go.work`. Then add the SDK requirement:
```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/pkg/plugintest
go get github.com/openbao/openbao/sdk/v2@v2.5.1
```

- [ ] **Step 2: Write `harness.go`**

```go
// Package plugintest provides shared resilience-test scaffolding for the
// cloud credential plugins. It is parameterized by a Harness so it never
// imports a specific plugin (which would create an import cycle).
package plugintest

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Harness is supplied by each plugin's resilience_test.go.
type Harness struct {
	// Factory is the plugin's logical.Factory.
	Factory logical.Factory
	// Configure writes config + a minter set named "default" + a role bound to
	// it, pointed at the plugin's fake. After it returns, IssuePath must issue.
	Configure func(t *testing.T, b logical.Backend, storage logical.Storage)
	// IssuePath is the read path that issues a credential, e.g. "creds/test-role".
	IssuePath string
	// RewriteDefaultSetWithout rewrites minter-sets/default with a single minter
	// whose id differs from the originally-issuing minter (so the issuing minter
	// id becomes absent), simulating a re-seed. Same fake.
	RewriteDefaultSetWithout func(t *testing.T, b logical.Backend, storage logical.Storage)
	// ProvisionedCount reports how many upstream credentials currently exist in
	// the plugin's fake.
	ProvisionedCount func() int
	// ExpectsHardRevoke is true for plugins that delete the upstream credential
	// on revoke (DO, UpCloud, Exoscale, Azure, Vultr, Akamai); false for
	// no-revoke plugins (AWS, GCP, OVH).
	ExpectsHardRevoke bool
}

// newConfiguredBackend builds a fresh backend against fresh storage and runs
// the harness Configure. Returns the backend and its storage.
func newConfiguredBackend(t *testing.T, h Harness) (logical.Backend, logical.Storage) {
	t.Helper()
	cfg := logical.TestBackendConfig()
	cfg.StorageView = &logical.InmemStorage{}
	b, err := h.Factory(context.Background(), cfg)
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	h.Configure(t, b, cfg.StorageView)
	return b, cfg.StorageView
}

// ReloadBackend calls the factory again against the same storage, with no
// intervening config write — simulating a raft failover / plugin reload /
// process restart where only persisted state is available.
func ReloadBackend(t *testing.T, factory logical.Factory, storage logical.Storage) logical.Backend {
	t.Helper()
	cfg := logical.TestBackendConfig()
	cfg.StorageView = storage
	b, err := factory(context.Background(), cfg)
	if err != nil {
		t.Fatalf("reload factory failed: %v", err)
	}
	return b
}

// issue performs a credential read at h.IssuePath and returns the response.
func issue(t *testing.T, b logical.Backend, storage logical.Storage, path string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   storage,
	})
}
```

- [ ] **Step 3: Write `reload.go` (Category R)**

```go
package plugintest

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// RunReloadSuite verifies a backend rehydrated from persisted storage (no
// config write) can still issue credentials. Catches KI-001.
func RunReloadSuite(t *testing.T, h Harness) {
	t.Run("ReloadFromStorageThenIssue", func(t *testing.T) {
		_, storage := newConfiguredBackend(t, h)

		// Simulate failover/restart: brand-new backend, same storage, no config write.
		b2 := ReloadBackend(t, h.Factory, storage)

		resp, err := issue(t, b2, storage, h.IssuePath)
		if err != nil {
			t.Fatalf("issue after reload errored: %v", err)
		}
		if resp == nil || resp.IsError() {
			t.Fatalf("issue after reload failed (KI-001): %v", resp)
		}
		if resp.Data["credential"] == nil {
			t.Fatalf("issue after reload returned no credential: %v", resp.Data)
		}
	})

	t.Run("ReloadPreservesRoleAndSet", func(t *testing.T) {
		_, storage := newConfiguredBackend(t, h)
		b2 := ReloadBackend(t, h.Factory, storage)

		// The role read must still resolve on the reloaded backend.
		resp, err := b2.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation, Path: "roles/test-role", Storage: storage,
		})
		if err != nil || resp == nil || resp.IsError() {
			t.Fatalf("role read after reload failed: err=%v resp=%v", err, resp)
		}
		if resp.Data["minter_set"] != "default" {
			t.Fatalf("reloaded role lost minter_set binding: %v", resp.Data["minter_set"])
		}
	})
}
```

- [ ] **Step 4: Write `perturbation.go` (Category P)**

```go
package plugintest

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// RunPerturbationSuite verifies that mutating the minter set after a lease is
// issued does not wedge revocation. Catches KI-002.
func RunPerturbationSuite(t *testing.T, h Harness) {
	t.Run("RevokeAfterIssuingMinterRemoved", func(t *testing.T) {
		b, storage := newConfiguredBackend(t, h)

		resp, err := issue(t, b, storage, h.IssuePath)
		if err != nil || resp == nil || resp.IsError() {
			t.Fatalf("initial issue failed: err=%v resp=%v", err, resp)
		}
		secret := resp.Secret
		if secret == nil {
			t.Fatal("issue returned no secret/lease")
		}

		// Re-seed the set so the issuing minter id is gone.
		h.RewriteDefaultSetWithout(t, b, storage)

		// Revoke the in-flight lease. Must not return an error (which OpenBao
		// would retry forever) — the credential expires via TTL regardless.
		revResp, revErr := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.RevokeOperation,
			Path:      h.IssuePath,
			Storage:   storage,
			Secret:    secret,
		})
		if revErr != nil {
			t.Fatalf("revoke after minter removal errored (KI-002): %v", revErr)
		}
		if revResp != nil && revResp.IsError() {
			t.Fatalf("revoke after minter removal returned error response (KI-002): %v", revResp)
		}
	})
}
```

- [ ] **Step 5: Write `revoke.go` (Category X)**

```go
package plugintest

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// RunRevokeResilienceSuite verifies revoke is well-behaved under adverse
// conditions: a double revoke must be a clean no-op.
func RunRevokeResilienceSuite(t *testing.T, h Harness) {
	t.Run("DoubleRevokeIsNoOp", func(t *testing.T) {
		b, storage := newConfiguredBackend(t, h)

		resp, err := issue(t, b, storage, h.IssuePath)
		if err != nil || resp == nil || resp.IsError() {
			t.Fatalf("issue failed: err=%v resp=%v", err, resp)
		}
		secret := resp.Secret
		if secret == nil {
			t.Fatal("issue returned no secret/lease")
		}

		revoke := func() (*logical.Response, error) {
			return b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.RevokeOperation,
				Path:      h.IssuePath,
				Storage:   storage,
				Secret:    secret,
			})
		}

		if r, e := revoke(); e != nil || (r != nil && r.IsError()) {
			t.Fatalf("first revoke failed: err=%v resp=%v", e, r)
		}
		// Second revoke of the same lease must not error.
		if r, e := revoke(); e != nil || (r != nil && r.IsError()) {
			t.Fatalf("second revoke (no-op) failed: err=%v resp=%v", e, r)
		}
	})
}
```

- [ ] **Step 6: Verify the package compiles**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds
go build github.com/nicois/openbao-cloud-creds/pkg/plugintest/...
```
Expected: success (no consumers yet, but it must compile).

- [ ] **Step 7: Commit**

```bash
git add pkg/plugintest/ go.work go.work.sum
git commit -m "feat(plugintest): add shared resilience test harness (reload/perturbation/revoke)"
```

---

## Task 2: DO — fake accessor + resilience_test (REFERENCE; red for R/P)

This task is the template for the other 9 plugins. It adds the uniform fake accessor and wires DO into the harness. Categories R and P are EXPECTED TO FAIL here (DO's reload is actually fine since its minter token is self-contained, so R passes for DO — but P fails because of KI-002). Confirm the exact red/green per the steps.

**Files:**
- Modify: `pkg/credenvelope/fakes/do.go`
- Create: `plugins/credential-do/resilience_test.go`

- [ ] **Step 1: Add `ProvisionedCount` to the DO fake**

In `pkg/credenvelope/fakes/do.go`, add a method (the fake stores tokens in `s.tokens`):
```go
// ProvisionedCount returns the number of tokens currently held by the fake.
func (s *DOServer) ProvisionedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}
```
Check the mutex field name in `do.go` (it is `s.mu`). If the tokens map field is named differently, use the actual name.

- [ ] **Step 2: Write `resilience_test.go` wiring the harness**

`plugins/credential-do/resilience_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func newResilienceHarness(t *testing.T) (plugintest.Harness, *fakes.DOServer) {
	srv := fakes.NewDOServer()
	t.Cleanup(srv.Close)

	configure := func(t *testing.T, b logical.Backend, storage logical.Storage) {
		write := func(path string, data map[string]interface{}) {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
			})
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("%s write failed: err=%v resp=%v", path, err, resp)
			}
		}
		write("config", map[string]interface{}{"do_api_url": srv.URL})
		write("minter-sets/default", map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "minter-1", "token": "dop_v1_test", "never_expires": true},
			},
		})
		write("roles/test-role", map[string]interface{}{
			"default_ttl": 900, "max_ttl": 3600, "scopes": "read,write", "minter_set": "default",
		})
	}

	rewriteWithout := func(t *testing.T, b logical.Backend, storage logical.Storage) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
			Data: map[string]interface{}{
				"minters": []interface{}{
					map[string]interface{}{"id": "minter-2", "token": "dop_v1_reseeded", "never_expires": true},
				},
			},
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("reseed minter-set failed: err=%v resp=%v", err, resp)
		}
	}

	return plugintest.Harness{
		Factory:                  credentialdo.Factory,
		Configure:                configure,
		IssuePath:                "creds/test-role",
		RewriteDefaultSetWithout: rewriteWithout,
		ProvisionedCount:         srv.ProvisionedCount,
		ExpectsHardRevoke:        true,
	}, srv
}

func TestResilience_Reload(t *testing.T) {
	h, _ := newResilienceHarness(t)
	plugintest.RunReloadSuite(t, h)
}

func TestResilience_Perturbation(t *testing.T) {
	h, _ := newResilienceHarness(t)
	plugintest.RunPerturbationSuite(t, h)
}

func TestResilience_Revoke(t *testing.T) {
	h, _ := newResilienceHarness(t)
	plugintest.RunRevokeResilienceSuite(t, h)
}
```

- [ ] **Step 3: Run — observe which categories fail (the bugs)**

```bash
cd plugins/credential-do && go test ./... -run TestResilience -v 2>&1 | tail -30
```
Expected: `TestResilience_Reload` PASSES (DO's minter token is self-contained — KI-001 doesn't bite DO). `TestResilience_Perturbation` FAILS with a revoke error ("minter ... not found in set") — this is KI-002, and proves the test has teeth. `TestResilience_Revoke` (double-revoke) likely FAILS too if the second revoke errors on the already-deleted token.

- [ ] **Step 4: Record the red result, do NOT fix yet**

The fixes are Tasks 12–13. Leave the failing tests in place. Commit the tests as the red baseline.

```bash
git add pkg/credenvelope/fakes/do.go plugins/credential-do/resilience_test.go
git commit -m "test(credential-do): add resilience suite + fake ProvisionedCount (red: exposes KI-002)"
```

---

## Tasks 3–11: replicate the resilience suite in the other 9 plugins

Each task applies Task 2's pattern to one plugin: add `ProvisionedCount` to its fake, create `resilience_test.go` wiring its Factory/fake/configure into the three harness runners. Read the plugin's existing `setupConfiguredBackend` (in its `path_creds_test.go`) to copy the exact config/minter-set/role write shape, and the DO `resilience_test.go` (committed in Task 2) as the structural template.

For each: commit `test(credential-<cloud>): add resilience suite + fake ProvisionedCount`. Do NOT fix any failures — they are the red baseline for Tasks 12–13. Record per plugin which categories fail.

**Per-plugin specifics** (the fake's token-map field, the configure shape, the revoke class):

### Task 3: credential-upcloud
- Fake: `pkg/credenvelope/fakes/upcloud.go` — `ProvisionedCount` returns `len(s.tokens)` (verify field name). 
- Configure: writes `config` with `username` + `upcloud_api_url`, `minter-sets/default`, role with `minter_set=default`. Copy from `plugins/credential-upcloud/path_creds_test.go` setupConfiguredBackend.
- `ExpectsHardRevoke: true`.
- **Expected red:** `TestResilience_Reload` FAILS (KI-001 — `username` not reloaded) AND `TestResilience_Perturbation` FAILS (KI-002). This is the key plugin proving KI-001.

### Task 4: credential-exoscale
- Fake: `exoscale.go` — count its api-keys map. Configure per its test helper (role has `role_id`). `ExpectsHardRevoke: true`.

### Task 5: credential-aws
- Fake: AWS uses an injected STS client, not an HTTP fake. `ProvisionedCount` must come from the test's fake STS client (count issued credentials it has minted). Wire the harness `ProvisionedCount` to that fake's counter; add one if absent.
- `ExpectsHardRevoke: false` (STS expires; revoke is a no-op).
- **Expected:** R passes (audit: AWS may also have config-only fields — `region`; if the STS endpoint/region isn't reloaded, R could fail — record it). P passes (no-op revoke already tolerates missing minter — confirm). Double-revoke passes.

### Task 6: credential-gcp
- Injected IAM client fake (like AWS). `ProvisionedCount` from the fake. `ExpectsHardRevoke: false`. Audit `project`/endpoint reload for R.

### Task 7: credential-ovh
- Fake: `ovh.go` has `TokenCount` — add `ProvisionedCount` delegating to it. `ExpectsHardRevoke: false` (1h tokens, no-op revoke). Audit `region`/`token_endpoint` reload for R (OVH sets these in config only — R may FAIL; record it).

### Task 8: credential-azure
- Fake: `azure.go` has `PasswordCount` — add `ProvisionedCount` delegating to it. `ExpectsHardRevoke: true` (removePassword). Configure writes `tenant_id` + endpoints. **Audit R carefully:** tenant_id/endpoints are config-only → reload may FAIL (a second KI-001 instance). Record it.

### Task 9: credential-vultr
- Fake: `vultr.go` — count users map. `ExpectsHardRevoke: true`.

### Task 10: credential-akamai
- Fake: `akamai.go` — count api-clients map. `ExpectsHardRevoke: true`. Configure writes `host`. Note: Akamai already has `loadHost` in Factory, so R should PASS — this validates the fix pattern already works when applied.

### Task 11: credential-oci
- OCI is phased-rotation. Issue reads the freshest slot (no per-read cloud call). `ExpectsHardRevoke: false` (soft revoke). Fake: injected OCI client — `ProvisionedCount` from the fake's token store.
- Reload (R): OCI provisions slots on role write; after reload the slots are in storage. Audit whether the rotation worker / slot read works on a reloaded backend (region is config-only → may FAIL R). Record it.
- Perturbation (P): OCI's revoke is already soft (forgets the lease), so P likely PASSES. Confirm.

---

## Task 12: Fix KI-001 — load config on backend init

**Files (per affected plugin, determined by which Category R tests are red):** at minimum `credential-upcloud`; plus any others whose `TestResilience_Reload` failed in Tasks 3–11 (candidates: azure, ovh, oci).
- Modify: `plugins/credential-<cloud>/backend.go` (Factory)
- Modify: `plugins/credential-<cloud>/path_config.go` (add `loadConfig` helper)

- [ ] **Step 1: Add a `loadConfig` helper to each affected plugin's path_config.go**

Using UpCloud as the worked example. In `plugins/credential-upcloud/path_config.go`:
```go
// loadConfig rehydrates operational config from storage into the backend.
// Called from Factory so a reloaded backend (failover/restart) has the same
// in-memory state as one that just had `config` written. Fixes KI-001.
func (b *backend) loadConfig(ctx context.Context, storage logical.Storage) error {
	entry, err := storage.Get(ctx, "config")
	if err != nil {
		return err
	}
	if entry == nil {
		return nil
	}
	var cfg cloudconfig.PluginConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return err
	}
	b.mu.Lock()
	b.config = &cfg
	b.mu.Unlock()

	// UpCloud stores the basic-auth username separately.
	uEntry, err := storage.Get(ctx, "config/username")
	if err != nil {
		return err
	}
	if uEntry != nil {
		b.mu.Lock()
		b.username = string(uEntry.Value)
		b.mu.Unlock()
	}
	return nil
}
```
IMPORTANT: confirm how `pathConfigWrite` persists the username. Read `plugins/credential-upcloud/path_config.go` — it stores `config/username` (or username inside the config blob). Match `loadConfig` to the actual persisted shape. If username lives inside the `config` JSON blob, `loadConfig` sets `b.username = cfg.Username` and there is no separate `config/username` read.

- [ ] **Step 2: Call `loadConfig` in Factory before `loadAllMinterSets`**

In `plugins/credential-upcloud/backend.go`, change the storage-load block:
```go
	if conf.StorageView != nil {
		_ = b.loadConfig(ctx, conf.StorageView)
		_ = b.loadAllMinterSets(ctx, conf.StorageView)
	}
```

- [ ] **Step 3: Run the reload suite — now green**

```bash
cd plugins/credential-upcloud && go test ./... -run TestResilience_Reload -v 2>&1 | tail -15
```
Expected: PASS.

- [ ] **Step 4: Apply the same fix to every other plugin whose R test was red**

For each (e.g. azure: load `tenant_id`/endpoints; ovh: `region`/`token_endpoint`; oci: `region`), add an analogous `loadConfig` reading exactly the storage keys that plugin's `pathConfigWrite` persists, and call it in Factory. Run each plugin's `TestResilience_Reload` to confirm green.

- [ ] **Step 5: Run full suites for the touched plugins**

```bash
for p in upcloud azure ovh oci; do (cd plugins/credential-$p && go test ./... -race 2>&1 | tail -1); done
```
Expected: all PASS (or, for plugins still red on Perturbation, that's KI-002 — fixed next task).

- [ ] **Step 6: Commit**

```bash
git add plugins/credential-*/backend.go plugins/credential-*/path_config.go
git commit -m "fix: load operational config on backend init (KI-001)

Factory now rehydrates config (incl. cloud-specific auth fields like
UpCloud's username) from storage, so a backend re-instantiated on raft
failover / plugin reload works without re-writing config."
```

---

## Task 13: Fix KI-002 — revoke tolerates a missing issuing minter

**Files:** the 6 hard-revoke plugins: `credential-do`, `credential-upcloud`, `credential-exoscale`, `credential-azure`, `credential-vultr`, `credential-akamai`.
- Modify: `plugins/credential-<cloud>/path_creds.go` (pathCredsRevoke + getMinter usage)
- Modify: `docs/decisions.md`

- [ ] **Step 1: Make revoke tolerate a missing minter (DO worked example)**

In `plugins/credential-do/path_creds.go`, `pathCredsRevoke` currently does:
```go
	client, err := b.getMinter(minterSet, minterID)
	if err != nil {
		return nil, err   // <- triggers infinite OpenBao retry
	}
```
Replace with tolerant handling — try the recorded minter, fall back to any healthy minter in the set, and if none is available treat revoke as a clean no-op (the credential TTL-expires):
```go
	client, err := b.getMinter(minterSet, minterID)
	if err != nil {
		// The issuing minter is gone (e.g. the set was re-seeded). We can no
		// longer actively delete the upstream credential, but it expires via
		// its own TTL. Try any healthy minter in the set; if none, no-op.
		fallback, ferr := b.anyHealthyMinterInSet(minterSet)
		if ferr != nil {
			b.Logger().Warn("revoke: issuing minter gone and no fallback; "+
				"leaving credential to expire via TTL",
				"minter_set", minterSet, "minter_id", minterID, "error", err)
			if delErr := req.Storage.Delete(ctx, "active-tokens/"+tokenID); delErr != nil {
				b.Logger().Warn("failed to remove active token tracking", "token_id", tokenID, "error", delErr)
			}
			return nil, nil
		}
		client = fallback
	}
```
Add the helper (near `selectMinter`):
```go
// anyHealthyMinterInSet returns a client for any healthy minter in the named
// set, or an error if the set is absent/empty. Used by revoke fallback.
func (b *backend) anyHealthyMinterInSet(setName string) (*doClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	apiURL := b.doAPIURL()
	if states, ok := b.minterSets[setName]; ok {
		for _, ms := range states {
			if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
				return newDOClient(apiURL, ms.minter.Token), nil
			}
		}
	}
	return nil, fmt.Errorf("no healthy minter in set %q", setName)
}
```
(If a plugin already has an `anyHealthyMinter()` for the reconciler, add the set-scoped variant alongside it.)

- [ ] **Step 2: Run DO perturbation suite — now green**

```bash
cd plugins/credential-do && go test ./... -run TestResilience_Perturbation -v 2>&1 | tail -15
```
Expected: PASS.

- [ ] **Step 3: Apply the same fix to the other 5 hard-revoke plugins**

upcloud, exoscale, azure, vultr, akamai — same structure, using each plugin's client type and its `active-*` tracking key name (DO/upcloud/exoscale/akamai use `active-tokens/` or `active-clients/`; vultr uses `active-users/`; azure deletes a password). For azure, the fallback still attempts `RemovePassword` via the fallback client; if no minter, no-op.

- [ ] **Step 4: Run perturbation + double-revoke suites for all 6**

```bash
for p in do upcloud exoscale azure vultr akamai; do
  echo "== $p =="; (cd plugins/credential-$p && go test ./... -run TestResilience -race 2>&1 | tail -1)
done
```
Expected: all PASS.

- [ ] **Step 5: Add the decision note**

Append to `docs/decisions.md`:
```markdown

## Why revoke tolerates a missing issuing minter (KI-002)

A hard-revoke plugin deletes the upstream credential on lease revoke using the
minter that issued it. If that minter was removed from its set after issuance
(e.g. the set was re-seeded), the plugin can no longer make that delete call.
Returning an error causes OpenBao to retry the revoke forever.

Decision: revoke falls back to any healthy minter in the same set, and if none
is available, treats revoke as a successful no-op (logged). This deliberately
weakens the "revoke deletes the upstream credential" property in the
minter-removed case. It is acceptable because the real guarantee is TTL expiry:
every issued credential has a bounded lifetime, so a credential that can't be
actively deleted still expires. A clean no-op lets the lease release rather than
accumulating infinite failed retries.
```

- [ ] **Step 6: Commit**

```bash
git add plugins/credential-*/path_creds.go docs/decisions.md
git commit -m "fix: revoke tolerates a removed issuing minter (KI-002)

Hard-revoke plugins now fall back to any healthy minter in the set, and
no-op (logging) if none remains, rather than returning an error that
OpenBao retries forever. The credential expires via TTL regardless."
```

---

## Task 14: Full verification + docs + close known issues

**Files:**
- Modify: `docs/known-issues.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Whole-workspace race test**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds
go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | grep -E "^(ok|FAIL)"
```
Expected: all packages `ok` (now including `pkg/plugintest`). No FAIL.

- [ ] **Step 2: Confirm every plugin has a resilience suite that passes**

```bash
for p in do upcloud exoscale aws gcp ovh azure vultr akamai oci; do
  echo "== $p =="; (cd plugins/credential-$p && go test ./... -run TestResilience -race 2>&1 | tail -1)
done
```
Expected: all PASS.

- [ ] **Step 3: Lint + smoke**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
make lint
make smoke-test
```
Expected: 0 lint issues; all 10 plugins register.

- [ ] **Step 4: Mark KI-001/KI-002 resolved in `docs/known-issues.md`**

At the top of each entry, change the heading to include `[RESOLVED 2026-05-30]` and add a line under it:
- KI-001: `**Resolved:** `Factory` now calls `loadConfig` (Task 12). Regression: `TestResilience_Reload` in every plugin's `resilience_test.go`.`
- KI-002: `**Resolved:** revoke falls back / no-ops when the issuing minter is gone (Task 13). Regression: `TestResilience_Perturbation`. Rationale in `docs/decisions.md`.`

- [ ] **Step 5: Document the taxonomy as a requirement in CLAUDE.md**

Add under Conventions:
```markdown
- Every plugin MUST have a `resilience_test.go` wiring `pkg/plugintest` (reload, perturbation, revoke-resilience categories). New plugins are not complete without it. See `docs/superpowers/specs/2026-05-30-resilience-test-taxonomy-design.md`.
```

- [ ] **Step 6: Commit**

```bash
git add docs/known-issues.md CLAUDE.md
git commit -m "docs: close KI-001/KI-002, require resilience_test.go per plugin"
```

---

## Summary of files

```
pkg/plugintest/                          (NEW module: harness.go, reload.go, perturbation.go, revoke.go, go.mod)
pkg/credenvelope/fakes/<cloud>.go        + ProvisionedCount() (×10)
plugins/credential-<cloud>/
├── resilience_test.go                   (NEW ×10: Harness + 3 runners)
├── backend.go                           (KI-001: loadConfig in Factory — affected plugins)
├── path_config.go                       (KI-001: loadConfig helper — affected plugins)
└── path_creds.go                        (KI-002: tolerant revoke — 6 hard-revoke plugins)
docs/decisions.md                        (KI-002 rationale)
docs/known-issues.md                     (KI-001/KI-002 resolved)
CLAUDE.md                                (taxonomy requirement)
go.work                                  (+ pkg/plugintest)
```
```
```
