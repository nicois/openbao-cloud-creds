# Minter Sets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single flat per-cloud minter list with named **minter sets**, bind each role to a required set, and record minting provenance in the envelope — across all 10 plugins.

**Architecture:** Minters move out of `config` into `minter-sets/<name>` (CRUD endpoint), each set independently validated by the existing `(≥1 never_expires) OR (≥2 with ≥7d gap)` rule. Roles gain a required `minter_set` field; issuance mints only from that set. Envelope metadata gains `minter_set`/`minter_id` (api_version already bumped to "2" in the shared package). OCI's rotation slots bind to a role's set instead of a flat minter list.

**Tech Stack:** Go 1.26.1, OpenBao SDK v2.5.1, golangci-lint v2. Shared changes (`pkg/credenvelope` v2, `pkg/cloudconfig.MinterSet` + `ValidateSetName`) are already committed.

---

## Prerequisites (already done)

The shared-package foundation is committed on this branch:
- `pkg/credenvelope`: `Metadata`/`EnvelopeParams` have `MinterSet`+`MinterID`; `APIVersion` const = `"2"`; `ToMap()` emits both; tests assert `"2"`.
- `pkg/cloudconfig`: `MinterSet{Name, Minters}` type and `ValidateSetName(name)`.

Verify before starting:
```bash
go test github.com/nicois/openbao-cloud-creds/pkg/credenvelope/... github.com/nicois/openbao-cloud-creds/pkg/cloudconfig/...
```
Expected: PASS.

---

## Task 1: credential-do — minter sets (REFERENCE IMPLEMENTATION)

This task fully implements minter sets in the DO plugin. Tasks 2–10 replicate this exact structure, so get it right here. **The other plugins will read these committed DO files as their template.**

**Files:**
- Create: `plugins/credential-do/path_minter_sets.go`
- Modify: `plugins/credential-do/backend.go`
- Modify: `plugins/credential-do/path_config.go`
- Modify: `plugins/credential-do/path_roles.go`
- Modify: `plugins/credential-do/path_creds.go`
- Modify: `plugins/credential-do/health_check.go`
- Modify: `plugins/credential-do/telemetry.go`
- Modify: `plugins/credential-do/path_config_test.go` (test helper)
- Modify: `plugins/credential-do/path_roles_test.go`
- Modify: `plugins/credential-do/path_creds_test.go`
- Create: `plugins/credential-do/minter_sets_test.go`

- [ ] **Step 1: Write the failing minter-set test**

Create `plugins/credential-do/minter_sets_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestMinterSetCRUD(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write a set
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/backup",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "m1", "token": "dop_v1_a", "never_expires": true},
			},
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("set write failed: err=%v resp=%v", err, resp)
	}

	// Read it back
	req = &logical.Request{Operation: logical.ReadOperation, Path: "minter-sets/backup", Storage: storage}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("set read failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["minter_count"] != 1 {
		t.Fatalf("expected minter_count=1, got %v", resp.Data["minter_count"])
	}

	// List
	req = &logical.Request{Operation: logical.ListOperation, Path: "minter-sets/", Storage: storage}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil {
		t.Fatalf("set list failed: err=%v resp=%v", err, resp)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "backup" {
		t.Fatalf("unexpected keys: %v", keys)
	}
}

func TestMinterSetValidationRejectsSingleExpiring(t *testing.T) {
	b, storage := getTestBackend(t)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/bad",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "m1", "token": "x", "expires_at": "2027-01-01T00:00:00Z"},
			},
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for single expiring minter in a set")
	}
}
```

- [ ] **Step 2: Run it to confirm it fails**

```bash
cd plugins/credential-do && go test ./... -run TestMinterSet 2>&1 | head
```
Expected: compile failure (no `minter-sets` path) or test failure.

- [ ] **Step 3: Create `path_minter_sets.go`**

```go
package credentialdo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) minterSetPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "minter-sets/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name":    {Type: framework.TypeString, Description: "Name of the minter set"},
				"minters": {Type: framework.TypeSlice, Description: "Minter credentials in this set"},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathMinterSetWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathMinterSetRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathMinterSetDelete},
			},
		},
		{
			Pattern: "minter-sets/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathMinterSetList},
			},
		},
	}
}

// parseMinters converts the raw "minters" field into cloudconfig.Minters.
func parseMinters(d *framework.FieldData) ([]cloudconfig.Minter, error) {
	raw := d.Get("minters")
	if raw == nil {
		return nil, fmt.Errorf("minters is required")
	}
	slice, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("minters must be an array")
	}
	var minters []cloudconfig.Minter
	for _, m := range slice {
		mMap, ok := m.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("each minter must be an object")
		}
		minter := cloudconfig.Minter{
			ID:        fmt.Sprintf("%v", mMap["id"]),
			Token:     fmt.Sprintf("%v", mMap["token"]),
			CreatedAt: time.Now(),
		}
		if ne, ok := mMap["never_expires"].(bool); ok && ne {
			minter.NeverExpires = true
		}
		if exp, ok := mMap["expires_at"].(string); ok {
			t, err := time.Parse(time.RFC3339, exp)
			if err != nil {
				return nil, fmt.Errorf("invalid expires_at for minter %s: %v", minter.ID, err)
			}
			minter.ExpiresAt = t
		}
		minters = append(minters, minter)
	}
	return minters, nil
}

func (b *backend) pathMinterSetWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := cloudconfig.ValidateSetName(name); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	minters, err := parseMinters(d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := cloudconfig.ValidateMinterSet(minters); err != nil {
		return logical.ErrorResponse("invalid minter set: %v", err), nil
	}
	set := &cloudconfig.MinterSet{Name: name, Minters: minters}
	entry, err := logical.StorageEntryJSON("minter-sets/"+name, set)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	b.loadMinterSet(set)
	go b.startWorkers(context.Background(), req.Storage)
	return nil, nil
}

func (b *backend) pathMinterSetRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	entry, err := req.Storage.Get(ctx, "minter-sets/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var set cloudconfig.MinterSet
	if err := json.Unmarshal(entry.Value, &set); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(set.Minters))
	for _, m := range set.Minters {
		ids = append(ids, m.ID)
	}
	return &logical.Response{Data: map[string]interface{}{
		"name": set.Name, "minter_count": len(set.Minters), "minter_ids": ids,
	}}, nil
}

func (b *backend) pathMinterSetDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := req.Storage.Delete(ctx, "minter-sets/"+name); err != nil {
		return nil, err
	}
	b.mu.Lock()
	delete(b.minterSets, name)
	b.mu.Unlock()
	return nil, nil
}

func (b *backend) pathMinterSetList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "minter-sets/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *backend) loadMinterSet(set *cloudconfig.MinterSet) {
	b.mu.Lock()
	defer b.mu.Unlock()
	states := make(map[string]*minterState, len(set.Minters))
	for _, m := range set.Minters {
		states[m.ID] = &minterState{
			set:    set.Name,
			minter: m,
			sm: recovery.NewStateMachine(recovery.Config{
				AuthFailThreshold:   30 * time.Second,
				HealthCheckInterval: 5 * time.Minute,
			}),
		}
	}
	b.minterSets[set.Name] = states
}

func (b *backend) loadAllMinterSets(ctx context.Context, storage logical.Storage) error {
	names, err := storage.List(ctx, "minter-sets/")
	if err != nil {
		return err
	}
	for _, name := range names {
		entry, err := storage.Get(ctx, "minter-sets/"+name)
		if err != nil || entry == nil {
			continue
		}
		var set cloudconfig.MinterSet
		if err := json.Unmarshal(entry.Value, &set); err != nil {
			continue
		}
		b.loadMinterSet(&set)
	}
	return nil
}
```

- [ ] **Step 4: Update `backend.go` — state shape and path registration**

Replace the `minters` field and `minterState`, and register the new path. The struct becomes:
```go
type backend struct {
	*framework.Backend
	mu            sync.RWMutex
	config        *cloudconfig.PluginConfig
	minterSets    map[string]map[string]*minterState // setName -> minterID -> state
	apiURL        string
	accessTracker *metrics.AccessTracker
	workerMgr     *worker.Manager
	workerCancel  context.CancelFunc
}

type minterState struct {
	set    string
	minter cloudconfig.Minter
	sm     *recovery.StateMachine
}
```
In `Factory`, change `minters: make(...)` to `minterSets: make(map[string]map[string]*minterState)`, add `b.minterSetPaths()` to `framework.PathAppend(...)`, and after `b.Setup` load persisted sets:
```go
	store := metrics.NewInMemoryStore()
	b.accessTracker = metrics.NewAccessTracker("local", store)

	if conf.StorageView != nil {
		_ = b.loadAllMinterSets(ctx, conf.StorageView)
	}
```

- [ ] **Step 5: Update `path_config.go` — remove minters**

Delete the `"minters"` field from the config schema, all minter-parsing logic in `pathConfigWrite`, and the `b.minters` population block. `config` now holds only operational + cloud settings. The DO config keeps `flush_interval`, `reconcile_cadence`, `do_api_url`. `PluginConfig.Minters` is no longer set here. `pathConfigRead` drops `minter_count`. The write still calls `go b.startWorkers(...)`. Result:
```go
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	flushInterval := time.Duration(d.Get("flush_interval").(int)) * time.Second
	reconcileCadence := time.Duration(d.Get("reconcile_cadence").(int)) * time.Second

	cfg := &cloudconfig.PluginConfig{
		Cloud:             "do",
		FlushInterval:     flushInterval,
		ReconcileCadence:  reconcileCadence,
		BootstrapDelay:    24 * time.Hour,
		MaxDeletesPerPass: 10,
	}
	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.config = cfg
	if url, ok := d.GetOk("do_api_url"); ok {
		b.apiURL = url.(string)
	}
	b.mu.Unlock()
	go b.startWorkers(context.Background(), req.Storage)
	return nil, nil
}
```
And remove the now-unused `recovery` import from `path_config.go` if present.

- [ ] **Step 6: Update `path_roles.go` — required `minter_set` field**

Add to the `doRole` struct: `MinterSet string \`json:"minter_set"\``. Add the field to the role schema:
```go
"minter_set": {Type: framework.TypeString, Description: "Name of the minter set this role mints from (required)"},
```
In `pathRoleWrite`, after reading other fields:
```go
	minterSet := d.Get("minter_set").(string)
	if minterSet == "" {
		return logical.ErrorResponse("minter_set is required"), nil
	}
	exists, err := b.minterSetExists(ctx, req.Storage, minterSet)
	if err != nil {
		return nil, err
	}
	if !exists {
		return logical.ErrorResponse("minter_set %q does not exist", minterSet), nil
	}
```
Persist `MinterSet: minterSet` in the stored `doRole`, and return it in `pathRoleRead`. Add this helper (in `path_minter_sets.go` is fine, but put it where `path_roles.go` can call it — package-level):
```go
func (b *backend) minterSetExists(ctx context.Context, storage logical.Storage, name string) (bool, error) {
	entry, err := storage.Get(ctx, "minter-sets/"+name)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}
```

- [ ] **Step 7: Update `path_creds.go` — set-scoped minting + provenance**

Change `selectMinter()` to take a set name and search only that set; thread set+minter through. Replace the relevant functions:
```go
func (b *backend) selectMinter(setName string) (setID, minterID string, client *doClient, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	states, ok := b.minterSets[setName]
	if !ok {
		return "", "", nil, fmt.Errorf("upstream_auth_failed: minter set %q not loaded", setName)
	}
	apiURL := b.doAPIURL()
	for id, ms := range states {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			return setName, id, newDOClient(apiURL, ms.minter.Token), nil
		}
	}
	return "", "", nil, fmt.Errorf("upstream_auth_failed: all minters in set %q are failing", setName)
}

func (b *backend) getMinter(setName, id string) (*doClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	apiURL := b.doAPIURL()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			return newDOClient(apiURL, ms.minter.Token), nil
		}
	}
	return nil, fmt.Errorf("minter %q not found in set %q", id, setName)
}

func (b *backend) recordMinterSuccess(setName, id string, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			ms.sm.RecordSuccess(at)
		}
	}
}

func (b *backend) recordMinterError(setName, id string, httpStatus int, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[id]; ok {
			ms.sm.RecordError(httpStatus, at)
		}
	}
}
```
In `pathCredsRead`, after loading the role:
```go
	setName, minterID, client, err := b.selectMinter(role.MinterSet)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
```
Replace `b.recordMinterError(minterID, httpStatus, now)` → `b.recordMinterError(setName, minterID, httpStatus, now)` and the success call similarly. Add `MinterSet`/`MinterID` to the envelope params:
```go
		Scope:        role.Scopes,
		IssuedBy:     "cloud-creds-do/v0.1",
		MinterSet:    setName,
		MinterID:     minterID,
```
Store the set in `internal_data` for revoke:
```go
	resp := b.Secret("do_token").Response(env.ToMap(), map[string]interface{}{
		"upstream_token_id": tokenResp.Token.ID,
		"role":              roleName,
		"minter_set":        setName,
		"minter_id":         minterID,
	})
```
In `pathCredsRevoke`, read both and use the set-aware getter:
```go
	minterSet, _ := req.Secret.InternalData["minter_set"].(string)
	minterID, _ := req.Secret.InternalData["minter_id"].(string)
	client, err := b.getMinter(minterSet, minterID)
	if err != nil {
		return nil, err
	}
	...
	httpStatus, err := client.DeleteToken(ctx, tokenID)
	if err != nil {
		b.recordMinterError(minterSet, minterID, httpStatus, now)
		emitLeaseRevokeFailed(roleName)
		return nil, fmt.Errorf("revoke failed: %v", err)
	}
	b.recordMinterSuccess(minterSet, minterID, now)
```
Update the `accessTracker.RecordAccess(minterID, roleName, now)` call to use a composite entity so provenance is preserved: `b.accessTracker.RecordAccess(minterSet+"/"+minterID, roleName, now)`.

- [ ] **Step 8: Update `health_check.go` — iterate sets**

The worker must walk every minter in every set:
```go
func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	type probe struct{ set, id, token string; sm *recovery.StateMachine }
	var probes []probe
	apiURL := b.doAPIURL()
	for setName, states := range b.minterSets {
		for id, ms := range states {
			if ms.sm.NeedsHealthCheck(time.Now()) {
				probes = append(probes, probe{setName, id, ms.minter.Token, ms.sm})
			}
		}
	}
	b.mu.RUnlock()

	now := time.Now()
	for _, p := range probes {
		client := newDOClient(apiURL, p.token)
		status, err := client.CheckHealth(ctx)
		if err != nil {
			continue
		}
		if status == 200 {
			p.sm.RecordSuccess(now)
		} else {
			p.sm.RecordError(status, now)
		}
	}
	b.emitMinterMetrics()
	return nil
}
```
Add the `recovery` import to `health_check.go` if not present.

- [ ] **Step 9: Update `telemetry.go` — set label on minter metrics**

`emitMinterMetrics` iterates `b.minterSets` and adds a `minter_set` label:
```go
func (b *backend) emitMinterMetrics() {
	b.mu.RLock()
	defer b.mu.RUnlock()
	now := time.Now()
	for setName, states := range b.minterSets {
		for id, ms := range states {
			labels := []metrics.Label{
				{Name: "cloud", Value: "do"},
				{Name: "minter_set", Value: setName},
				{Name: "cred_id", Value: id},
			}
			emitGauge([]string{"cloud_creds", "upstream_state"}, 1, append(labels, metrics.Label{Name: "state", Value: string(ms.sm.State())}))
			emitGauge([]string{"cloud_creds", "upstream_consecutive_failures"}, float32(ms.sm.ConsecutiveFailures()), labels)
			if ls := ms.sm.LastSuccessAt(); !ls.IsZero() {
				emitGauge([]string{"cloud_creds", "upstream_last_success_seconds_ago"}, float32(now.Sub(ls).Seconds()), labels)
			}
			if !ms.minter.ExpiresAt.IsZero() {
				emitGauge([]string{"cloud_creds", "upstream_expires_in_seconds"}, float32(ms.minter.ExpiresAt.Sub(now).Seconds()), labels)
			}
		}
	}
}
```

- [ ] **Step 10: Update test helpers in `path_config_test.go`**

`setupConfiguredBackend` must now create a minter set and a role bound to it. Replace the config-write-with-minters block. The new helper:
```go
func setupConfiguredBackend(t *testing.T, doURL string) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)

	// config: operational settings only
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{"do_api_url": doURL},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// minter set
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{"id": "minter-1", "token": "dop_v1_test", "never_expires": true},
			},
		},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// role bound to the set
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/test-role", Storage: storage,
		Data: map[string]interface{}{
			"default_ttl": 900, "max_ttl": 3600, "scopes": "read,write", "minter_set": "default",
		},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}
	return b, storage
}
```
Update `TestConfigWriteRead` to not send `minters` (it now lives in minter-sets).

- [ ] **Step 11: Update `path_roles_test.go`**

Every role-write in tests must include `"minter_set": "default"` (and create that set first where the test doesn't use `setupConfiguredBackend`). For `TestRoleCRUD`, add a minter-set write before the role write, add `"minter_set": "default"` to the role data, and assert `resp.Data["minter_set"] == "default"` on read. Add a new test:
```go
func TestRoleRequiresExistingMinterSet(t *testing.T) {
	b, storage := getTestBackend(t)
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/orphan", Storage: storage,
		Data: map[string]interface{}{"default_ttl": 900, "max_ttl": 3600, "scopes": "read", "minter_set": "nonexistent"},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error binding role to nonexistent minter set")
	}
}
```

- [ ] **Step 12: Update `path_creds_test.go` — provenance assertion**

In `TestCredsIssue`, after the existing checks, assert provenance:
```go
	meta := resp.Data["metadata"].(map[string]interface{})
	if meta["minter_set"] != "default" {
		t.Fatalf("expected minter_set=default, got %v", meta["minter_set"])
	}
	if meta["minter_id"] != "minter-1" {
		t.Fatalf("expected minter_id=minter-1, got %v", meta["minter_id"])
	}
	if meta["api_version"] != "2" {
		t.Fatalf("expected api_version=2, got %v", meta["api_version"])
	}
```
Add an isolation test proving a role only uses its own set:
```go
func TestMinterSetIsolation(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL) // has set "default" + role "test-role"

	// Add a second, independent set "secondary" and a role bound to it.
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/secondary", Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-2", "token": "dop_v1_other", "never_expires": true},
		}},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("secondary set write: err=%v resp=%v", err, resp)
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/role2", Storage: storage,
		Data: map[string]interface{}{"default_ttl": 900, "max_ttl": 3600, "scopes": "read", "minter_set": "secondary"},
	}
	if resp, err := b.HandleRequest(context.Background(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role2 write: err=%v resp=%v", err, resp)
	}

	// role2 must mint via minter-2.
	req = &logical.Request{Operation: logical.ReadOperation, Path: "creds/role2", Storage: storage}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("role2 issue failed: err=%v resp=%v", err, resp)
	}
	meta := resp.Data["metadata"].(map[string]interface{})
	if meta["minter_set"] != "secondary" || meta["minter_id"] != "minter-2" {
		t.Fatalf("role2 used wrong minter: set=%v id=%v", meta["minter_set"], meta["minter_id"])
	}
}
```

- [ ] **Step 13: Run all DO tests**

```bash
cd plugins/credential-do && go test ./... -race 2>&1 | tail -20
```
Expected: PASS. Fix compile errors (the most likely: a leftover reference to `b.minters` — grep `grep -rn "b.minters\b" .` and convert).

- [ ] **Step 14: Lint**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
cd plugins/credential-do && golangci-lint run ./...
```
Expected: 0 issues. Run `gofmt -w .` first.

- [ ] **Step 15: Commit**

```bash
git add plugins/credential-do/
git commit -m "feat(credential-do): minter sets with required role binding and provenance"
```

---

## Tasks 2–9: replicate minter sets in the other JIT plugins

Each of these tasks applies the **exact same transformation as Task 1** to one plugin. The committed `plugins/credential-do/` files are the concrete template — read them (`path_minter_sets.go`, and the diffs in `backend.go`/`path_config.go`/`path_roles.go`/`path_creds.go`/`health_check.go`/`telemetry.go`/tests) and mirror them, substituting the cloud-specific details listed per task.

For every task in this group:
1. Create `path_minter_sets.go` (identical except the `recovery`/`metrics` label `Value: "<cloud>"`).
2. `backend.go`: `minters` → `minterSets map[string]map[string]*minterState`; `minterState` gains `set string`; register `b.minterSetPaths()`; load sets after `Setup`.
3. `path_config.go`: remove `minters` field + parsing; keep the cloud-specific config fields listed below.
4. `path_roles.go`: add required `minter_set` field + existence check + persist + return.
5. `path_creds.go`: `selectMinter(setName)`, set-aware `getMinter`/`recordMinter*`, envelope `MinterSet`/`MinterID`, `minter_set` in internal_data, composite metrics entity.
6. `health_check.go` + `telemetry.go`: iterate sets, add `minter_set` label.
7. Tests: update the `setupConfiguredBackend` helper (create set + bind role), add `minter_set` to all role writes, add provenance + isolation + role-requires-set tests.
8. Run `go test ./... -race` (PASS), `gofmt -w .`, `golangci-lint run ./...` (0 issues).
9. Commit `feat(credential-<cloud>): minter sets with required role binding and provenance`.

**Cloud-specific details (the only things that differ from DO):**

### Task 2: credential-upcloud
- Envelope/label cloud value: `upcloud`. Config retains `username`, `upcloud_api_url`, `flush_interval`, `reconcile_cadence`.
- `username` stays in `config` (account-level, shared across sets). The client constructor already takes username + token.
- Health check endpoint and client constructor are unchanged; just route the token through the set.

### Task 3: credential-exoscale
- Cloud value: `exoscale`. Config retains `exoscale_api_url`. Role already has `role_id` — keep it, add `minter_set` alongside.

### Task 4: credential-aws
- Cloud value: `aws`. Config retains `region`, `sts_endpoint`. Minter token is `access_key_id:secret_access_key` (compound) — `parseMinters` is unchanged (it reads the opaque `token` string); the AWS client split logic already lives in the client constructor, so just pass `ms.minter.Token` through as today.
- AWS has no revoke (STS expires) — `selectMinter(setName)` is used in `pathCredsRead`; there is no `getMinter` call in revoke (revoke is a no-op that clears tracking). Still thread `setName`/`minterID` into the envelope + internal_data + metrics. Skip the `getMinter`-in-revoke changes; keep revoke's no-op body but it may read `minter_set` for logging only.
- The STS client interface is injected for tests (`SetSTSClientFactory`); the per-set token must reach the factory. Confirm the factory is keyed on the minter token; route accordingly.

### Task 5: credential-gcp
- Cloud value: `gcp`. Config retains `project`. Minter token is the SA JSON. No revoke (token expires) — same no-op-revoke note as AWS.
- Uses an injected `IAMCredentialsClient` factory for tests — route the per-set minter's JSON through it.

### Task 6: credential-ovh
- Cloud value: `ovh`. Config retains `region`, `token_endpoint`. Minter token is `client_id:client_secret`. No revoke (1h tokens) — same no-op-revoke note.
- Uses an injected token-client factory; route per-set credentials through it.

### Task 7: credential-azure
- Cloud value: `azure`. Config retains `tenant_id`, `graph_endpoint`, `login_endpoint`. Minter token is `client_id:client_secret`.
- Azure HAS hard revoke (`removePassword`) — so the set-aware `getMinter(setName, minterID)` in revoke IS needed (mirror DO exactly).
- Azure caches a Graph token per minter; ensure the cache is keyed per (set, minter) — if the existing client caches on the backend, move the cache into the per-minter client instance or key it by minter ID. Verify no cross-minter token bleed.

### Task 8: credential-vultr
- Cloud value: `vultr`. Config retains `vultr_api_url`. Role has `acls`, `email_domain` — keep, add `minter_set`. Hard revoke (delete sub-user) — set-aware `getMinter` in revoke needed (mirror DO).

### Task 9: credential-akamai
- Cloud value: `akamai`. Config retains `host`, `akamai_api_url`. Minter token is `client_token:access_token:client_secret` (EdgeGrid triple). Hard revoke (delete API client) — set-aware `getMinter` in revoke needed.
- The EdgeGrid signer is built from the minter token; ensure it's constructed from the per-set minter.

---

## Task 10: credential-oci — minter sets for phased rotation

OCI differs: it pre-provisions **slots** rather than minting per-read. The minter (tenancy/user/key) that provisions slots must come from the role's bound set.

**Files:**
- Create: `plugins/credential-oci/path_minter_sets.go`
- Modify: `plugins/credential-oci/backend.go`, `path_config.go`, `path_roles.go`, `path_creds.go`, `slots.go`, `workers.go`, `health_check.go`, `telemetry.go`, tests.

- [ ] **Step 1: Create `path_minter_sets.go`**

Same as DO's (substitute `recovery`/metrics label value `oci`). OCI's minter token format is `tenancy_ocid:user_ocid:fingerprint:private_key_pem` — `parseMinters` reads it as the opaque `token` string unchanged.

- [ ] **Step 2: `backend.go` — set-keyed state**

Replace the flat minter map with `minterSets map[string]map[string]*minterState`, `minterState` gains `set string`, register `minterSetPaths()`, load sets after `Setup`. (Mirror DO Task 1 Step 4.)

- [ ] **Step 3: `path_config.go` — remove minters**

Keep `region`, `rotation_check_interval`, `flush_interval`, `reconcile_cadence`. Remove minter parsing. (Mirror DO Task 1 Step 5.)

- [ ] **Step 4: `path_roles.go` — required `minter_set`**

Add required `minter_set` (existence-checked), alongside OCI's existing `user_ocid`, `slot_count`, `rotation_period`. (Mirror DO Task 1 Step 6.)

- [ ] **Step 5: `slots.go` / `workers.go` — provision via the role's set**

Wherever a slot is provisioned or rotated, the OCI client must be built from a healthy minter in **the role's bound set**. Add a set-aware selector:
```go
func (b *backend) selectMinterForSet(setName string) (minterID string, client OCIIAMClient, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	states, ok := b.minterSets[setName]
	if !ok {
		return "", nil, fmt.Errorf("upstream_auth_failed: minter set %q not loaded", setName)
	}
	for id, ms := range states {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			return id, b.newOCIClient(ms.minter.Token), nil
		}
	}
	return "", nil, fmt.Errorf("upstream_auth_failed: all minters in set %q failing", setName)
}
```
(Use the existing client constructor name; if it's not `newOCIClient`, match the actual one.) The slot record should persist the `minter_set` and `minter_id` used, so rotation and cleanup use the same set.

- [ ] **Step 6: `path_creds.go` — provenance in the slot read**

When returning the freshest slot, populate envelope `MinterSet`/`MinterID` from the slot's recorded provenance. (The read itself doesn't call the cloud; the values come from the slot record.)

- [ ] **Step 7: `health_check.go` / `telemetry.go`**

Iterate every minter in every set; add `minter_set` label. (Mirror DO Steps 8–9.)

- [ ] **Step 8: Tests**

Update the OCI test setup to create a minter set and bind the role to it (the OCI suite uses an in-memory fake `OCIIAMClient` factory — route per-set minter through it). Add the role-requires-set test and a provenance assertion on the slot read (`metadata.minter_set` / `minter_id` present, `api_version` "2"). Update `rotation_test.go` setup similarly.

- [ ] **Step 9: Run, lint, commit**

```bash
cd plugins/credential-oci && gofmt -w . && go test ./... -race 2>&1 | tail -20
export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...
git add plugins/credential-oci/ && git commit -m "feat(credential-oci): minter sets bound to rotation slots with provenance"
```

---

## Task 11: Full verification, smoke test, and docs

**Files:**
- Modify: `docs/techrfc.md` (envelope section — add minter_set/minter_id, note api_version 2)
- Modify: `CLAUDE.md` (document the minter-set model)
- Modify: `README.md` (mention minter sets in the config flow)

- [ ] **Step 1: Whole-workspace test + race**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds/.claude/worktrees/minter-sets
go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | grep -E "^(ok|FAIL)"
```
Expected: all 17 packages `ok`.

- [ ] **Step 2: Full lint**

```bash
export PATH="$(go env GOPATH)/bin:$PATH" && make lint
```
Expected: 0 issues across all modules.

- [ ] **Step 3: Registration smoke test**

```bash
make smoke-test
```
Expected: all 10 plugins register and enable. (Confirms no Factory/path regressions from the state-shape change.)

- [ ] **Step 4: Update `docs/techrfc.md` envelope section**

In the envelope shape (around the `metadata` object in the "Issue a credential lease" section), add `minter_set` and `minter_id` to the metadata fields and change `api_version` to `"2"`. Add a sentence: "`metadata.minter_set` and `metadata.minter_id` identify the minting credential that issued this credential, for audit provenance."

- [ ] **Step 5: Update `CLAUDE.md`**

Add a "Minter sets" subsection under conventions:
```markdown
## Minter sets

Minters are grouped into named **sets** at `cloud-creds/<cloud>/minter-sets/<name>`, each independently validated by the `(≥1 never_expires) OR (≥2 with ≥7d gap)` rule. The bare `config` endpoint holds operational + cloud settings only (no minters). Every role has a **required** `minter_set` field and mints only from that set — there is no cross-set failover, by design (it's the isolation boundary). The issuing set+minter are recorded in `metadata.minter_set`/`minter_id` (envelope api_version 2) and in lease internal_data. For capability isolation, give each set's minters only the upstream rights its bound roles need.
```

- [ ] **Step 6: Update `README.md`**

In the build/usage flow, note the order: write `config`, then `minter-sets/<name>`, then `roles/<name>` with `minter_set=<name>`.

- [ ] **Step 7: Commit docs**

```bash
git add docs/techrfc.md CLAUDE.md README.md
git commit -m "docs: document minter sets and envelope api_version 2"
```

---

## Summary of files per plugin (×10, identical shape)

```
plugins/credential-<cloud>/
├── path_minter_sets.go   (NEW — set CRUD, loadMinterSet, loadAllMinterSets, minterSetExists)
├── backend.go            (minterSets map; minterState.set; register path; load on Factory)
├── path_config.go        (remove minters; keep cloud/operational settings)
├── path_roles.go         (required minter_set field + existence check + persist)
├── path_creds.go         (set-scoped selectMinter; provenance in envelope + internal_data)
├── health_check.go       (iterate sets)
├── telemetry.go          (minter_set label)
└── *_test.go             (helper creates set + binds role; provenance/isolation/requires-set tests)
```
OCI additionally touches `slots.go` and `workers.go` (slot provisioning uses the role's set).
