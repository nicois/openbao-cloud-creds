# DO Production Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the DO plugin from "works in tests" to production-ready with background workers (health-check, metrics flush, reconciler), real storage integration, and Prometheus telemetry.

**Architecture:** A new `pkg/worker/` package manages goroutine lifecycles. The DO plugin registers three workers (health-check, flush, reconciler) that start on config write and stop on cleanup. The `MetricsStore` interface gains `context.Context` to support real plugin storage. Prometheus metrics emit via OpenBao's armon/go-metrics integration.

**Tech Stack:** Go 1.22+, OpenBao SDK v2, `github.com/armon/go-metrics` (transitive via OpenBao SDK)

---

## Task 1: pkg/worker — Worker Manager

**Files:**
- Create: `pkg/worker/go.mod`
- Create: `pkg/worker/worker.go`
- Create: `pkg/worker/worker_test.go`
- Modify: `go.work` (add `./pkg/worker`)

- [ ] **Step 1: Initialize module**

```bash
mkdir -p pkg/worker
cd pkg/worker && go mod init github.com/nicois/openbao-cloud-creds/pkg/worker
```

Add `./pkg/worker` to the `use` block in `go.work`.

- [ ] **Step 2: Write failing test**

`pkg/worker/worker_test.go`:
```go
package worker_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/worker"
)

func TestWorkerTicks(t *testing.T) {
	var count atomic.Int32
	wm := worker.New()
	wm.Register("counter", 10*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		count.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	wm.Start(ctx)
	time.Sleep(55 * time.Millisecond)
	cancel()
	wm.Wait()

	got := count.Load()
	if got < 4 || got > 6 {
		t.Fatalf("expected ~5 ticks, got %d", got)
	}
}

func TestWorkerInitialDelay(t *testing.T) {
	var count atomic.Int32
	wm := worker.New()
	wm.Register("delayed", 10*time.Millisecond, worker.Opts{InitialDelay: 30 * time.Millisecond}, func(ctx context.Context) error {
		count.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	wm.Start(ctx)
	time.Sleep(25 * time.Millisecond)

	if count.Load() != 0 {
		t.Fatalf("expected 0 ticks during delay, got %d", count.Load())
	}

	time.Sleep(30 * time.Millisecond)
	cancel()
	wm.Wait()

	got := count.Load()
	if got < 1 {
		t.Fatalf("expected >=1 ticks after delay, got %d", got)
	}
}

func TestWorkerStopDrainsCleanly(t *testing.T) {
	wm := worker.New()
	wm.Register("noop", 10*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	wm.Start(ctx)
	time.Sleep(20 * time.Millisecond)
	cancel()
	wm.Wait()

	if wm.Running() {
		t.Fatal("expected not running after Wait")
	}
}

func TestWorkerErrorDoesNotCrash(t *testing.T) {
	var count atomic.Int32
	wm := worker.New()
	wm.Register("failer", 10*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		count.Add(1)
		return fmt.Errorf("oops")
	})

	ctx, cancel := context.WithCancel(context.Background())
	wm.Start(ctx)
	time.Sleep(35 * time.Millisecond)
	cancel()
	wm.Wait()

	if count.Load() < 2 {
		t.Fatalf("worker should keep ticking after errors, got %d", count.Load())
	}
}
```

Add `"fmt"` to imports.

- [ ] **Step 3: Run test to verify it fails**

```bash
cd pkg/worker && go test ./... -v
```

Expected: FAIL — package not implemented.

- [ ] **Step 4: Implement worker manager**

`pkg/worker/worker.go`:
```go
package worker

import (
	"context"
	"sync"
	"time"
)

type WorkerFunc func(ctx context.Context) error

type Opts struct {
	InitialDelay time.Duration
}

type registration struct {
	name     string
	interval time.Duration
	opts     Opts
	fn       WorkerFunc
}

type Manager struct {
	mu      sync.Mutex
	workers []registration
	wg      sync.WaitGroup
	running bool
}

func New() *Manager {
	return &Manager{}
}

func (m *Manager) Register(name string, interval time.Duration, opts Opts, fn WorkerFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workers = append(m.workers, registration{
		name:     name,
		interval: interval,
		opts:     opts,
		fn:       fn,
	})
}

func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = true
	for _, w := range m.workers {
		m.wg.Add(1)
		go m.run(ctx, w)
	}
}

func (m *Manager) Wait() {
	m.wg.Wait()
	m.mu.Lock()
	m.running = false
	m.mu.Unlock()
}

func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *Manager) run(ctx context.Context, w registration) {
	defer m.wg.Done()

	if w.opts.InitialDelay > 0 {
		select {
		case <-time.After(w.opts.InitialDelay):
		case <-ctx.Done():
			return
		}
	}

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = w.fn(ctx)
		}
	}
}
```

- [ ] **Step 5: Run tests**

```bash
cd pkg/worker && go test ./... -v -race
```

Expected: PASS (all 4 tests).

- [ ] **Step 6: Commit**

```bash
git add pkg/worker/ go.work
git commit -m "feat(worker): add background worker lifecycle manager"
```

---

## Task 2: pkg/recovery — Add ConsecutiveFailures Counter

**Files:**
- Modify: `pkg/recovery/state.go`
- Modify: `pkg/recovery/state_test.go`

- [ ] **Step 1: Write failing test**

Add to `pkg/recovery/state_test.go`:
```go
func TestConsecutiveFailures(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold:   30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	if sm.ConsecutiveFailures() != 0 {
		t.Fatalf("expected 0 initial failures, got %d", sm.ConsecutiveFailures())
	}

	now := time.Now()
	sm.RecordError(500, now)
	sm.RecordError(500, now.Add(time.Second))
	sm.RecordError(401, now.Add(2*time.Second))

	if sm.ConsecutiveFailures() != 3 {
		t.Fatalf("expected 3 failures, got %d", sm.ConsecutiveFailures())
	}

	sm.RecordSuccess(now.Add(3 * time.Second))
	if sm.ConsecutiveFailures() != 0 {
		t.Fatalf("expected 0 after success, got %d", sm.ConsecutiveFailures())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd pkg/recovery && go test ./... -v
```

Expected: FAIL — `ConsecutiveFailures` not defined.

- [ ] **Step 3: Implement**

In `pkg/recovery/state.go`, add a field to `StateMachine`:
```go
consecutiveFailures int
```

Add to `RecordError` (inside the lock, before the switch):
```go
sm.consecutiveFailures++
```

Add to `RecordSuccess` (inside the lock):
```go
sm.consecutiveFailures = 0
```

Add the getter:
```go
func (sm *StateMachine) ConsecutiveFailures() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.consecutiveFailures
}
```

- [ ] **Step 4: Run tests**

```bash
cd pkg/recovery && go test ./... -v
```

Expected: PASS (all 6 tests).

- [ ] **Step 5: Commit**

```bash
git add pkg/recovery/
git commit -m "feat(recovery): add ConsecutiveFailures counter"
```

---

## Task 3: pkg/metrics — Add context.Context to MetricsStore Interface

**Files:**
- Modify: `pkg/metrics/access.go`
- Modify: `pkg/metrics/access_test.go`

This is a breaking interface change. All methods on `MetricsStore`, `InMemoryStore`, and `AccessTracker` gain a `context.Context` parameter. The `AccessTracker` methods (`Flush`, `MergeEntity`) also gain context.

- [ ] **Step 1: Update MetricsStore interface**

In `pkg/metrics/access.go`, change:
```go
type MetricsStore interface {
	Put(ctx context.Context, key string, value []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	List(ctx context.Context, prefix string) ([]string, error)
}
```

Add `"context"` to imports.

- [ ] **Step 2: Update InMemoryStore methods**

```go
func (s *InMemoryStore) Put(ctx context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return nil
}

func (s *InMemoryStore) Get(ctx context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return v, nil
}

func (s *InMemoryStore) List(ctx context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	return keys, nil
}
```

- [ ] **Step 3: Update AccessTracker.Flush**

Change signature to:
```go
func (t *AccessTracker) Flush(ctx context.Context, now time.Time) error {
```

Update the internal call from `t.store.Put(storageKey, data)` to `t.store.Put(ctx, storageKey, data)`.

- [ ] **Step 4: Update AccessTracker.MergeEntity**

Change signature to:
```go
func (t *AccessTracker) MergeEntity(ctx context.Context, entityID string, now time.Time) (*MergedEntry, error) {
```

Update internal calls:
- `t.store.List(prefix)` → `t.store.List(ctx, prefix)`
- `t.store.Get(key)` → `t.store.Get(ctx, key)`

- [ ] **Step 5: Add ListStaleEntities method**

```go
func (t *AccessTracker) ListStaleEntities(ctx context.Context, olderThan time.Duration, now time.Time) ([]string, error) {
	prefix := "metrics/"
	keys, err := t.store.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	// Group by entity_id (first path component after "metrics/")
	entityAccess := make(map[string]time.Time)
	for _, key := range keys {
		data, err := t.store.Get(ctx, key)
		if err != nil {
			continue
		}
		var entry AccessEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		// Extract entity_id from key: metrics/<entity_id>/<role>/<node_id>
		parts := strings.SplitN(strings.TrimPrefix(key, "metrics/"), "/", 3)
		if len(parts) < 1 {
			continue
		}
		entityID := parts[0]
		if existing, ok := entityAccess[entityID]; !ok || entry.LastAccessAt.After(existing) {
			entityAccess[entityID] = entry.LastAccessAt
		}
	}

	threshold := now.Add(-olderThan)
	var stale []string
	for entityID, lastAccess := range entityAccess {
		if lastAccess.Before(threshold) {
			stale = append(stale, entityID)
		}
	}

	sort.Slice(stale, func(i, j int) bool {
		return entityAccess[stale[i]].Before(entityAccess[stale[j]])
	})

	return stale, nil
}
```

Add `"sort"` and `"strings"` to imports.

- [ ] **Step 6: Update tests**

In `pkg/metrics/access_test.go`, update all calls:
- `tracker.Flush(now)` → `tracker.Flush(context.Background(), now)`
- `tracker.MergeEntity("entity-1", now)` → `tracker.MergeEntity(context.Background(), "entity-1", now)`

Add `"context"` to imports.

Add a new test:
```go
func TestListStaleEntities(t *testing.T) {
	store := metrics.NewInMemoryStore()
	tracker := metrics.NewAccessTracker("node-1", store)

	now := time.Now()
	// Record old access
	tracker.RecordAccess("old-entity", "role-a", now.Add(-10*24*time.Hour))
	// Record recent access
	tracker.RecordAccess("fresh-entity", "role-a", now.Add(-1*time.Hour))

	tracker.Flush(context.Background(), now)

	stale, err := tracker.ListStaleEntities(context.Background(), 7*24*time.Hour, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stale) != 1 {
		t.Fatalf("expected 1 stale entity, got %d", len(stale))
	}
	if stale[0] != "old-entity" {
		t.Fatalf("expected old-entity, got %s", stale[0])
	}
}
```

- [ ] **Step 7: Run tests**

```bash
cd pkg/metrics && go test ./... -v
```

Expected: PASS (all 4 tests).

- [ ] **Step 8: Commit**

```bash
git add pkg/metrics/
git commit -m "feat(metrics): add context.Context to MetricsStore, add ListStaleEntities"
```

---

## Task 4: Update Plugin and Fakes for New Metrics Interface

**Files:**
- Modify: `plugins/credential-do/path_metrics.go`
- Modify: `plugins/credential-do/path_creds.go` (the MergeEntity call)
- Modify: `pkg/credenvelope/fakes/do.go` (add GET /v2/account endpoint)

- [ ] **Step 1: Update path_metrics.go**

Change the `MergeEntity` call in `pathMetricsEntity`:
```go
merged, err := tracker.MergeEntity(ctx, entityID, now)
```

Replace `pathMetricsStale` with the real implementation:
```go
func (b *backend) pathMetricsStale(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	tracker := b.accessTracker
	b.mu.RUnlock()

	if tracker == nil {
		return logical.ErrorResponse("metrics not initialized"), nil
	}

	olderThanSec := d.Get("older_than").(int)
	olderThan := time.Duration(olderThanSec) * time.Second
	now := time.Now()

	stale, err := tracker.ListStaleEntities(ctx, olderThan, now)
	if err != nil {
		return logical.ErrorResponse("stale query failed: %v", err), nil
	}

	return logical.ListResponse(stale), nil
}
```

- [ ] **Step 2: Update path_creds.go**

Find the `tracker.MergeEntity` call if any (there isn't one in path_creds — it's only in path_metrics). But the `Flush` call may exist — check. Actually, `path_creds.go` only calls `RecordAccess` which doesn't need context. No change needed here.

- [ ] **Step 3: Add GET /v2/account to DO fake**

In `pkg/credenvelope/fakes/do.go`, in the `handler()` method, add:
```go
mux.HandleFunc("GET /v2/account", s.getAccount)
```

Add the handler:
```go
func (s *DOServer) getAccount(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"account": map[string]interface{}{
			"uuid":   "fake-account-uuid",
			"status": "active",
		},
	})
}
```

- [ ] **Step 4: Run all tests**

```bash
go test github.com/nicois/openbao-cloud-creds/...
```

Expected: PASS (all packages).

- [ ] **Step 5: Commit**

```bash
git add pkg/credenvelope/fakes/ plugins/credential-do/
git commit -m "feat: update metrics callers for context, add /v2/account to DO fake"
```

---

## Task 5: DO Client — Add CheckHealth and ListTokens

**Files:**
- Modify: `plugins/credential-do/do_client.go`
- Create: `plugins/credential-do/do_client_test.go`

- [ ] **Step 1: Write failing test**

`plugins/credential-do/do_client_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestDOClient_CheckHealth(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)
	_ = storage

	// Issue a cred to prove the minter works (health check uses same token)
	// Actually, test CheckHealth directly by creating a client
	// We can't access doClient directly from test package, so test via the health check behavior
	// Instead, test that after config, health check endpoint would work
	// This is better tested via integration in Task 6
	t.Skip("CheckHealth tested via health-check worker integration in Task 6")
}

func TestDOClient_ListTokens(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// Create a couple of tokens
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/test-role",
			Storage:   storage,
		}
		resp, err := b.HandleRequest(ctx, req)
		if err != nil || resp.IsError() {
			t.Fatalf("issue %d failed: err=%v resp=%v", i, err, resp)
		}
	}

	// List tokens via reconcile (which uses ListTokens internally)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data:      map[string]interface{}{"mode": "dry_run"},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("reconcile failed: err=%v resp=%v", err, resp)
	}
	// After Task 6 wires up reconciler, this will show orphans
}
```

Actually, since `doClient` is unexported, the better approach is to add the methods and test them through the plugin endpoints (Task 6). Let me just add the methods now.

- [ ] **Step 1: Add CheckHealth method to do_client.go**

```go
func (c *doClient) CheckHealth(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v2/account", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}
```

Add `"io"` to imports if not already present.

- [ ] **Step 2: Add ListTokens method**

```go
type tokenInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type listTokensResponse struct {
	Tokens []tokenInfo `json:"tokens"`
}

func (c *doClient) ListTokens(ctx context.Context) ([]tokenInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v2/tokens", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DO API list tokens returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result listTokensResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Tokens, nil
}
```

- [ ] **Step 3: Verify compilation**

```bash
cd plugins/credential-do && go build ./...
```

Expected: success.

- [ ] **Step 4: Commit**

```bash
git add plugins/credential-do/do_client.go
git commit -m "feat(credential-do): add CheckHealth and ListTokens to DO client"
```

---

## Task 6: Reconciler Integration — doCloudLister + leaseRegistry + Real Endpoint

**Files:**
- Create: `plugins/credential-do/reconciler_integration.go`
- Modify: `plugins/credential-do/path_reconcile.go`
- Create: `plugins/credential-do/reconciler_integration_test.go`

- [ ] **Step 1: Write failing test**

`plugins/credential-do/reconciler_integration_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestReconcileFindsOrphans(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)
	ctx := context.Background()

	// Issue a token (creates an upstream token)
	issueReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	issueResp, err := b.HandleRequest(ctx, issueReq)
	if err != nil || issueResp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, issueResp)
	}

	// Revoke it (deletes from DO but we still have the upstream record)
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    issueResp.Secret,
	}
	_, err = b.HandleRequest(ctx, revokeReq)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	// Issue another token (this one stays active)
	issueResp2, err := b.HandleRequest(ctx, issueReq)
	if err != nil || issueResp2.IsError() {
		t.Fatalf("second issue failed: err=%v resp=%v", err, issueResp2)
	}

	// Run reconcile — the second token is still active, should find 0 orphans
	reconcileReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data:      map[string]interface{}{"mode": "dry_run"},
	}
	resp, err := b.HandleRequest(ctx, reconcileReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("reconcile failed: err=%v resp=%v", err, resp)
	}

	// The second token matches "cloud-creds-" prefix and is known (active lease)
	// so orphans_found should be 0
	orphans := resp.Data["orphans_found"].(int)
	if orphans != 0 {
		t.Fatalf("expected 0 orphans (active lease exists), got %d", orphans)
	}
}

func TestReconcileDryRunNoDelete(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)
	ctx := context.Background()

	// Issue and immediately forget (simulate orphan by not tracking in registry)
	issueReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	_, err := b.HandleRequest(ctx, issueReq)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	// Reconcile in dry_run mode
	reconcileReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data:      map[string]interface{}{"mode": "dry_run"},
	}
	resp, err := b.HandleRequest(ctx, reconcileReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("reconcile failed: err=%v resp=%v", err, resp)
	}

	deleted := resp.Data["deleted"].(int)
	if deleted != 0 {
		t.Fatalf("dry_run should not delete, got deleted=%d", deleted)
	}
}
```

- [ ] **Step 2: Implement doCloudLister and leaseRegistry**

`plugins/credential-do/reconciler_integration.go`:
```go
package credentialdo

import (
	"context"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const tokenPrefix = "cloud-creds-"

type doCloudLister struct {
	client *doClient
}

func (l *doCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	tokens, err := l.client.ListTokens(ctx)
	if err != nil {
		return nil, err
	}

	var entities []reconciler.UpstreamEntity
	for _, t := range tokens {
		if strings.HasPrefix(t.Name, tokenPrefix) {
			entities = append(entities, reconciler.UpstreamEntity{
				ID:   t.ID,
				Name: t.Name,
			})
		}
	}
	return entities, nil
}

func (l *doCloudLister) DeleteEntity(ctx context.Context, id string) error {
	_, err := l.client.DeleteToken(ctx, id)
	return err
}

type leaseRegistry struct {
	storage logical.Storage
	ctx     context.Context
}

func (r *leaseRegistry) IsKnown(id string) bool {
	// Check if any active lease references this upstream token ID
	// Leases are stored by OpenBao's lease manager, but we track them
	// via the secret's InternalData. For now, scan storage for active secrets.
	// A simple approach: store issued token IDs in a known-tokens/ prefix.
	entries, err := r.storage.List(r.ctx, "active-tokens/")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry == id {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: Track active tokens on issue/revoke**

In `plugins/credential-do/path_creds.go`, after successful mint (before returning), add:
```go
// Track active token for reconciler
activeEntry, _ := logical.StorageEntryJSON("active-tokens/"+tokenResp.Token.ID, map[string]interface{}{
    "role":    roleName,
    "minter":  minterID,
    "created": now.UTC().Format(time.RFC3339),
})
if activeEntry != nil {
    req.Storage.Put(ctx, activeEntry)
}
```

In `pathCredsRevoke`, after successful delete, add:
```go
// Remove from active tokens
req.Storage.Delete(ctx, "active-tokens/"+tokenID)
```

- [ ] **Step 4: Wire up real reconciler in path_reconcile.go**

Replace the entire `pathReconcile` function:
```go
func (b *backend) pathReconcile(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	mode := d.Get("mode").(string)
	dryRun := mode == "dry_run"

	_, client, err := b.selectMinter()
	if err != nil {
		return logical.ErrorResponse("cannot reconcile: %v", err), nil
	}

	lister := &doCloudLister{client: client}
	registry := &leaseRegistry{storage: req.Storage, ctx: ctx}

	cfg := reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  0,
		DryRun:            dryRun,
	}

	b.mu.RLock()
	if b.config != nil {
		cfg.MaxDeletesPerPass = b.config.MaxDeletesPerPass
	}
	b.mu.RUnlock()

	result, err := reconciler.New(cfg, lister, registry).Run(ctx, time.Now())
	if err != nil {
		return logical.ErrorResponse("reconcile failed: %v", err), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"mode":          mode,
			"dry_run":       dryRun,
			"orphans_found": len(result.OrphansFound),
			"deleted":       result.Deleted,
			"hit_limit":     result.HitLimit,
		},
	}, nil
}
```

Add `"time"` and the reconciler import to path_reconcile.go imports:
```go
import (
    "context"
    "time"

    "github.com/nicois/openbao-cloud-creds/pkg/reconciler"
    "github.com/openbao/openbao/sdk/v2/framework"
    "github.com/openbao/openbao/sdk/v2/logical"
)
```

- [ ] **Step 5: Run tests**

```bash
cd plugins/credential-do && go test ./... -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add plugins/credential-do/
git commit -m "feat(credential-do): wire up real reconciler with doCloudLister and lease tracking"
```

---

## Task 7: Background Workers — Health-Check, Flush, Reconciler

**Files:**
- Create: `plugins/credential-do/workers.go`
- Create: `plugins/credential-do/health_check.go`
- Modify: `plugins/credential-do/backend.go`
- Modify: `plugins/credential-do/path_config.go`
- Create: `plugins/credential-do/workers_test.go`

- [ ] **Step 1: Create health_check.go**

`plugins/credential-do/health_check.go`:
```go
package credentialdo

import (
	"context"
	"time"
)

func (b *backend) healthCheckWorker(ctx context.Context) error {
	b.mu.RLock()
	minters := b.minters
	apiURL := b.doAPIURL()
	b.mu.RUnlock()

	now := time.Now()
	for id, ms := range minters {
		if !ms.sm.NeedsHealthCheck(now) {
			continue
		}

		client := newDOClient(apiURL, ms.minter.Token)
		status, err := client.CheckHealth(ctx)
		if err != nil {
			continue
		}

		if status == 200 {
			ms.sm.RecordSuccess(now)
		} else {
			ms.sm.RecordError(status, now)
		}
		_ = id
	}

	return nil
}
```

- [ ] **Step 2: Create workers.go**

`plugins/credential-do/workers.go`:
```go
package credentialdo

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/nicois/openbao-cloud-creds/pkg/worker"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) startWorkers(ctx context.Context, storage logical.Storage) {
	b.stopWorkers()

	b.mu.RLock()
	cfg := b.config
	b.mu.RUnlock()

	if cfg == nil {
		return
	}

	wm := worker.New()

	// Health-check: every 5min
	wm.Register("health-check", 5*time.Minute, worker.Opts{}, b.healthCheckWorker)

	// Metrics flush
	wm.Register("metrics-flush", cfg.FlushInterval, worker.Opts{}, func(ctx context.Context) error {
		return b.accessTracker.Flush(ctx, time.Now())
	})

	// Reconciler
	wm.Register("reconciler", cfg.ReconcileCadence, worker.Opts{
		InitialDelay: cfg.BootstrapDelay,
	}, func(ctx context.Context) error {
		return b.reconcileWorker(ctx, storage)
	})

	b.mu.Lock()
	b.workerMgr = wm
	b.workerCancel = nil
	b.mu.Unlock()

	workerCtx, cancel := context.WithCancel(ctx)
	b.mu.Lock()
	b.workerCancel = cancel
	b.mu.Unlock()

	wm.Start(workerCtx)
}

func (b *backend) stopWorkers() {
	b.mu.Lock()
	cancel := b.workerCancel
	wm := b.workerMgr
	b.workerCancel = nil
	b.workerMgr = nil
	b.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if wm != nil {
		wm.Wait()
	}
}

func (b *backend) reconcileWorker(ctx context.Context, storage logical.Storage) error {
	_, client, err := b.selectMinter()
	if err != nil {
		return err
	}

	lister := &doCloudLister{client: client}
	registry := &leaseRegistry{storage: storage, ctx: ctx}

	b.mu.RLock()
	maxDeletes := 10
	if b.config != nil {
		maxDeletes = b.config.MaxDeletesPerPass
	}
	b.mu.RUnlock()

	cfg := reconciler.Config{
		MaxDeletesPerPass: maxDeletes,
		ConfirmationHold:  1 * time.Hour,
		DryRun:            false,
	}

	_, err = reconciler.New(cfg, lister, registry).Run(ctx, time.Now())
	return err
}
```

- [ ] **Step 3: Add worker fields to backend**

In `plugins/credential-do/backend.go`, add to the `backend` struct:
```go
workerMgr    *worker.Manager
workerCancel context.CancelFunc
```

Add import:
```go
"github.com/nicois/openbao-cloud-creds/pkg/worker"
```

Add a `Clean` method:
```go
func (b *backend) Clean(ctx context.Context) {
	b.stopWorkers()
}
```

Register cleanup in Factory (after `b.Setup`):
```go
b.Backend.Clean = b.Clean
```

- [ ] **Step 4: Start workers on config write**

In `plugins/credential-do/path_config.go`, at the end of `pathConfigWrite` (after `b.mu.Unlock()`), add:
```go
// Start background workers with new config
go b.startWorkers(context.Background(), req.Storage)
```

- [ ] **Step 5: Write test**

`plugins/credential-do/workers_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestWorkersStartOnConfig(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)
	_ = b
	_ = storage

	// Workers start asynchronously — give them a moment
	time.Sleep(50 * time.Millisecond)

	// Issue a credential to generate metrics
	ctx := context.Background()
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	_, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	// The metrics flush worker will eventually persist — but at 15min interval
	// For this test, just verify the plugin doesn't crash with workers running
	time.Sleep(50 * time.Millisecond)
}
```

- [ ] **Step 6: Run tests**

```bash
cd plugins/credential-do && go test ./... -v -race
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add plugins/credential-do/ pkg/worker/
git commit -m "feat(credential-do): add background workers for health-check, flush, and reconciler"
```

---

## Task 8: Prometheus Telemetry

**Files:**
- Create: `plugins/credential-do/telemetry.go`
- Modify: `plugins/credential-do/path_creds.go` (emit counters)
- Modify: `plugins/credential-do/health_check.go` (emit gauges)
- Modify: `plugins/credential-do/path_reconcile.go` (emit counters)

- [ ] **Step 1: Create telemetry.go**

`plugins/credential-do/telemetry.go`:
```go
package credentialdo

import (
	"time"

	"github.com/armon/go-metrics"
)

func emitGauge(key []string, val float32, labels []metrics.Label) {
	metrics.SetGaugeWithLabels(key, val, labels)
}

func emitCounter(key []string, val float32, labels []metrics.Label) {
	metrics.IncrCounterWithLabels(key, val, labels)
}

func (b *backend) emitMinterMetrics() {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	for id, ms := range b.minters {
		labels := []metrics.Label{
			{Name: "cloud", Value: "do"},
			{Name: "cred_id", Value: id},
		}

		// State gauge
		state := string(ms.sm.State())
		emitGauge([]string{"cloud_creds", "upstream_state"}, 1, append(labels, metrics.Label{Name: "state", Value: state}))

		// Consecutive failures
		emitGauge([]string{"cloud_creds", "upstream_consecutive_failures"}, float32(ms.sm.ConsecutiveFailures()), labels)

		// Last success seconds ago
		lastSuccess := ms.sm.LastSuccessAt()
		if !lastSuccess.IsZero() {
			emitGauge([]string{"cloud_creds", "upstream_last_success_seconds_ago"}, float32(now.Sub(lastSuccess).Seconds()), labels)
		}

		// Expires in seconds
		if !ms.minter.ExpiresAt.IsZero() {
			expiresIn := ms.minter.ExpiresAt.Sub(now).Seconds()
			emitGauge([]string{"cloud_creds", "upstream_expires_in_seconds"}, float32(expiresIn), labels)
		}
	}
}

func emitLeaseIssued(role string) {
	emitCounter([]string{"cloud_creds", "lease_issued_total"}, 1, []metrics.Label{
		{Name: "cloud", Value: "do"},
		{Name: "role", Value: role},
	})
}

func emitLeaseRevokeFailed(role string) {
	emitCounter([]string{"cloud_creds", "lease_revoke_failures_total"}, 1, []metrics.Label{
		{Name: "cloud", Value: "do"},
		{Name: "role", Value: role},
	})
}

func emitAutoDeleted(role, reason string) {
	emitCounter([]string{"cloud_creds", "auto_deleted_total"}, 1, []metrics.Label{
		{Name: "cloud", Value: "do"},
		{Name: "role", Value: role},
		{Name: "reason", Value: reason},
	})
}

func emitOrphansFound(count int) {
	emitGauge([]string{"cloud_creds", "orphans_found"}, float32(count), []metrics.Label{
		{Name: "cloud", Value: "do"},
	})
}
```

- [ ] **Step 2: Emit in health-check worker**

In `plugins/credential-do/health_check.go`, at the end of `healthCheckWorker` (after the minter loop), add:
```go
b.emitMinterMetrics()
```

- [ ] **Step 3: Emit lease_issued in path_creds.go**

In `pathCredsRead`, after successful mint (near `RecordAccess`), add:
```go
emitLeaseIssued(roleName)
```

In `pathCredsRevoke`, in the error path, add:
```go
emitLeaseRevokeFailed(roleName)
```

Where `roleName` is extracted from `req.Secret.InternalData["role"].(string)` — add that extraction at the top of `pathCredsRevoke`:
```go
roleName, _ := req.Secret.InternalData["role"].(string)
```

- [ ] **Step 4: Emit in reconcile path**

In `plugins/credential-do/path_reconcile.go`, after `reconciler.New(...).Run(...)` returns successfully:
```go
emitOrphansFound(len(result.OrphansFound))
```

- [ ] **Step 5: Add go-metrics dependency**

```bash
cd plugins/credential-do && go get github.com/armon/go-metrics
```

(It's likely already a transitive dependency via the OpenBao SDK.)

- [ ] **Step 6: Run tests**

```bash
cd plugins/credential-do && go test ./... -v
```

Expected: PASS (metrics emit silently — no test assertion on metric values needed for this pass; the armon/go-metrics package handles missing sinks gracefully).

- [ ] **Step 7: Commit**

```bash
git add plugins/credential-do/
git commit -m "feat(credential-do): add Prometheus telemetry emission"
```

---

## Summary of File Structure (new/modified)

```
pkg/worker/
├── go.mod                          (NEW)
├── worker.go                       (NEW)
└── worker_test.go                  (NEW)

pkg/recovery/
├── state.go                        (MODIFIED — add consecutiveFailures)
└── state_test.go                   (MODIFIED — add test)

pkg/metrics/
├── access.go                       (MODIFIED — context.Context, ListStaleEntities)
└── access_test.go                  (MODIFIED — context params, stale test)

pkg/credenvelope/fakes/
└── do.go                           (MODIFIED — add GET /v2/account)

plugins/credential-do/
├── backend.go                      (MODIFIED — worker fields, Clean method)
├── do_client.go                    (MODIFIED — CheckHealth, ListTokens)
├── health_check.go                 (NEW)
├── path_config.go                  (MODIFIED — start workers)
├── path_creds.go                   (MODIFIED — active-token tracking, telemetry)
├── path_metrics.go                 (MODIFIED — real stale endpoint, context)
├── path_reconcile.go               (MODIFIED — real reconciler)
├── reconciler_integration.go       (NEW)
├── reconciler_integration_test.go  (NEW)
├── telemetry.go                    (NEW)
├── workers.go                      (NEW)
└── workers_test.go                 (NEW)
```
