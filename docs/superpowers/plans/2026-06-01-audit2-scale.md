# Audit-2 Effort 3: Scale (#1, #3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make per-node metrics persist in `logical.Storage` (so the documented cross-node merge design actually works) and make the reconciler's known-lease lookup O(N) and fail-closed.

**Architecture:** Two independent scale fixes sharing `pkg/` substrate. #1 adds a `logical.Storage`-backed `MetricsStore` (with a *recursive, full-key* `List` matching the existing interface contract) plus a node-local `ResolveNodeID()`, wired into all 10 plugin backends. #3 changes the shared `reconciler.Registry` interface from per-entity `IsKnown(id) bool` to a once-per-pass `KnownIDs(ctx) (map[string]struct{}, error)` (fail-closed on error), implemented by the 6 hard-revoke plugins.

**Tech Stack:** Go 1.26.1 workspace; OpenBao SDK v2.5.1 (`logical.Storage`, `logical.StorageEntry`, `logical.InmemStorage`); golangci-lint v2.12.2.

**Spec:** `docs/superpowers/specs/2026-06-01-audit2-scale-design.md`

**CRITICAL EXECUTION CONSTRAINTS (these bit prior efforts):**
- Work ONLY in the effort's worktree. Prefix every bash call with `cd <worktree> && ...` and READ each file (absolute worktree path) immediately before editing it — subagent bash cwd resets between calls and stray edits have repeatedly landed in the main checkout.
- ZERO new `//nolint`. Restructure instead. If an internal test introduces a repeated string literal that trips `goconst` package-wide, hoist it to a `const`.
- Lint MUST use the v2 binary at `/home/claude-aiven-2/code/qualcheck/bin/golangci-lint` (the `golangci-lint` on PATH is v1.64.8 and fails on the v2 config). Run `<v2> cache clean` before linting to avoid stale cross-worktree cache artifacts.
- Use the full module path for go commands: `github.com/nicois/openbao-cloud-creds/...` (NOT `./...`, which doesn't resolve across the workspace).
- After each task, verify the main checkout is clean: `git -C /home/claude-aiven-2/code/openbao-cloud-creds status --short | grep -v '.claude'` returns nothing.

---

## File Structure

**#1 metrics:**
- `pkg/metrics/go.mod` — add `github.com/openbao/openbao/sdk/v2 v2.5.1` (currently SDK-free; copy the require/indirect block from `pkg/localexpiry/go.mod`).
- `pkg/metrics/storage_store.go` (create) — `StorageBackedStore` over `logical.Storage`; recursive full-key `List`.
- `pkg/metrics/nodeid.go` (create) — `ResolveNodeID()` + the env-var const + fallback const.
- `pkg/metrics/storage_store_test.go` (create) — round-trip, recursion contract, missing-key parity, end-to-end consumer parity.
- `pkg/metrics/nodeid_test.go` (create) — env→hostname precedence.
- `plugins/credential-<p>/backend.go` (×10) — swap `NewInMemoryStore()`+`"local"` for `NewStorageBackedStore(conf.StorageView)`+`ResolveNodeID()`.

**#3 reconciler:**
- `pkg/reconciler/reconciler.go` — `Registry` interface + `Run` (call once, fail-closed).
- `pkg/reconciler/reconciler_test.go` — adapt `fakeRegistry`; add once-call + fail-closed tests.
- `plugins/credential-<p>/reconciler_integration.go` (×6: do, akamai, azure, exoscale, upcloud, vultr) — `IsKnown`→`KnownIDs`.
- `plugins/credential-<p>/workers.go` + `path_reconcile.go` (×6) — drop the captured `ctx` from `leaseRegistry{}` construction.

---

## Task 1: `pkg/metrics` — add SDK dependency + `ResolveNodeID`

**Files:**
- Modify: `pkg/metrics/go.mod`
- Create: `pkg/metrics/nodeid.go`
- Create: `pkg/metrics/nodeid_test.go`

- [ ] **Step 1: Add the SDK dependency to `pkg/metrics/go.mod`**

Replace the contents of `pkg/metrics/go.mod` with the module line plus the full require block copied verbatim from `pkg/localexpiry/go.mod` (same SDK version v2.5.1 and identical indirect set), changing only the module path:

```
module github.com/nicois/openbao-cloud-creds/pkg/metrics

go 1.26.1

require (
	github.com/hashicorp/go-hclog v1.6.3
	github.com/openbao/openbao/sdk/v2 v2.5.1
)
```
(plus the entire `require ( ... // indirect )` block from `pkg/localexpiry/go.mod` — copy it exactly). Note: `go-hclog` is in localexpiry's direct block; if `go mod tidy` later demotes it to indirect because metrics doesn't use it, that's fine — run tidy in Step 4.

- [ ] **Step 2: Write the failing test** `pkg/metrics/nodeid_test.go`

```go
package metrics_test

import (
	"os"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
)

func TestResolveNodeID_EnvWins(t *testing.T) {
	t.Setenv("OPENBAO_CLOUD_CREDS_NODE_ID", "node-42")
	if got := metrics.ResolveNodeID(); got != "node-42" {
		t.Fatalf("env override: got %q, want node-42", got)
	}
}

func TestResolveNodeID_FallsBackToHostname(t *testing.T) {
	t.Setenv("OPENBAO_CLOUD_CREDS_NODE_ID", "")
	host, _ := os.Hostname()
	got := metrics.ResolveNodeID()
	// On any normal machine Hostname() is non-empty, so ResolveNodeID must
	// return it. (The empty-hostname path falls through to the documented
	// "unknown-node" constant; it cannot be forced in-process.)
	if host != "" && got != host {
		t.Fatalf("hostname fallback: got %q, want %q", got, host)
	}
	if got == "" {
		t.Fatal("ResolveNodeID must never return empty")
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/pkg/metrics/ -run TestResolveNodeID 2>&1 | tail`
Expected: FAIL — `undefined: metrics.ResolveNodeID`.

- [ ] **Step 4: Implement** `pkg/metrics/nodeid.go`

```go
package metrics

import "os"

// nodeIDEnvVar is the node-local override for this node's metrics ID. It must
// be node-local (per-process), NOT a persisted config field: PluginConfig is
// stored in logical.Storage, which raft replicates across nodes — a persisted
// override would make every node share one ID and collapse the per-node
// keyspace the cross-node merge depends on.
const nodeIDEnvVar = "OPENBAO_CLOUD_CREDS_NODE_ID"

// unknownNodeID is the last-resort fallback when neither the env override nor
// the OS hostname is available.
const unknownNodeID = "unknown-node"

// ResolveNodeID returns this node's stable, node-local metrics ID:
// $OPENBAO_CLOUD_CREDS_NODE_ID, else os.Hostname(), else "unknown-node".
func ResolveNodeID() string {
	if id := os.Getenv(nodeIDEnvVar); id != "" {
		return id
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return unknownNodeID
}
```

Then run: `cd <worktree> && (cd pkg/metrics && go mod tidy)` to resolve the new dependency.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/pkg/metrics/ -run TestResolveNodeID 2>&1 | tail`
Expected: PASS (ok).

- [ ] **Step 6: Commit**

```bash
cd <worktree>
git add pkg/metrics/go.mod pkg/metrics/go.sum pkg/metrics/nodeid.go pkg/metrics/nodeid_test.go
git commit -m "$(printf 'feat(metrics): node-local ResolveNodeID + SDK dep (audit2 #1)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2: `pkg/metrics` — `StorageBackedStore` with recursive full-key `List`

**Files:**
- Create: `pkg/metrics/storage_store.go`
- Create: `pkg/metrics/storage_store_test.go`

This is the load-bearing task. The existing `MetricsStore` consumers (`MergeEntity`, `ListStaleEntities` in `access.go`) pass `List` results straight into `Get` and parse them as **full keys** (`strings.HasSuffix(key, "/"+nodeID)`, `SplitN(TrimPrefix(key,"metrics/"),"/",3)`). But `logical.Storage.List` returns *relative immediate children* (nested levels appear as `"child/"`). So `StorageBackedStore.List` MUST recurse and return full keys to satisfy the contract `InMemoryStore` already meets.

- [ ] **Step 1: Write the failing test** `pkg/metrics/storage_store_test.go`

```go
package metrics_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestStorageBackedStore_PutGetRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := metrics.NewStorageBackedStore(&logical.InmemStorage{})
	if err := s.Put(ctx, "metrics/e/r/node", []byte("hello")); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.Get(ctx, "metrics/e/r/node")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want hello", got)
	}
}

func TestStorageBackedStore_GetMissingReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	s := metrics.NewStorageBackedStore(&logical.InmemStorage{})
	if _, err := s.Get(ctx, "metrics/absent/r/node"); err == nil {
		t.Fatal("expected not-found error for absent key, got nil")
	}
}

// The contract test: List must return FULL recursive keys, matching what
// InMemoryStore returns and what MergeEntity/ListStaleEntities consume. A
// naive delegate that returns logical.Storage's relative children would
// return ["e/"] here and break every consumer.
func TestStorageBackedStore_ListReturnsFullRecursiveKeys(t *testing.T) {
	ctx := context.Background()
	s := metrics.NewStorageBackedStore(&logical.InmemStorage{})
	put := func(k string) {
		if err := s.Put(ctx, k, []byte("x")); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
	}
	put("metrics/entityA/roleX/node1")
	put("metrics/entityA/roleX/node2")
	put("metrics/entityA/roleY/node1")
	put("metrics/entityB/roleZ/node1")

	got, err := s.List(ctx, "metrics/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{
		"metrics/entityA/roleX/node1",
		"metrics/entityA/roleX/node2",
		"metrics/entityA/roleY/node1",
		"metrics/entityB/roleZ/node1",
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %d keys %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key %d: got %q want %q", i, got[i], want[i])
		}
	}
}

// End-to-end: the real consumers (Flush + ListStaleEntities) must work through
// StorageBackedStore exactly as they do through InMemoryStore.
func TestStorageBackedStore_ConsumerParity(t *testing.T) {
	ctx := context.Background()
	s := metrics.NewStorageBackedStore(&logical.InmemStorage{})
	tr := metrics.NewAccessTracker("node1", s)

	old := time.Now().Add(-48 * time.Hour)
	tr.RecordAccess("set/minter-old", "role-a", old)
	if err := tr.Flush(ctx, old); err != nil {
		t.Fatalf("flush: %v", err)
	}

	stale, err := tr.ListStaleEntities(ctx, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("list stale: %v", err)
	}
	found := false
	for _, e := range stale {
		if e == "set/minter-old" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected set/minter-old in stale list, got %v", stale)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/pkg/metrics/ -run TestStorageBackedStore 2>&1 | tail`
Expected: FAIL — `undefined: metrics.NewStorageBackedStore`.

- [ ] **Step 3: Implement** `pkg/metrics/storage_store.go`

```go
package metrics

import (
	"context"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// StorageBackedStore implements MetricsStore over a logical.Storage view, so
// flushed access metrics persist across reloads and (because the keyspace is
// raft-replicated) merge across nodes via the per-node key suffix.
type StorageBackedStore struct {
	storage logical.Storage
}

func NewStorageBackedStore(storage logical.Storage) *StorageBackedStore {
	return &StorageBackedStore{storage: storage}
}

func (s *StorageBackedStore) Put(ctx context.Context, key string, value []byte) error {
	return s.storage.Put(ctx, &logical.StorageEntry{Key: key, Value: value})
}

func (s *StorageBackedStore) Get(ctx context.Context, key string) ([]byte, error) {
	entry, err := s.storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		// Match InMemoryStore.Get so consumers see an identical contract.
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return entry.Value, nil
}

// List returns the full keys under prefix. logical.Storage.List returns only
// the relative immediate children (a nested level appears as "child/"), so we
// recurse and re-prepend the prefix, yielding the flat full-key list the
// MetricsStore consumers (MergeEntity / ListStaleEntities) require.
func (s *StorageBackedStore) List(ctx context.Context, prefix string) ([]string, error) {
	children, err := s.storage.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, child := range children {
		full := prefix + child
		if strings.HasSuffix(child, "/") {
			sub, err := s.List(ctx, full)
			if err != nil {
				return nil, err
			}
			keys = append(keys, sub...)
			continue
		}
		keys = append(keys, full)
	}
	return keys, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/pkg/metrics/ 2>&1 | tail`
Expected: PASS — all `TestStorageBackedStore*`, `TestResolveNodeID*`, and the pre-existing `access_test.go` tests (proving the consumers stay store-agnostic).

- [ ] **Step 5: Lint**

```bash
cd <worktree>
/home/claude-aiven-2/code/qualcheck/bin/golangci-lint cache clean
(cd pkg/metrics && gofmt -w . && /home/claude-aiven-2/code/qualcheck/bin/golangci-lint run ./... 2>&1 | tail -4); echo "exit ${PIPESTATUS[0]}"
```
Expected: 0 issues.

- [ ] **Step 6: Commit**

```bash
cd <worktree>
git add pkg/metrics/storage_store.go pkg/metrics/storage_store_test.go pkg/metrics/go.sum
git commit -m "$(printf 'feat(metrics): StorageBackedStore with recursive full-key List (audit2 #1)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 3: Wire all 10 plugin backends to the storage-backed store + real nodeID

**Files (Modify, all ×10):**
- `plugins/credential-do/backend.go:73-74`
- `plugins/credential-aws/backend.go:78-79`
- `plugins/credential-gcp/backend.go:77-78`
- `plugins/credential-azure/backend.go:76-77`
- `plugins/credential-ovh/backend.go:79-80`
- `plugins/credential-upcloud/backend.go:74-75`
- `plugins/credential-exoscale/backend.go:73-74`
- `plugins/credential-vultr/backend.go:73-74`
- `plugins/credential-akamai/backend.go:74-75`
- `plugins/credential-oci/backend.go:100-101`

Every plugin has the identical two lines:
```go
store := metrics.NewInMemoryStore()
b.accessTracker = metrics.NewAccessTracker("local", store)
```
In every case `conf.StorageView` is referenced a few lines below, so it is in scope here.

- [ ] **Step 1: For each of the 10 plugins, READ the backend.go around the construction site, then Edit**

Replace those two lines with:
```go
store := metrics.NewStorageBackedStore(conf.StorageView)
b.accessTracker = metrics.NewAccessTracker(metrics.ResolveNodeID(), store)
```

Note on `conf.StorageView` being nil: the existing code already guards `if conf.StorageView != nil` for config/minter loading, but the tracker line runs unconditionally. `NewStorageBackedStore(nil)` would store a nil `logical.Storage` and panic on first `Flush`. In practice OpenBao always supplies `conf.StorageView` (the existing unconditional `metrics.NewAccessTracker` already assumes the tracker is usable). To stay safe and behavior-equivalent, guard it:
```go
var store metrics.MetricsStore = metrics.NewInMemoryStore()
if conf.StorageView != nil {
	store = metrics.NewStorageBackedStore(conf.StorageView)
}
b.accessTracker = metrics.NewAccessTracker(metrics.ResolveNodeID(), store)
```
Use this guarded form in all 10 plugins. (Keeps the in-memory fallback only for the nil-storage edge — e.g. some unit tests construct a backend without a StorageView.)

- [ ] **Step 2: Build all 10 plugins**

Run: `cd <worktree> && go build github.com/nicois/openbao-cloud-creds/... 2>&1 | tail`
Expected: exit 0, no output.

- [ ] **Step 3: Run the full plugin test suite**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/plugins/... 2>&1 | grep -E 'FAIL|^ok ' | tail -12`
Expected: all `ok`. (Existing resilience/reload tests now exercise the storage-backed store — they should pass; if any test constructed a backend with a nil StorageView and relied on the tracker, the guarded fallback keeps it green.)

- [ ] **Step 4: Lint all 10 plugins**

```bash
cd <worktree>
GL=/home/claude-aiven-2/code/qualcheck/bin/golangci-lint
"$GL" cache clean
for p in do aws gcp azure ovh upcloud exoscale vultr akamai oci; do
  (cd plugins/credential-$p && gofmt -w . && "$GL" run ./... 2>&1 | tail -3) && echo "0 issues: $p" || echo "ISSUES: $p"
done
```
Expected: 0 issues for every plugin. (`NewInMemoryStore` still appears in backend.go as the guarded nil-storage fallback — that is expected and correct; the assertion is that `NewStorageBackedStore(conf.StorageView)` is the live path.)

- [ ] **Step 5: Commit**

```bash
cd <worktree>
git add plugins/credential-*/backend.go
git commit -m "$(printf 'feat(metrics): wire all 10 backends to StorageBackedStore + ResolveNodeID (audit2 #1)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 4: `pkg/reconciler` — `Registry.KnownIDs` + once-per-pass, fail-closed `Run`

**Files:**
- Modify: `pkg/reconciler/reconciler.go` (interface at `:34-36`, `Run` at `:78-121`)
- Modify: `pkg/reconciler/reconciler_test.go` (`fakeRegistry` at `:42-48`; add two tests)

- [ ] **Step 1: Adapt `fakeRegistry` and write the failing tests** in `pkg/reconciler/reconciler_test.go`

Replace the existing `fakeRegistry` (lines 42-48):
```go
type fakeRegistry struct {
	known map[string]bool
}

func (f *fakeRegistry) IsKnown(id string) bool {
	return f.known[id]
}
```
with a `KnownIDs`-based fake that also counts calls and can inject an error:
```go
type fakeRegistry struct {
	known     map[string]bool
	callCount int
	err       error
}

func (f *fakeRegistry) KnownIDs(_ context.Context) (map[string]struct{}, error) {
	f.callCount++
	if f.err != nil {
		return nil, f.err
	}
	set := make(map[string]struct{}, len(f.known))
	for id := range f.known {
		set[id] = struct{}{}
	}
	return set, nil
}
```
(The existing tests construct `&fakeRegistry{known: map[string]bool{...}}`, which still compiles unchanged.)

Add two new tests at the end of the file:
```go
func TestRun_CallsKnownIDsExactlyOnce(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "a", Name: "cloud-creds-r-1"},
			{ID: "b", Name: "cloud-creds-r-2"},
			{ID: "c", Name: "cloud-creds-r-3"},
		},
	}
	reg := &fakeRegistry{known: map[string]bool{"a": true}}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10}, cloud, reg)
	if _, err := r.Run(context.Background(), time.Now()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg.callCount != 1 {
		t.Fatalf("KnownIDs called %d times, want exactly 1 (O(N), not O(N^2))", reg.callCount)
	}
}

func TestRun_KnownIDsErrorIsFailClosed(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "orphan-1", Name: "cloud-creds-r-1"},
		},
	}
	reg := &fakeRegistry{err: errors.New("storage unreachable")}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10}, cloud, reg)
	res, err := r.Run(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected Run to return the KnownIDs error (fail-closed), got nil")
	}
	if res != nil && res.Deleted != 0 {
		t.Fatalf("fail-closed must delete nothing, deleted %d", res.Deleted)
	}
	// fakeCloudLister.DeleteEntity removes the entity from its slice, so a
	// fail-closed pass must leave orphan-1 present (it was never deleted).
	if len(cloud.entities) != 1 {
		t.Fatalf("fail-closed must not delete; entities now %v", cloud.entities)
	}
}
```
Add `"errors"` to the test file's imports if not present (the file already imports `context`, `time`, `testing`, `fmt`, and `reconciler`). `fakeCloudLister` has NO delete counter — do NOT add one; assert via `res.Deleted` and the surviving `cloud.entities` slice as shown (its `DeleteEntity` mutates that slice).

- [ ] **Step 2: Run to verify failure**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/pkg/reconciler/ 2>&1 | tail`
Expected: compile error — `*fakeRegistry does not implement reconciler.Registry (missing method IsKnown)` / `Registry` mismatch, OR the new tests fail. (The interface still declares `IsKnown`.)

- [ ] **Step 3: Implement the interface + `Run` change** in `pkg/reconciler/reconciler.go`

Replace the `Registry` interface (lines 34-36):
```go
type Registry interface {
	IsKnown(id string) bool
}
```
with:
```go
// Registry enumerates the lease IDs this node knows about. Run calls KnownIDs
// once per pass and membership-checks in memory (O(N), not a List-per-entity
// O(N^2) scan). Returning an error aborts the pass WITHOUT deleting anything:
// an incomplete known-set could misclassify a live credential as an orphan, so
// the safe response to "cannot enumerate known leases" is to delete nothing.
type Registry interface {
	KnownIDs(ctx context.Context) (map[string]struct{}, error)
}
```

In `Run`, replace the per-entity check. Insert after `result := &Result{}` (line 84) a single call, and change the loop guard:
```go
	result := &Result{}

	known, err := r.registry.KnownIDs(ctx)
	if err != nil {
		// Fail closed: without a complete known-set we cannot safely decide
		// what is an orphan, so abort the pass rather than risk deleting a
		// live credential.
		return nil, err
	}

	for _, entity := range entities {
		if _, ok := known[entity.ID]; ok {
			continue
		}
		// ... (rest of loop unchanged: confirmation-hold guard, OrphansFound,
		// DryRun, MaxDeletesPerPass, DeleteEntity)
	}
```
Keep everything else in `Run` exactly as-is. Note the function already has a named-or-local `err` from `r.cloud.ListTaggedEntities(ctx)` at line 79 (`entities, err := ...`); reuse that `err` variable for `KnownIDs` (`known, err := ...` becomes `known, err = ...` if `err` is already declared — use `:=` only if introducing `known` requires it; since `known` is new, `known, err := r.registry.KnownIDs(ctx)` shadows correctly only if `err` isn't needed afterward — simplest is `known, kerr := r.registry.KnownIDs(ctx); if kerr != nil { return nil, kerr }`). Use a distinct `kerr` to avoid shadow-lint issues.

- [ ] **Step 4: Run to verify pass**

Run: `cd <worktree> && go test github.com/nicois/openbao-cloud-creds/pkg/reconciler/ 2>&1 | tail`
Expected: all PASS, including the two new tests and all pre-existing reconciler tests (unchanged behavior for the success path).

- [ ] **Step 5: Lint**

```bash
cd <worktree>
GL=/home/claude-aiven-2/code/qualcheck/bin/golangci-lint
"$GL" cache clean
(cd pkg/reconciler && gofmt -w . && "$GL" run ./... 2>&1 | tail -4); echo "exit ${PIPESTATUS[0]}"
```
Expected: 0 issues.

- [ ] **Step 6: Commit**

```bash
cd <worktree>
git add pkg/reconciler/reconciler.go pkg/reconciler/reconciler_test.go
git commit -m "$(printf 'refactor(reconciler): KnownIDs once-per-pass, fail-closed (audit2 #3)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 5: Update the 6 hard-revoke plugins' `leaseRegistry` to `KnownIDs`

**Files (Modify, ×6):**
- `plugins/credential-do/reconciler_integration.go` (`leaseRegistry` at `:45-61`, prefix `active-tokens/`)
- `plugins/credential-akamai/reconciler_integration.go` (prefix `active-clients/`)
- `plugins/credential-azure/reconciler_integration.go` (prefix `active-tokens/`)
- `plugins/credential-exoscale/reconciler_integration.go` (prefix `active-tokens/`)
- `plugins/credential-upcloud/reconciler_integration.go` (prefix `active-tokens/`)
- `plugins/credential-vultr/reconciler_integration.go` (prefix `active-users/`)
- Plus per plugin: `workers.go` + `path_reconcile.go` construction sites (drop the captured `ctx`).

AWS/GCP/OVH (no-revoke) and OCI (phased) have NO `leaseRegistry` — confirm with `grep -rln 'leaseRegistry' plugins/credential-<p>/` before assuming; do not touch them.

- [ ] **Step 1 (per plugin): READ the plugin's `reconciler_integration.go`, then replace the `leaseRegistry` type + `IsKnown`**

Current (DO; identical shape elsewhere, only the prefix differs):
```go
type leaseRegistry struct {
	storage logical.Storage
	ctx     context.Context
}

func (r *leaseRegistry) IsKnown(id string) bool {
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
Replace with (use the plugin's own active-prefix in place of `active-tokens/`):
```go
type leaseRegistry struct {
	storage logical.Storage
}

func (r *leaseRegistry) KnownIDs(ctx context.Context) (map[string]struct{}, error) {
	entries, err := r.storage.List(ctx, "active-tokens/")
	if err != nil {
		return nil, err
	}
	known := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		known[entry] = struct{}{}
	}
	return known, nil
}
```
The `ctx` field is removed from the struct. If `context` is now an unused import in this file, remove it; if it's still used (e.g. by the lister), keep it.

- [ ] **Step 2 (per plugin): Update the two construction sites** in `workers.go` and `path_reconcile.go`

Current (DO `workers.go:90`):
```go
registry := &leaseRegistry{storage: storage, ctx: ctx}
```
Current (DO `path_reconcile.go:53`):
```go
registry := &leaseRegistry{storage: req.Storage, ctx: ctx}
```
Drop the `ctx:` field in both:
```go
registry := &leaseRegistry{storage: storage}      // workers.go
registry := &leaseRegistry{storage: req.Storage}  // path_reconcile.go
```
(The `ctx` is now passed to `KnownIDs` by `Run`, which receives it as a call argument — the registry no longer captures one.)

- [ ] **Step 3: Build + test all 6 plugins after each (or batch, then verify all)**

Run: `cd <worktree> && go build github.com/nicois/openbao-cloud-creds/... && go test github.com/nicois/openbao-cloud-creds/plugins/... 2>&1 | grep -E 'FAIL|^ok ' | tail -12`
Expected: build exit 0; all `ok`. Watch for the 6 plugins' `created_at_test.go` (akamai/do/azure/upcloud have one) — these test the reconciler integration and may construct a `leaseRegistry` or call `IsKnown` directly. READ each `created_at_test.go`; if it references `IsKnown` or `leaseRegistry{...ctx...}`, update it to the new API (call `KnownIDs(ctx)` and assert on the returned map / error). Report any such test updated.

- [ ] **Step 4: Lint the 6 plugins**

```bash
cd <worktree>
GL=/home/claude-aiven-2/code/qualcheck/bin/golangci-lint
"$GL" cache clean
for p in do akamai azure exoscale upcloud vultr; do
  (cd plugins/credential-$p && gofmt -w . && "$GL" run ./... 2>&1 | tail -3) && echo "0 issues: $p" || echo "ISSUES: $p"
done
```
Expected: 0 issues each.

- [ ] **Step 5: Commit**

```bash
cd <worktree>
git add plugins/credential-do/ plugins/credential-akamai/ plugins/credential-azure/ plugins/credential-exoscale/ plugins/credential-upcloud/ plugins/credential-vultr/
git commit -m "$(printf 'refactor(reconciler): 6 plugins implement KnownIDs (audit2 #3)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 6: Full-workspace verification + mark resolved

**Files:**
- Modify: `docs/audit-2026-06-01.md` (mark #1 and #3 RESOLVED)

- [ ] **Step 1: Full build + race test + lint + smoke**

```bash
cd <worktree>
echo "=== build ===" && go build github.com/nicois/openbao-cloud-creds/... && echo "build OK"
echo "=== race ===" && go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | grep -E 'FAIL|^ok ' | tail -22
GL=/home/claude-aiven-2/code/qualcheck/bin/golangci-lint
"$GL" cache clean
fail=0
for d in pkg/cloudconfig pkg/credenvelope pkg/credenvelope/fakes pkg/localexpiry pkg/metrics pkg/metricspath pkg/plugintest pkg/reconciler pkg/recovery pkg/telemetry pkg/worker plugins/credential-akamai plugins/credential-aws plugins/credential-azure plugins/credential-do plugins/credential-exoscale plugins/credential-gcp plugins/credential-oci plugins/credential-ovh plugins/credential-upcloud plugins/credential-vultr; do
  (cd "$d" && "$GL" run ./... >/dev/null 2>&1) && echo "0: $d" || { echo "ISSUES: $d"; fail=1; }
done
echo "lint overall: $([ $fail -eq 0 ] && echo CLEAN || echo ISSUES)"
echo "=== nolint added this effort ===" && git diff main..HEAD | grep -cE '^\+.*nolint'
echo "=== smoke ===" && make smoke-test 2>&1 | tail -4
```
Expected: build OK; all `ok` (race); lint CLEAN for all 20 modules; nolint count 0; smoke 10/10.

- [ ] **Step 2: Mark #1 and #3 resolved** in `docs/audit-2026-06-01.md`

Add a `— [RESOLVED 2026-06-01]` tag to the `## 1.` and `## 3.` headings and a bold **Resolved:** note under each, mirroring the style used for #2/#4/#5/#6/#8/#10. For #1:
> **Resolved:** Added `metrics.StorageBackedStore` (a `logical.Storage`-backed `MetricsStore` with a recursive full-key `List`) and `metrics.ResolveNodeID()` (node-local: `$OPENBAO_CLOUD_CREDS_NODE_ID` → hostname → `unknown-node`, never a replicated config field). All 10 backends now construct the access tracker with the storage-backed store + real nodeID, so flushed metrics persist across reloads and merge across nodes per the documented design. The reclamation-safety risk is foreclosed (the substrate is now real); an actual GC-by-staleness job remains a separate future feature.

For #3:
> **Resolved:** `reconciler.Registry` changed from per-entity `IsKnown(id) bool` to `KnownIDs(ctx) (map[string]struct{}, error)`, called once per `Run` (O(N), not O(N²)); the 6 hard-revoke plugins implement it with a single `storage.List`. A `KnownIDs` error now aborts the pass with zero deletes (fail-closed), fixing the prior fail-open-on-List-error behavior. Tests: `TestRun_CallsKnownIDsExactlyOnce`, `TestRun_KnownIDsErrorIsFailClosed`.

- [ ] **Step 3: Verify main checkout clean, then commit**

```bash
cd <worktree>
git -C /home/claude-aiven-2/code/openbao-cloud-creds status --short | grep -v '.claude' && echo "MAIN DIRTY" || echo "main clean"
git add docs/audit-2026-06-01.md
git commit -m "$(printf 'docs(audit2): mark #1/#3 resolved (Effort 3)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Self-review notes (for the executor)

- **Spec coverage:** Task 1 (ResolveNodeID + SDK dep), Task 2 (StorageBackedStore + recursion contract), Task 3 (wire 10 backends) cover #1. Task 4 (interface + Run fail-closed) and Task 5 (6 plugin impls) cover #3. Task 6 is the full gate + doc.
- **Type consistency:** `NewStorageBackedStore(logical.Storage) *StorageBackedStore`, `ResolveNodeID() string`, `MetricsStore` (existing), `Registry.KnownIDs(context.Context) (map[string]struct{}, error)`, `leaseRegistry{storage}` (no `ctx`). Used identically across tasks.
- **Known hazard:** the `created_at_test.go` files (akamai/do/azure/upcloud) and any `reconciler_integration` test may reference the old `IsKnown`/`ctx` field — Task 5 Step 3 explicitly says to read and update them. Do not skip that.
- **Nil-storage guard:** Task 3 uses the guarded fallback so backends built without a StorageView (some unit tests) don't panic; this is why `NewInMemoryStore` legitimately remains in backend.go.