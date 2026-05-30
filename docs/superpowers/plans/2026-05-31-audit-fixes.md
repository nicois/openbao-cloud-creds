# Audit Fixes (batch 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the four verified correctness/security defects from the 2026-05-31 audit: metrics double-count (#2), stale-entity mis-parse (#3), unused error_code contract (#1), and the untested reconciler delete-safety boundary (#4).

**Architecture:** #2/#3 are single-site fixes in the shared `pkg/metrics/access.go` (URL-escape key segments; skip the local node's own storage key when merging). #1 adds a narrow `credenvelope.ErrorResponse(code, msg, …)` helper carrying a machine-readable `error_code`, then converts each plugin's credential-issuance error sites. #4 adds a per-plugin reconciler safety test. No broad de-duplication (audit #7) in this batch.

**Tech Stack:** Go 1.26.1, OpenBao SDK v2.5.1, golangci-lint v2. Reference spec: `docs/superpowers/specs/2026-05-31-audit-fixes-design.md`; audit: `docs/audit-2026-05-31.md`.

**Verified SDK fact:** `logical.ErrorResponse(text)` returns `&logical.Response{Data: {"error": text}}` — so a helper that returns `&logical.Response{Data: {"error": msg, "error_code": code}}` carries both fields to the client.

---

## Task 1: pkg/metrics — fix #2 (double-count) and #3 (key-segment escaping)

Both bugs are in `pkg/metrics/access.go`. Fix together since both touch the storage-key build/parse and the test setup overlaps.

**Files:**
- Modify: `pkg/metrics/access.go`
- Modify: `pkg/metrics/access_test.go`

- [ ] **Step 1: Write the failing tests (both bugs)**

Add to `pkg/metrics/access_test.go`:
```go
func TestMergeEntity_NoDoubleCountOnLocalNode(t *testing.T) {
	store := metrics.NewInMemoryStore()
	tr := metrics.NewAccessTracker("node-1", store)
	now := time.Now()

	tr.RecordAccess("set-a/minter-1", "role-x", now)
	tr.RecordAccess("set-a/minter-1", "role-x", now.Add(time.Minute))
	if err := tr.Flush(context.Background(), now.Add(2*time.Minute)); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Same tracker (the node that issued) serves the query. Must report 2, not 4.
	merged, err := tr.MergeEntity(context.Background(), "set-a/minter-1", now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if merged.AccessCount != 2 {
		t.Fatalf("double-count: expected 2, got %d", merged.AccessCount)
	}
}

func TestListStaleEntities_EntityIDWithSlash(t *testing.T) {
	store := metrics.NewInMemoryStore()
	tr := metrics.NewAccessTracker("node-1", store)
	now := time.Now()

	// Two minters in the same set: one stale, one fresh.
	tr.RecordAccess("set-a/minter-old", "role-x", now.Add(-10*24*time.Hour))
	tr.RecordAccess("set-a/minter-new", "role-x", now.Add(-1*time.Hour))
	if err := tr.Flush(context.Background(), now); err != nil {
		t.Fatalf("flush: %v", err)
	}

	stale, err := tr.ListStaleEntities(context.Background(), 7*24*time.Hour, now)
	if err != nil {
		t.Fatalf("stale: %v", err)
	}
	// Must bucket per set/minter, returning ONLY the old minter — not the set.
	if len(stale) != 1 {
		t.Fatalf("expected 1 stale entity, got %d: %v", len(stale), stale)
	}
	if stale[0] != "set-a/minter-old" {
		t.Fatalf("expected set-a/minter-old, got %q", stale[0])
	}
}
```

- [ ] **Step 2: Run to confirm both fail**

```bash
cd pkg/metrics && go test ./... -run 'TestMergeEntity_NoDoubleCount|TestListStaleEntities_EntityIDWithSlash' -v 2>&1 | tail -20
```
Expected: `TestMergeEntity_NoDoubleCountOnLocalNode` FAILS with count 4 (double). `TestListStaleEntities_EntityIDWithSlash` FAILS — returns `set-a` (parsed `parts[0]`), not `set-a/minter-old`.

- [ ] **Step 3: Add the `net/url` import**

In `pkg/metrics/access.go`, add `"net/url"` to the import block (alongside `encoding/json`, `fmt`, `sort`, `strings`, `sync`, `time`, `context`).

- [ ] **Step 4: Escape segments in Flush (key build)**

In `Flush`, change the storage key line (currently `storageKey := fmt.Sprintf("metrics/%s/%s/%s", k.EntityID, k.Role, t.nodeID)`) to:
```go
		storageKey := fmt.Sprintf("metrics/%s/%s/%s",
			url.PathEscape(k.EntityID), url.PathEscape(k.Role), url.PathEscape(t.nodeID))
```

- [ ] **Step 5: Escape the prefix + skip the local node key in MergeEntity**

In `MergeEntity`, change the prefix line (currently `prefix := fmt.Sprintf("metrics/%s/", entityID)`) to escape the entity:
```go
	prefix := fmt.Sprintf("metrics/%s/", url.PathEscape(entityID))
	localSuffix := "/" + url.PathEscape(t.nodeID)
```
Then in the loop over storage `keys`, skip this node's own key so its contribution is counted only once (from in-memory entries below):
```go
	for _, key := range keys {
		// Skip this node's own flushed key: its accesses are counted from the
		// live in-memory map below, so summing the storage copy too would
		// double-count on any node that both issued and serves this query.
		if strings.HasSuffix(key, localSuffix) {
			continue
		}
		data, err := t.store.Get(ctx, key)
		// ... unchanged ...
	}
```
Leave the existing in-memory merge block (the `for k, entry := range t.entries` loop) as-is.

Add a comment near that block noting the eviction edge case:
```go
	// Local accesses are merged from memory (above-skipped storage key avoids
	// double counting). If a local entry was evicted after flush (lease ended),
	// this node contributes nothing here — correct: no active lease references it.
```

- [ ] **Step 6: Unescape on parse in ListStaleEntities**

In `ListStaleEntities`, the parse currently does `parts := strings.SplitN(strings.TrimPrefix(key, "metrics/"), "/", 3)` then `entityID := parts[0]`. Replace with:
```go
		parts := strings.SplitN(strings.TrimPrefix(key, "metrics/"), "/", 3)
		if len(parts) < 1 {
			continue
		}
		entityID, err := url.PathUnescape(parts[0])
		if err != nil {
			continue
		}
```
(The `entityID` is then used in the existing `entityAccess[entityID]` logic unchanged.)

- [ ] **Step 7: Run the new tests — now pass**

```bash
cd pkg/metrics && go test ./... -run 'TestMergeEntity_NoDoubleCount|TestListStaleEntities_EntityIDWithSlash' -v 2>&1 | tail -20
```
Expected: both PASS.

- [ ] **Step 8: Run the whole metrics package (no regressions)**

```bash
cd pkg/metrics && go test ./... -race 2>&1 | tail -5
```
Expected: PASS (existing TestRecordAccess/TestFlushAndLoad/TestMergeMultipleNodes/TestListStaleEntities still green — note the pre-existing TestMergeMultipleNodes uses slash-free IDs and distinct querying nodes, so it stays valid).

- [ ] **Step 9: gofmt + lint**

```bash
cd pkg/metrics && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...
```
Expected: 0 issues.

- [ ] **Step 10: Commit**

```bash
git add pkg/metrics/
git commit -m "fix(metrics): escape key segments and stop local-node double-count (audit #2, #3)"
```

---

## Task 2: pkg/credenvelope — add the error_code-carrying ErrorResponse helper (#1 part A)

**Files:**
- Modify: `pkg/credenvelope/errors.go`
- Modify: `pkg/credenvelope/envelope_test.go` (or a new `errors_test.go`)
- Modify: `pkg/credenvelope/go.mod` (add the OpenBao SDK dependency)

- [ ] **Step 1: Add the SDK dependency to pkg/credenvelope**

`pkg/credenvelope` does not currently import the OpenBao SDK. The helper needs `logical.Response`.
```bash
cd pkg/credenvelope && go get github.com/openbao/openbao/sdk/v2@v2.5.1
```

- [ ] **Step 2: Write the failing test**

Add to `pkg/credenvelope/errors_test.go` (new file):
```go
package credenvelope_test

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
)

func TestErrorResponseCarriesCode(t *testing.T) {
	resp := credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", "snapshot-rw")
	if resp == nil {
		t.Fatal("nil response")
	}
	if !resp.IsError() {
		t.Fatal("expected IsError() true")
	}
	if resp.Data["error_code"] != string(credenvelope.ErrRoleNotFound) {
		t.Fatalf("expected error_code=%q, got %v", credenvelope.ErrRoleNotFound, resp.Data["error_code"])
	}
	if resp.Data["error"] != `role "snapshot-rw" does not exist` {
		t.Fatalf("unexpected error text: %v", resp.Data["error"])
	}
}
```

- [ ] **Step 3: Run to confirm it fails**

```bash
cd pkg/credenvelope && go test ./... -run TestErrorResponseCarriesCode -v 2>&1 | tail
```
Expected: FAIL (undefined `credenvelope.ErrorResponse`).

- [ ] **Step 4: Implement the helper**

Add to `pkg/credenvelope/errors.go` (add imports `"fmt"` if not present and `"github.com/openbao/openbao/sdk/v2/logical"`):
```go
import (
	"fmt"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// ErrorResponse builds a logical error response that carries a stable,
// machine-readable error_code in its Data alongside the human-readable message.
// Clients pin to metadata.api_version and may switch on error_code.
func ErrorResponse(code ErrorCode, msg string, args ...interface{}) *logical.Response {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"error":      msg,
			"error_code": string(code),
		},
	}
}
```
Keep the existing `PluginError`/`NewError` (still valid for in-process error values); this adds the response-rendering path. (`*logical.Response` with `Data["error"]` set is what `logical.ErrorResponse` itself returns, so `IsError()` is true.)

- [ ] **Step 5: Run the test — now passes**

```bash
cd pkg/credenvelope && go test ./... -v 2>&1 | tail -15
```
Expected: PASS (including the existing envelope tests).

- [ ] **Step 6: gofmt + lint + commit**

```bash
cd pkg/credenvelope && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...
git add pkg/credenvelope/
git commit -m "feat(credenvelope): add ErrorResponse helper carrying stable error_code (audit #1)"
```

---

## Task 3: credential-do — convert error sites to error_code (#1 part B, reference)

This task converts DO's credential-issuance error sites to the new helper, establishing the pattern the other 9 plugins copy.

**Files:**
- Modify: `plugins/credential-do/path_creds.go`
- Modify: `plugins/credential-do/path_creds_test.go`

- [ ] **Step 1: Write the failing test**

Add to `plugins/credential-do/path_creds_test.go`:
```go
func TestCredsIssue_RoleNotFound_HasErrorCode(t *testing.T) {
	b, storage := getTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/nope", Storage: storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response")
	}
	if resp.Data["error_code"] != "role_not_found" {
		t.Fatalf("expected error_code=role_not_found, got %v", resp.Data["error_code"])
	}
}
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cd plugins/credential-do && go test ./... -run TestCredsIssue_RoleNotFound_HasErrorCode -v 2>&1 | tail
```
Expected: FAIL (`error_code` is nil — current code uses `logical.ErrorResponse("role_not_found: ...")` which only sets `error`).

- [ ] **Step 3: Convert the error sites in path_creds.go**

In `plugins/credential-do/path_creds.go`, add the import `"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"` (already imported for the envelope — confirm). Replace the credential-issuance error responses:
- role missing: `return logical.ErrorResponse("role_not_found: role %q does not exist", roleName), nil` → `return credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", roleName), nil`
- role disabled: `return logical.ErrorResponse("role_disabled: role %q is disabled", roleName), nil` → `return credenvelope.ErrorResponse(credenvelope.ErrRoleDisabled, "role %q is disabled", roleName), nil`
- minter selection failure: where `selectMinter` returns an error and the handler does `return logical.ErrorResponse(err.Error()), nil` (the "all minters failing" path) → `return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "%s", err.Error()), nil`
- upstream mint error: the `return logical.ErrorResponse("upstream error: %v", err), nil` path → `return credenvelope.ErrorResponse(credenvelope.ErrUpstreamTimeout, "upstream error: %v", err), nil` if it's a timeout-class failure, else `ErrInternal`. Use `ErrUpstreamAuthFailed` only for auth; for a generic mint failure use `ErrInternal`. (Read the surrounding code: if the mint path can't distinguish status, map generic upstream failure to `ErrInternal` and leave a comment; do NOT invent codes.)

Read `path_creds.go` and convert only the sites where a documented code in `errors.go` clearly applies. Leave `fmt.Errorf` returns that are true internal errors (e.g. missing `upstream_token_id` in revoke) as-is, or wrap with `ErrInternal` if they produce a client response.

- [ ] **Step 4: Run the new + existing tests**

```bash
cd plugins/credential-do && go test ./... -race 2>&1 | tail -10
```
Expected: PASS. Note: the existing `TestCredsIssue_RoleNotFound` asserts `resp.IsError()`, which stays true with the new helper, so it still passes.

- [ ] **Step 5: gofmt + lint + commit**

```bash
cd plugins/credential-do && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...
git add plugins/credential-do/
git commit -m "fix(credential-do): emit stable error_code on credential errors (audit #1)"
```

---

## Tasks 4–12: convert error sites in the other 9 plugins (#1 part B)

Each task applies Task 3's conversion to one plugin: read its `path_creds.go`, convert the credential-issuance error sites to `credenvelope.ErrorResponse(<code>, ...)`, add the `error_code` assertion test, run + lint + commit. Use the committed `plugins/credential-do/path_creds.go` as the pattern.

For each plugin (`credential-upcloud`, `credential-exoscale`, `credential-aws`, `credential-gcp`, `credential-ovh`, `credential-azure`, `credential-vultr`, `credential-akamai`, `credential-oci`):

1. In `path_creds.go`, ensure `credenvelope` is imported; convert each error site to the matching code:
   - role missing → `ErrRoleNotFound`
   - role disabled (if the plugin has a disabled flag) → `ErrRoleDisabled`
   - all minters / set failing (`selectMinter` error) → `ErrUpstreamAuthFailed`
   - upstream mint failure → `ErrInternal` (or `ErrUpstreamTimeout`/`ErrUpstreamQuotaExceeded` only if the code distinguishes the status; don't invent)
   - OCI only: slot/pool unavailable on read → `ErrPoolExhausted`
2. Add a `TestCredsIssue_RoleNotFound_HasErrorCode` (or the closest issuable error for that plugin — e.g. for OCI which reads a slot, assert the role-not-found path) asserting `resp.Data["error_code"]` equals the expected code.
3. `cd plugins/credential-<cloud> && gofmt -w . && go test ./... -race` (PASS) and `golangci-lint run ./...` (0 issues).
4. Commit `fix(credential-<cloud>): emit stable error_code on credential errors (audit #1)`.

Task numbers: 4=upcloud, 5=exoscale, 6=aws, 7=gcp, 8=ovh, 9=azure, 10=vultr, 11=akamai, 12=oci.

Per-plugin note: AWS/GCP/OVH/OCI have no-op/soft revoke — their issuance error sites still apply (role lookup, minter selection, upstream mint). OCI's issuance reads a slot rather than minting; map "no slot available" to `ErrPoolExhausted` and "role not found" to `ErrRoleNotFound`.

---

## Task 13: reconciler delete-safety boundary tests (#4)

Add a test per plugin with a cloud lister proving foreign (non-`cloud-creds-`-prefixed) entities are never returned for deletion. Also add a `pkg/reconciler` guard test.

**Files:**
- Modify: `pkg/reconciler/reconciler_test.go`
- Create/Modify: `plugins/credential-<cloud>/reconciler_integration_test.go` for the 6 hard-revoke plugins (do, upcloud, exoscale, azure, vultr, akamai) — these have `reconciler_integration.go` with a `doCloudLister`/equivalent.

- [ ] **Step 1: pkg/reconciler — assert Run never deletes an unknown-but-also-untracked entity beyond what the lister returns**

The reconciler already only deletes what the lister returns and the registry says is unknown. Add a test pinning that an entity the lister does NOT return is never passed to `DeleteEntity`, and that `IsKnown` entities are skipped. Add to `pkg/reconciler/reconciler_test.go`:
```go
func TestRun_OnlyDeletesListedOrphans(t *testing.T) {
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		{ID: "orphan-1", Name: "cloud-creds-role-a-1"},
		{ID: "known-1", Name: "cloud-creds-role-a-2"},
	}}
	reg := &fakeRegistry{known: map[string]bool{"known-1": true}}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10}, cloud, reg)
	res, err := r.Run(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// known-1 must survive; only orphan-1 deleted.
	if len(cloud.entities) != 1 || cloud.entities[0].ID != "known-1" {
		t.Fatalf("known entity was deleted or orphan survived: %v", cloud.entities)
	}
	if res.Deleted != 1 {
		t.Fatalf("expected 1 delete, got %d", res.Deleted)
	}
}
```

- [ ] **Step 2: Run it**

```bash
cd pkg/reconciler && go test ./... -run TestRun_OnlyDeletesListedOrphans -v 2>&1 | tail
```
Expected: PASS (this confirms the reconciler core respects known/listed; it's a regression guard, not a bug fix).

- [ ] **Step 3: Per-plugin — assert the cloud lister filters by owner-tag prefix**

For each of the 6 plugins with `reconciler_integration.go`, add a test that the `doCloudLister` (or equivalent type name in that plugin) returns ONLY `cloud-creds-`-prefixed entities when the underlying fake holds a mix. DO worked example — add `plugins/credential-do/reconciler_integration_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestReconciler_OnlyTaggedEntitiesConsidered(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL)

	// Issue one plugin-owned token (named cloud-creds-...).
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Inject a foreign token directly into the fake (not cloud-creds- prefixed).
	srv.AddForeignToken("user-personal-token", "my-laptop")

	// Dry-run reconcile must report only the orphaned cloud-creds- token (if any),
	// and must NEVER count/delete the foreign token.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: storage,
		Data: map[string]interface{}{"mode": "dry_run"},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("reconcile: err=%v resp=%v", err, resp)
	}
	// The foreign token must still exist in the fake afterward (never deleted).
	if !srv.HasToken("user-personal-token") {
		t.Fatal("reconciler deleted a foreign (non-owned) token — safety boundary breached")
	}
}
```
This requires two small test-only fake helpers on `DOServer`: `AddForeignToken(id, name string)` (insert a token with an arbitrary non-prefixed name) and `HasToken(id string) bool`. Add them to `pkg/credenvelope/fakes/do.go` (test-support, like `ProvisionedCount`). For the other 5 plugins, add the equivalent helpers to their fakes and a parallel test using that plugin's foreign-entity shape (user/client/key).

NOTE: if a plugin's reconcile worker (not the dry-run endpoint) is the only place the lister runs, drive the test through the dry-run reconcile endpoint as above — it exercises the same `doCloudLister`. Confirm dry-run actually lists (it should, to report orphans_found).

- [ ] **Step 4: Run each plugin's safety test**

```bash
for p in do upcloud exoscale azure vultr akamai; do
  echo "== $p =="; (cd plugins/credential-$p && go test ./... -run TestReconciler_OnlyTagged -v 2>&1 | tail -3)
done
```
Expected: all PASS (the prefix filter already exists; these tests pin it).

- [ ] **Step 5: gofmt + lint + commit**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
for p in do upcloud exoscale azure vultr akamai; do (cd plugins/credential-$p && gofmt -w . && golangci-lint run ./... >/dev/null && echo "$p ok"); done
(cd pkg/reconciler && gofmt -w . && golangci-lint run ./...)
git add pkg/reconciler/ pkg/credenvelope/fakes/ plugins/credential-do plugins/credential-upcloud plugins/credential-exoscale plugins/credential-azure plugins/credential-vultr plugins/credential-akamai
git commit -m "test: pin reconciler owner-tag delete-safety boundary (audit #4)"
```

---

## Task 14: full verification + audit doc update

**Files:**
- Modify: `docs/audit-2026-05-31.md`

- [ ] **Step 1: Whole-workspace race test**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds
go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | grep -E "^(ok|FAIL)"
```
Expected: all packages `ok`.

- [ ] **Step 2: Lint + smoke**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
make lint
make smoke-test
```
Expected: 0 lint issues; all 10 plugins register.

- [ ] **Step 3: Mark #1–4 resolved in the audit doc**

In `docs/audit-2026-05-31.md`, prefix the headings of items 1, 2, 3, 4 with `[RESOLVED 2026-05-31]` and add a one-line resolution under each pointing at the commit/test (e.g. for #2/#3 → `pkg/metrics/access.go` + the two new tests; #1 → `credenvelope.ErrorResponse` + per-plugin tests; #4 → the reconciler safety tests). Leave #5–10 as open.

- [ ] **Step 4: Commit**

```bash
git add docs/audit-2026-05-31.md
git commit -m "docs: mark audit items #1-4 resolved"
```

---

## Summary of files

```
pkg/metrics/access.go            (#2 skip-local-key, #3 url-escape segments) + access_test.go
pkg/credenvelope/errors.go       (#1 ErrorResponse helper) + errors_test.go + go.mod (SDK dep)
pkg/reconciler/reconciler_test.go (#4 core guard test)
pkg/credenvelope/fakes/<cloud>.go (#4 AddForeignToken/HasToken helpers — 6 hard-revoke fakes)
plugins/credential-<cloud>/
├── path_creds.go                (#1 error_code conversion — all 10)
├── path_creds_test.go           (#1 error_code assertion — all 10)
└── reconciler_integration_test.go (#4 owner-tag safety test — 6 hard-revoke plugins)
docs/audit-2026-05-31.md         (mark #1-4 resolved)
```
