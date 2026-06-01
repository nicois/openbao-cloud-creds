# Audit-2 Effort 1: Small Verified Bugs (#2, #6, #10) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three verified bugs — Akamai EdgeGrid body-hash signing (+ signature-validating fake), OCI overdue-slot TTL=0, and worker-goroutine leak on backend teardown (all 10 plugins) — each TDD, behavior-preserving except the fix.

**Architecture:** Three independent fixes. #2 buffers+hashes the real request body and upgrades the Akamai fake to recompute/validate the EG1-HMAC-SHA256 signature (proving correctness). #6 makes OCI skip overdue slots rather than serve a TTL=0 lease. #10 wires `framework.Backend.Clean` → worker teardown and derives the worker context from a backend base context, across all 10 plugins.

**Tech Stack:** Go 1.26.1 workspace, OpenBao SDK v2 (`framework`/`logical`), golangci-lint v2.12.2.

**Reference spec:** `docs/superpowers/specs/2026-06-01-audit2-small-bugs-design.md`

---

## How to work this plan

- **Worktree:** all work on one branch (created by the execution skill). Never touch the parent checkout. Confirm `git branch --show-current` before each commit. Commit messages end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. **Edit ONLY worktree files** (relative go.work — parent edits silently don't take effect).
- **Build/test:** `go build github.com/nicois/openbao-cloud-creds/...` ; `go test -race github.com/nicois/openbao-cloud-creds/...`
- **Per-module lint:** `export PATH="$(go env GOPATH)/bin:$PATH"; (cd <module> && golangci-lint run ./...)`
- **No new `//nolint`** (project record). If lint forces a choice, restructure.
- Trust live code over plan line numbers; read before editing.

---

## Task 1: Akamai — sign the real request body (#2 part 1)

**Files:**
- Modify: `plugins/credential-akamai/edgegrid.go`
- Test: `plugins/credential-akamai/edgegrid_test.go` (create if absent)

- [ ] **Step 1: Write the failing unit test**

The signing is currently `bodyHash = hashBody(nil)` for POST/PUT. A correct signature must hash the real body. Create/append `plugins/credential-akamai/edgegrid_test.go`:
```go
package credentialakamai

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"testing"
)

// TestSignRequest_HashesBody proves the EdgeGrid signature covers the actual
// POST body (not the empty-body hash). It recomputes the expected body hash and
// asserts the canonical request the signer used contains it — i.e. a non-empty
// body changes the signature.
func TestSignRequest_HashesBody(t *testing.T) {
	cred := &edgeGridCredential{ClientToken: "ct", AccessToken: "at", ClientSecret: "cs"}
	body := []byte(`{"clientName":"cloud-creds-x"}`)

	req, _ := http.NewRequest(http.MethodPost, "https://h.example/x", bytes.NewReader(body))
	sigWithBody := signAndExtract(t, cred, req)

	reqEmpty, _ := http.NewRequest(http.MethodPost, "https://h.example/x", http.NoBody)
	sigEmpty := signAndExtract(t, cred, reqEmpty)

	if sigWithBody == sigEmpty {
		t.Fatal("signature must differ when the body is non-empty (body hash not included)")
	}

	// And the body must remain readable after signing (restored for the real send).
	got, _ := io.ReadAll(req.Body)
	if !bytes.Equal(got, body) {
		t.Fatalf("body not restored after signing: got %q", got)
	}

	// Sanity: expected body hash is sha256→base64 of the body.
	want := base64.StdEncoding.EncodeToString(func() []byte { s := sha256.Sum256(body); return s[:] }())
	_ = want // hashBody(body) must equal this; exercised indirectly via the differing signature
	_ = hmac.New // keep import set stable if signAndExtract changes
}

// signAndExtract signs req and returns the signature= value from the header.
func signAndExtract(t *testing.T, cred *edgeGridCredential, req *http.Request) string {
	t.Helper()
	signRequest(req, cred) // current signature — adjust if signRequest takes more args
	auth := req.Header.Get("Authorization")
	const marker = "signature="
	i := bytesIndex(auth, marker)
	if i < 0 {
		t.Fatalf("no signature in %q", auth)
	}
	return auth[i+len(marker):]
}

func bytesIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```
IMPORTANT: read the real `signRequest` signature first (`grep -n 'func signRequest' plugins/credential-akamai/edgegrid.go`) and adjust the call. The test is `package credentialakamai` (internal) so it can call the unexported `signRequest`/`edgeGridCredential`/`hashBody`.

- [ ] **Step 2: Run, confirm fail**

```bash
cd <WT>
go test -run TestSignRequest_HashesBody github.com/nicois/openbao-cloud-creds/plugins/credential-akamai/ -v 2>&1 | tail -15
```
Expected: FAIL — current code uses `hashBody(nil)`, so the body-bearing and empty-body signatures are identical.

- [ ] **Step 3: Implement — buffer + hash the real body**

In `plugins/credential-akamai/edgegrid.go`, add a const near the top:
```go
// maxBodyHashBytes is EdgeGrid's documented cap on the bytes hashed for the
// request-body portion of the signature.
const maxBodyHashBytes = 131072
```
Add imports `"bytes"` and `"io"` if absent. Replace the body-hash block (currently `bodyHash = hashBody(nil) // empty for simplicity`):
```go
	bodyHash := ""
	if req.Body != nil && (req.Method == http.MethodPost || req.Method == http.MethodPut) {
		buf, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(buf)) // restore for the real send
			hashInput := buf
			if len(hashInput) > maxBodyHashBytes {
				hashInput = hashInput[:maxBodyHashBytes]
			}
			bodyHash = hashBody(hashInput)
		}
	}
```
(Use `http.MethodPost`/`http.MethodPut` rather than the string literals — usestdlibvars. The existing code may use `"POST"`; switch it.)

- [ ] **Step 4: Run, confirm pass**

```bash
cd <WT>
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-akamai/... 2>&1 | tail -12
```
Expected: TestSignRequest_HashesBody passes; all existing akamai tests pass.

- [ ] **Step 5: lint + commit**

```bash
cd <WT>
(cd plugins/credential-akamai && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add plugins/credential-akamai/
git commit -m "$(printf 'fix(akamai): sign the real request body in EdgeGrid auth (audit2 #2)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2: Akamai fake validates the EG1-HMAC-SHA256 signature (#2 part 2)

This is the load-bearing verification: prove the plugin's signing is correct end-to-end by having the fake recompute and check it.

**Files:**
- Modify: `pkg/credenvelope/fakes/akamai.go`
- Test: `pkg/credenvelope/fakes/akamai_test.go` (or the akamai plugin integration test)

Context (read first): the fake already parses `client_token` from the `EG1-HMAC-SHA256` Authorization header (`checkEdgeGridAuth`/`parseClientToken`, akamai.go ~124-165). The Authorization header carries `client_token`, `access_token`, `timestamp`, `nonce`, and `signature=` — but NOT the client_secret (the secret is only used to compute the signature). So the fake must be told the expected secret out-of-band.

- [ ] **Step 1: read the fake's auth handling + the EG1 header fields the plugin sends**

```bash
cd <WT>
sed -n '124,200p' pkg/credenvelope/fakes/akamai.go
sed -n '/func signRequest/,/^}/p' plugins/credential-akamai/edgegrid.go   # exact authData layout: client_token;access_token;timestamp;nonce; and the canonical-request format
```
Note the EXACT `authData` string format and canonical-request format the plugin builds, because the fake must reconstruct the identical `dataToSign = authData + canonicalRequest` and `signingKey = HMAC(client_secret, timestamp)`.

- [ ] **Step 2: add a credential registry + signature validation to the fake**

Add to `AkamaiServer`:
```go
// expectedSecrets maps client_token -> client_secret so the fake can recompute
// and validate the EG1-HMAC-SHA256 signature. Populated via RegisterCredential.
expectedSecrets map[string]string
```
Initialize the map in `NewAkamaiServer`. Add:
```go
// RegisterCredential tells the fake the client_secret to expect for a given
// client_token, so it can validate the EdgeGrid signature on requests signed
// with that token. Tests call this with the same triple they configure as the
// plugin's minter.
func (s *AkamaiServer) RegisterCredential(clientToken, clientSecret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expectedSecrets[clientToken] = clientSecret
}
```
In `checkEdgeGridAuth`, after extracting the client_token, if a secret is registered for it, recompute the signature from the request (method, scheme, host, path+query, the SAME empty signed-headers, and the body hash of the actual received body) using the registered secret + the timestamp from the header, and 401 if it doesn't match the presented `signature=`. Mirror the plugin's `signRequest` algorithm EXACTLY (extract `timestamp`/`nonce`/`access_token` from the header too, since `authData` includes them). If no secret is registered for the token (back-compat for tests that don't register), skip validation (preserve existing behavior).

**Implementation note:** factor the canonical-request + signing into a small shared-able helper if it keeps the fake readable, but the fake is test code in `package fakes` — it can't import the plugin's unexported `signRequest`. Reimplement the algorithm in the fake (that's the point — an independent recomputation). Keep it minimal.

- [ ] **Step 3: write the test that proves validation works**

In `pkg/credenvelope/fakes/akamai_test.go`:
```go
// A request signed with the correct secret is accepted; a wrong signature 401s.
func TestAkamaiFake_ValidatesSignature(t *testing.T) {
	srv := NewAkamaiServer()
	defer srv.Close()
	srv.RegisterCredential("ct-test", "cs-test")

	// Build a request and sign it with the SAME algorithm the plugin uses —
	// simplest: drive it through the real plugin client in an akamai plugin
	// test instead (see Step 4). Here, assert the negative: an unsigned/bad
	// request to createClient is rejected.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/identity-management/v3/api-clients?createCredential=true", strings.NewReader(`{"clientName":"x"}`))
	req.Header.Set("Authorization", "EG1-HMAC-SHA256 client_token=ct-test;access_token=at;timestamp=20260101T00:00:00+0000;nonce=n;signature=WRONG")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad signature, got %d", resp.StatusCode)
	}
}
```

- [ ] **Step 4: the end-to-end proof — register the test minter's secret and confirm the existing mint still passes**

In the akamai plugin's `setupConfiguredBackend` (test helper, `plugins/credential-akamai/*_test.go`), after creating the fake, register the configured minter's triple secret:
```go
srv.RegisterCredential("ct-test", "cs-test")
```
(the minter token is `ct-test:at-test:cs-test`). Now `TestFullLifecycle`/`integration_test.go` (which mints via the real plugin client) passes ONLY because Task 1 made the body hash correct — if Task 1 were reverted, the fake would 401. This is the red-then-green at the integration level. Run:
```bash
cd <WT>
go test -race github.com/nicois/openbao-cloud-creds/pkg/credenvelope/... github.com/nicois/openbao-cloud-creds/plugins/credential-akamai/... 2>&1 | tail -15
```
Expected: all pass. (To self-verify the guard: temporarily revert Task 1's body-hash change and confirm the akamai integration test now 401s; then restore. Optional but recommended — note it in the report.)

- [ ] **Step 5: lint + commit**

```bash
cd <WT>
export PATH="$(go env GOPATH)/bin:$PATH"
(cd pkg/credenvelope && gofmt -w . && golangci-lint run ./...)
(cd plugins/credential-akamai && gofmt -w . && golangci-lint run ./...)
git add pkg/credenvelope/ plugins/credential-akamai/
git commit -m "$(printf 'test(akamai): fake validates EG1-HMAC-SHA256 signature (audit2 #2)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 3: OCI skips overdue slots instead of serving TTL=0 (#6)

**Files:**
- Modify: `plugins/credential-oci/slots.go` (or `path_creds.go`)
- Test: `plugins/credential-oci/path_creds_test.go` (or wherever OCI creds reads are tested)

Context (verified): `path_creds.go:73-77` floors a lagging slot's TTL to 0 and still serves it. `freshestSlot` (slots.go) filters only `State == slotActive`. Slots are phase-staggered (slots.go:119,131), so the freshest slot is normally not the overdue one; skipping overdue is safe and only yields `pool_exhausted` when every slot has lapsed.

- [ ] **Step 1: write the failing tests**

The OCI concurrency test already shows the overdue-slot setup pattern (`concurrency_test.go:78-85`: load slot, set `NextRotationAt` into the past, `saveSlot`). Reuse it. Add to the OCI creds test file:
```go
// An overdue slot is not served as a TTL=0 lease; with no other active slot,
// the read returns pool_exhausted.
func TestCredsRead_OverdueSlotNotServed(t *testing.T) {
	b, storage := setupConfiguredBackend(t)   // provisions slots for test-role
	// Force ALL slots overdue.
	role := loadTestRole(t, storage)          // helper: read roles/test-role
	for i := 0; i < role.SlotCount; i++ {
		s, _ := loadSlot(context.Background(), storage, "test-role", i)
		s.NextRotationAt = time.Now().Add(-time.Hour)
		_ = saveSlot(context.Background(), storage, "test-role", s)
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected pool_exhausted error response, got %v", resp)
	}
	// (Optionally assert the error_code prefix is ErrPoolExhausted.)
}

// With one overdue + one fresh slot, the fresh slot is served with a positive TTL.
func TestCredsRead_FreshSlotServedWhenAnotherOverdue(t *testing.T) {
	b, storage := setupConfiguredBackend(t)
	// Force slot 0 overdue, leave slot 1 fresh (NextRotationAt in the future).
	s0, _ := loadSlot(context.Background(), storage, "test-role", 0)
	s0.NextRotationAt = time.Now().Add(-time.Hour)
	_ = saveSlot(context.Background(), storage, "test-role", s0)
	s1, _ := loadSlot(context.Background(), storage, "test-role", 1)
	s1.NextRotationAt = time.Now().Add(time.Hour)
	s1.RotatedAt = time.Now() // make slot 1 the freshest
	_ = saveSlot(context.Background(), storage, "test-role", s1)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("expected a served credential, got %v", resp)
	}
	if resp.Secret == nil || resp.Secret.TTL <= 0 {
		t.Fatalf("expected positive TTL, got %v", resp.Secret)
	}
}
```
Adapt to the real setup: read how the OCI `_test` package builds a configured backend with provisioned slots (it has `getTestBackend`/a `setupConfiguredBackend`; the concurrency test's internal `newInternalConfiguredBackend` shows the slot/role wiring). Use the real `loadSlot`/`saveSlot`/role-load helpers. If `SlotCount` default is 2, the two-slot test is valid.

- [ ] **Step 2: run, confirm fail**

```bash
cd <WT>
go test -run 'TestCredsRead_OverdueSlotNotServed|TestCredsRead_FreshSlotServedWhenAnotherOverdue' github.com/nicois/openbao-cloud-creds/plugins/credential-oci/ -v 2>&1 | tail -20
```
Expected: `OverdueSlotNotServed` FAILS (current code serves the overdue slot with TTL=0, not an error). `FreshSlotServedWhenAnotherOverdue` likely passes already (freshest = slot 1) — keep it as a guard that the fix doesn't over-skip.

- [ ] **Step 3: implement — skip overdue slots**

In `slots.go`, change `freshestSlot` to take `now` and exclude overdue active slots:
```go
func freshestSlot(slots []*slot, now time.Time) *slot {
	var best *slot
	for _, s := range slots {
		if s.State != slotActive {
			continue
		}
		if !s.NextRotationAt.After(now) {
			continue // overdue: not eligible to serve (TTL would be <= 0)
		}
		if best == nil || s.RotatedAt.After(best.RotatedAt) {
			best = s
		}
	}
	return best
}
```
Update all callers of `freshestSlot` to pass `now` (grep `freshestSlot(` — the creds read path; pass the `now := time.Now()` it already computes). In `path_creds.go`, remove the now-dead `if ttlSeconds < 0 { ttlSeconds = 0 }` branch (a served slot now always has `NextRotationAt` in the future, so `ttlSeconds > 0`). Keep the existing `default_ttl` cap. The `best == nil → ErrPoolExhausted` path already exists and now also covers the all-overdue case.

NOTE on other freshestSlot callers: if `freshestSlot` is used elsewhere (e.g. a metrics/status path) where overdue-skipping would change behavior, check each caller — but the spec's intent (never serve an overdue slot) is correct for the read path. Report any caller where skip-overdue is wrong.

- [ ] **Step 4: run, confirm green**

```bash
cd <WT>
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-oci/... 2>&1 | tail -15
```
Expected: both new tests pass; all existing OCI tests pass (incl rotation/reconcile/resilience — confirm skip-overdue didn't break the concurrency test that sets a slot overdue; that test asserts a rotation/reconcile race, not a creds read, so it should be unaffected — verify).

- [ ] **Step 5: lint + commit**

```bash
cd <WT>
(cd plugins/credential-oci && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add plugins/credential-oci/
git commit -m "$(printf 'fix(oci): skip overdue slots rather than serve a TTL=0 lease (audit2 #6)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 4: Worker teardown via `Clean` + base context — credential-do (reference) (#10)

**Files:**
- Modify: `plugins/credential-do/backend.go`, `plugins/credential-do/workers.go`
- Test: `plugins/credential-do/backend_test.go` (or an existing test file)

Context (verified): workers launched with `go b.startWorkers(context.Background(), req.Storage)` (path_config.go:102, path_minter_sets.go:95); `startWorkers` derives `workerCtx` from that ctx; no `Clean` hook on `framework.Backend{}`. `stopWorkersLocked` (workers.go:53) takes `b.mu` itself (it's named "Locked" meaning "call under workerLifecycleMu", NOT "b.mu held"). The backend struct (backend.go) has `workerMgr`/`workerCancel`; add `baseCtx`/`baseCancel`.

- [ ] **Step 1: write the failing test**

```go
// After Clean, the worker manager is drained (no leaked goroutines).
func TestBackend_CleanStopsWorkers(t *testing.T) {
	b, storage := getTestBackend(t)
	// Write config to start workers (mirror an existing test's config write).
	writeConfig(t, b, storage)        // helper that does the "config" UpdateOperation
	// workers are started asynchronously by the config write; give Start a beat
	// — but assert via Running() which is set synchronously in Start.
	bk := b.(*backend)
	// Clean must stop them.
	bk.Backend.Clean(context.Background())
	if bk.workerMgr != nil && bk.workerMgr.Running() {
		t.Fatal("workers still running after Clean")
	}
}
```
Adapt: the config write spawns `go startWorkers`, which is async — to make the test deterministic, either (a) call `bk.startWorkers(context.Background(), storage)` synchronously in the test to guarantee a running manager, then `Clean`; or (b) poll `Running()` true then Clean then assert false. Prefer (a): construct the backend, call `startWorkers` directly (synchronous), assert `Running()` true, call `Clean`, assert `Running()` false. Read how an existing test starts workers to mirror it.

- [ ] **Step 2: run, confirm fail**

```bash
cd <WT>
go test -run TestBackend_CleanStopsWorkers github.com/nicois/openbao-cloud-creds/plugins/credential-do/ -v 2>&1 | tail -12
```
Expected: FAIL — `b.Backend.Clean` is nil (panics) or workers still Running (no Clean wired).

- [ ] **Step 3: implement**

In `backend.go`:
3a. Add fields to the `backend` struct:
```go
	baseCtx    context.Context
	baseCancel context.CancelFunc
```
3b. In `Factory`, after creating `b` (before/after `b.Setup` is fine), set the base context and the Clean hook:
```go
	b.baseCtx, b.baseCancel = context.WithCancel(context.Background())
```
and on the `framework.Backend{...}` literal add:
```go
		Clean: func(_ context.Context) { b.stopWorkers() },
```
(Define a small lock-safe `stopWorkers` wrapper in workers.go — see 3d — that takes `workerLifecycleMu` like `startWorkers` does, then calls `stopWorkersLocked`, then `b.baseCancel()`.)

3c. Change the two launch sites (`path_config.go:102`, `path_minter_sets.go:95`) from `context.Background()` to `b.baseCtx`:
```go
	go b.startWorkers(b.baseCtx, req.Storage)
```

3d. In `workers.go`, add the lock-safe stop wrapper (mirrors how `startWorkers` takes the lifecycle mutex; `stopWorkersLocked` must be called holding `workerLifecycleMu`, and it internally takes `b.mu`):
```go
// stopWorkers drains the worker manager under the lifecycle mutex. Safe to call
// from Clean (backend teardown).
func (b *backend) stopWorkers() {
	b.workerLifecycleMu.Lock()
	defer b.workerLifecycleMu.Unlock()
	b.stopWorkersLocked()
}
```
And in the `Clean` hook also cancel the base context after stopping workers — simplest: have `stopWorkers` call `b.baseCancel()` at the end (guard nil). Confirm `stopWorkersLocked` doesn't itself take `workerLifecycleMu` (it doesn't — it takes `b.mu`), so no double-lock.

**Lock-safety check:** `startWorkers` holds `workerLifecycleMu` then calls `stopWorkersLocked` (which takes/releases `b.mu`). `stopWorkers` does the same ordering (`workerLifecycleMu` → `stopWorkersLocked`→`b.mu`). No path takes `b.mu` then `workerLifecycleMu`, so no AB-BA. `Clean` calling `stopWorkers` is consistent with that order.

- [ ] **Step 4: run, confirm green + no race**

```bash
cd <WT>
go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-do/... 2>&1 | tail -15
```
Expected: TestBackend_CleanStopsWorkers passes; all existing DO tests pass; no race.

- [ ] **Step 5: lint + commit**

```bash
cd <WT>
(cd plugins/credential-do && gofmt -w . && export PATH="$(go env GOPATH)/bin:$PATH" && golangci-lint run ./...)
git add plugins/credential-do/
git commit -m "$(printf 'fix(do): stop workers on backend Clean + use base context (audit2 #10)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Tasks 5–13: Worker teardown for the other 9 plugins (#10)

Each of aws, gcp, azure, oci, ovh, upcloud, exoscale, vultr, akamai gets the **exact Task 4 treatment**. Per plugin:
1. Read its `backend.go` (Factory + backend struct) and `workers.go` to confirm the same shape (`workerLifecycleMu`, `stopWorkersLocked`, `workerMgr`, the two `go startWorkers(context.Background(), ...)` launch sites in path_config.go + path_minter_sets.go — OCI also launches from its rotation path; grep `go b.startWorkers`).
2. Apply 3a (baseCtx/baseCancel fields), 3b (Clean hook + baseCtx init in Factory), 3c (launch sites → b.baseCtx), 3d (stopWorkers wrapper).
3. Add `TestBackend_CleanStopsWorkers` (same shape; OCI's worker set includes rotation — same Running() assertion).
4. `go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-<p>/...` green; existing tests unchanged.
5. gofmt + lint; commit `fix(<p>): stop workers on backend Clean + use base context (audit2 #10)`.

One commit each. **Per-plugin note:** OCI launches workers from more than the two standard sites (it has rotation) — grep ALL `go b.startWorkers` / `go startWorkers` call sites in each plugin and switch every one to `b.baseCtx`. Injected-client plugins (aws/gcp/oci) have the same backend lifecycle shape — confirm per plugin.

After all 9:
```bash
cd <WT>
go build github.com/nicois/openbao-cloud-creds/... && go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | grep -E 'FAIL|ok ' | tail -22
```

---

## Task 14: Full verification

**Files:** none (verification only).

- [ ] **Step 1: every module 0 lint + workspace green**

```bash
cd <WT>
export PATH="$(go env GOPATH)/bin:$PATH"
go build github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -3; echo "build: $?"
go test -race github.com/nicois/openbao-cloud-creds/... 2>&1 | tail -30
fail=0
for d in pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/worker pkg/plugintest pkg/localexpiry pkg/telemetry pkg/metricspath \
         plugins/credential-akamai plugins/credential-aws plugins/credential-azure plugins/credential-do \
         plugins/credential-exoscale plugins/credential-gcp plugins/credential-oci plugins/credential-ovh \
         plugins/credential-upcloud plugins/credential-vultr; do
  (cd "$d" && golangci-lint run ./... 2>&1 | grep -q '0 issues') || { echo "LINT FAIL $d"; fail=1; }
done
[ $fail -eq 0 ] && echo "ALL 20 MODULES CLEAN"
make lint 2>&1 | tail -3; echo "make lint: $?"
make smoke-test 2>&1 | tail -4
```
Expected: build OK, all tests pass, ALL 20 MODULES CLEAN, make lint exit 0, smoke green.

- [ ] **Step 2: no stray nolint; mark audit-2 #2/#6/#10 done**

```bash
cd <WT>
git diff main..HEAD | grep -nE '^\+.*nolint' || echo "no nolint added"
```
In `docs/audit-2026-06-01.md`, append ` — [RESOLVED 2026-06-01]` to the #2, #6, #10 headings with a one-line resolution note each (Effort 1 done): #2 body-hash signing + signature-validating fake; #6 skip-overdue→pool_exhausted; #10 Clean hook + base context across all 10 plugins.

- [ ] **Step 3: commit the doc update**

```bash
cd <WT>
git add docs/audit-2026-06-01.md
git commit -m "$(printf 'docs: mark audit2 #2/#6/#10 resolved (effort 1)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
git log --oneline main..HEAD
```

---

## Self-review notes (for the executor)

- **Task ordering:** Task 1 (akamai body hash) before Task 2 (fake validation) — the fake validating proves Task 1 correct, and Task 2's integration assertion depends on Task 1's fix being in. Task 3 (OCI) and Tasks 4–13 (#10) are independent of #2 and of each other (different plugins/files). Task 14 last.
- **#2 is the subtle one:** the fake must reimplement the EG1-HMAC-SHA256 algorithm independently (it's `package fakes`, can't import the plugin's `signRequest`). Get the `authData`+canonical-request format byte-identical to the plugin or the fake will reject valid requests. Read both sides carefully.
- **#10 lock-safety:** `stopWorkers` takes `workerLifecycleMu` then `stopWorkersLocked` takes `b.mu` — same order as `startWorkers`. Don't call `stopWorkersLocked` directly from `Clean` (it's not under the lifecycle mutex). The `-race` suite + the Running()-after-Clean test guard it.
- **Behavior preservation:** every existing test passes unchanged except where a NEW test is added. No test edited to force a pass (except adding `srv.RegisterCredential` to the akamai setup helper, which is additive test-harness wiring, not changing an assertion).
- **No new nolint.** Trust live code over plan line numbers.
