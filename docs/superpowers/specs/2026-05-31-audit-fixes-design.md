# Audit Fixes (batch 1) — Design Spec

**Status:** Approved (2026-05-31)
**Scope:** The four correctness/security defects from `docs/audit-2026-05-31.md` items #1–4. Broad de-duplication (#7) is explicitly deferred to a later effort.

## Sequencing decision

Bugs-first (audit option 2). Rationale: #2 and #3 live in the **already-shared** `pkg/metrics/access.go`, so they are single-site fixes today — the broad de-dup (#7) would not reduce their blast radius. Only #1 (error_code) has genuine per-plugin surface; it gets a **narrow** shared helper in `pkg/credenvelope` (a thin slice of #7), not the full extraction.

## Fix 1 — `#3` metrics storage-key segment escaping (`pkg/metrics/access.go`)

**Bug (verified):** entity IDs are `setName/minterID` (contain `/`). Flush key is `metrics/<entityID>/<role>/<nodeID>`; `ListStaleEntities` does `SplitN(trimmed, "/", 3)` and takes `parts[0]` → recovers only `setName`, collapsing every minter in a set into one staleness bucket.

**Fix:** escape each segment with `url.PathEscape` when building keys, `url.PathUnescape` when parsing. THREE sites must agree:
- Flush (l.84): `fmt.Sprintf("metrics/%s/%s/%s", url.PathEscape(k.EntityID), url.PathEscape(k.Role), url.PathEscape(t.nodeID))`
- MergeEntity prefix (l.97): `fmt.Sprintf("metrics/%s/", url.PathEscape(entityID))` — must escape identically so the prefix lookup still matches.
- ListStaleEntities parse (l.200): `SplitN(trimmed, "/", 3)`; `entityID, _ = url.PathUnescape(parts[0])`.

`set/minter` → `set%2Fminter` (slash-free), so split is unambiguous.

## Fix 2 — `#2` per-node metrics double-count (`pkg/metrics/access.go`)

**Bug (verified):** `Flush` writes the full running `AccessCount` to storage and never resets `t.entries`. `MergeEntity` sums the flushed storage value AND the same node's live in-memory entries → a node that both issues and serves the query double-counts itself.

**Fix (skip-local-storage-key):** in `MergeEntity`, when iterating storage keys, skip this node's own key (the one ending in the escaped `t.nodeID`) — that node's contribution comes from the in-memory `t.entries` instead. Remote nodes' storage values are still summed. Net: each node counted once (live node via memory, others via storage).

Implementation: derive the local suffix `"/"+url.PathEscape(t.nodeID)` and `continue` for any listed key with that suffix; keep the existing in-memory merge block.

Edge case: if the local node has flushed but has since evicted its in-memory entry (lease ended), skipping its storage key would undercount. Acceptable and correct: an evicted entry means no active lease references it on this node; staleness/recency is still represented by other nodes and the entry's own retention. Document this in a code comment.

## Fix 3 — `#1` stable `error_code` actually emitted (`pkg/credenvelope` + plugins)

**Bug (verified):** `pkg/credenvelope/errors.go` defines 10 `ErrorCode`s but no plugin uses them; handlers put the code in free text (`logical.ErrorResponse("role_not_found: ...")`). Clients can't machine-parse `error_code`.

**Fix:** add a narrow helper to `pkg/credenvelope`:
```go
// ErrorResponse builds a logical error response carrying a stable, machine-readable
// error_code in its Data, plus the human message.
func ErrorResponse(code ErrorCode, msg string, args ...interface{}) *logical.Response
```
It returns `logical.ErrorResponse(...)` with the formatted message AND sets `resp.Data["error_code"] = string(code)`. (Verify OpenBao surfaces `Data` on error responses; if `logical.ErrorResponse` discards Data, instead return a `*logical.Response{Data: {...}, ...}` with the error flag set — confirm the SDK mechanism during implementation and use whichever actually carries `error_code` to the client.)

Then convert the credential-issuance error sites in all 10 plugins' `path_creds.go` (and role/config handlers where a documented code applies) from ad-hoc strings to `credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, ...)` etc. Map: role missing → `ErrRoleNotFound`; role disabled → `ErrRoleDisabled`; all minters failing → `ErrUpstreamAuthFailed`; upstream 429 → `ErrUpstreamQuotaExceeded`; upstream timeout → `ErrUpstreamTimeout`; pool/slot unavailable (OCI) → `ErrPoolExhausted`; internal → `ErrInternal`. Only map sites where a defined code clearly applies; leave genuinely-internal `fmt.Errorf` (e.g. missing internal_data) as-is or map to `ErrInternal`.

This is per-plugin but mechanical; it is NOT the broad #7 extraction.

## Fix 4 — `#4` reconciler delete-safety boundary test (per plugin)

**Bug (verified):** the owner-tag delete boundary — "the reconciler SHALL only delete entities matching the owner-tag/prefix scheme" — has no test asserting a non-matching entity is never deleted.

**Fix:** add a test per plugin that has a `reconciler_integration.go` (the 6 hard-revoke + any with a cloud lister) feeding the `doCloudLister`/equivalent a mix of `cloud-creds-`-prefixed and foreign-named entities, and asserting only prefixed ones are returned by `ListTaggedEntities` / reach `DeleteEntity`. Where reconciliation is shared via `pkg/reconciler`, also add a `pkg/reconciler` test asserting `Run` never calls `DeleteEntity` on an entity the lister didn't return (it can't) AND — defense in depth — consider a reconciler-level prefix guard (optional, note only).

## Out of scope (this batch)

- Audit #5 (OCI/AWS reconciler convergence), #6 (worker error/panic handling), #7 (broad de-dup), #8 (cloudconfig coverage), #9 (concurrency tests), #10 (CI gates). Each is a separate future effort.

## Testing

- `pkg/metrics`: a single-tracker record→flush→record-again→MergeEntity test proving no double-count; a `ListStaleEntities` test using a `set/minter` entity ID proving correct per-minter bucketing.
- `pkg/credenvelope`: test that `ErrorResponse` carries `error_code` in Data.
- Per plugin: at least one creds error path asserting `resp.Data["error_code"]` equals the expected stable code; the reconciler safety test.
- Whole workspace: `go test -race`, `make lint`, `make smoke-test` green.

## Success criteria

1. `MergeEntity` returns correct (non-doubled) counts on a node that issued locally.
2. `ListStaleEntities` buckets per `set/minter`, not per set.
3. Every documented `error_code` is emitted as machine-readable Data by at least the credential-issuance error paths; a test pins it.
4. Each cloud-lister plugin has a test proving foreign entities are never deleted.
5. All 17+ packages pass `-race`; lint + smoke green.
