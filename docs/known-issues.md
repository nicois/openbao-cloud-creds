# Known Issues / Follow-ups

Issues found during live testing that are not yet fixed. Each entry has a
precise root cause and a proposed fix. Found during the SRE-12109 OpenBao
multi-cloud spike's resilience assessment (against a live raft cluster, UpCloud).

---

## KI-001 — `config`/`username` not loaded on backend init (credential-upcloud)

**Severity:** High — breaks issuance on every plugin reload / raft failover until
`config` is re-written.

**Symptom (observed live):** after a raft leader failover (and equivalently after
any plugin reload), issuance on the now-active node fails with
`upstream_auth_failed: all minters in set "primary" are failing`, even though the
persisted minter set and its credentials are valid and unchanged. Re-writing
`cloud-creds/upcloud/config` (re-seeding) immediately fixes it.

**Root cause:** `Factory` (`plugins/credential-upcloud/backend.go`) calls
`loadAllMinterSets` to rehydrate minter sets from storage, but it does **not**
load the operational config — specifically `b.username`. `b.username` is the
UpCloud basic-auth *username* and is set **only** in `pathConfigWrite`
(`path_config.go:82`), i.e. only when `config` is written. On a fresh backend
instance (new active node after failover, or a plugin reload), `b.username` is
`""`.

The minter's `token` (the UpCloud *password*) lives in the minter set and *is*
loaded, but basic auth with username `""` + a valid password returns **HTTP 401
AUTHENTICATION_FAILED**. Each failing read records an auth error against the
minter's recovery state machine; after `AuthFailThreshold` (30s) every minter in
the set transitions to `AuthFailing`, and `selectMinter` then returns
`all minters in set … are failing`.

This is masked in unit tests because the test setup always writes `config`
before issuing.

**Proposed fix:** in `Factory`, load `config` (and `config/username`) from
`conf.StorageView` the same way `loadAllMinterSets` is loaded, so `b.username`
and `b.config` are populated on every backend instantiation — not just on
`config` write. Sketch:

```go
if conf.StorageView != nil {
    _ = b.loadConfig(ctx, conf.StorageView)        // new: sets b.config + b.username
    _ = b.loadAllMinterSets(ctx, conf.StorageView)
}
```

where `loadConfig` reads the `config` and `config/username` storage entries
written by `pathConfigWrite`.

**Cross-cloud note:** audit the other plugins for the same pattern — any backend
field set only in `pathConfigWrite` (not reloaded in `Factory`) will be empty
after a reload. (DO's minter token is self-contained in the minter set, so DO is
likely unaffected, but plugins with separate auth config like UpCloud need the
same fix.)

---

## KI-002 — revoke retries forever when the issuing minter is gone (all JIT plugins)

**Severity:** Medium — noisy failing revokes; upstream credential still expires
via TTL, so not a security hole, but it leaks revoke-retry work indefinitely.

**Symptom (observed live):** after a minter set is changed so a previously-present
minter id no longer exists (e.g. re-seeding `primary` from minters `[good]` to
`[upcloud-primary]`), in-flight leases that were issued by the now-absent minter
fail revocation forever:

```
expiration: failed to revoke lease: ... err: minter "good" not found in set "primary" attempts=N next_attempt=...
```

OpenBao keeps retrying the revoke with backoff, but it can never succeed because
the minter used to perform the upstream `DELETE` is gone.

**Root cause:** `pathCredsRevoke` (`path_creds.go`) resolves the issuing minter via
`getMinter(minterSet, minterID)` to make the upstream delete call; `getMinter`
(`path_creds.go:208`) returns `minter %q not found in set %q` when the id is
absent, and the revoke returns that error, so OpenBao reschedules it.

**Proposed fix:** when the issuing minter is gone, the upstream credential can no
longer be actively deleted by this plugin — but it will expire on its own (these
are short-lived credentials with a native or lease TTL). So revoke should treat
"minter not found" as a **successful no-op** (optionally logging a warning),
letting the lease be released cleanly. Optionally fall back to *any* healthy
minter in the same set to attempt the delete before giving up. Either way, do not
return an error that triggers infinite retry.

**Design tension to resolve:** this slightly weakens the "revoke deletes the
upstream credential" guarantee for the minter-removed case — acceptable because
TTL expiry is the real guarantee (see the envelope/lease contract), but worth a
decision note in `docs/decisions.md`.
