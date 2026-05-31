# Known Issues / Follow-ups

Issues found during live testing, each with a precise root cause and the fix.
Found during the SRE-12109 OpenBao multi-cloud spike's resilience assessment
(against a live raft cluster, UpCloud). Both entries below are now **RESOLVED**
(fix + red-baseline regression tests); kept for the rationale and history.

---

## KI-001 — `config`/`username` not loaded on backend init (credential-upcloud) — [RESOLVED 2026-05-30]

**Resolved:** `Factory` now calls `loadConfig` (before `loadAllMinterSets`) to
rehydrate config-derived backend fields from storage. Turned out to affect **7
plugins**, not just UpCloud — every HTTP-fake plugin stashed a config field
(api URL, username, region, endpoints, tenant) set only in `pathConfigWrite`.
Akamai's pre-existing `loadHost` was partial (restored `host` but not `apiURL`)
and was replaced by a full `loadConfig`. Regression: `TestResilience_Reload` in
each plugin's `resilience_test.go` (via `pkg/plugintest`). The injected-client
plugins (AWS/GCP/OCI) can't exercise reload through the fake and `t.Skip` it —
residual risk noted in the taxonomy spec.

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

## KI-002 — revoke retries forever when the issuing minter is gone (all JIT plugins) — [RESOLVED 2026-05-30]

**Resolved:** the 6 hard-revoke plugins (do, upcloud, exoscale, azure, vultr,
akamai) now tolerate a removed issuing minter — `pathCredsRevoke` falls back to
any healthy minter in the same set via `anyHealthyMinterInSet`, and if none
remains, no-ops (logging) and releases the lease. A related bug surfaced by the
same suite: a 404 on the upstream delete (double-revoke / already-deleted) is
now treated as success rather than an error. Rationale in `docs/decisions.md`.
Regression: `TestResilience_Perturbation` and `TestResilience_Revoke` in each
hard-revoke plugin's `resilience_test.go`. (No-revoke/soft-revoke plugins —
aws, gcp, ovh, oci — were never affected: their revoke makes no upstream call.)

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

---

## KI-003 — Azure addPassword Graph propagation lag — [DOCUMENTED-RISK 2026-05-31]

**Status:** DOCUMENTED-RISK (audit F7, 2026-05-31). Not reproducible without a
real Entra tenant; self-heals within seconds. Consuming clients should implement
transient 401 retry rather than treating it as fatal.

**Severity:** Low — self-heals automatically within seconds; affects only the
immediate post-issuance window.

**Symptom:** a freshly-issued Azure `client_secret` may fail authentication
(typically `AADSTS7000215` or similar Entra errors) for a few seconds immediately
after issuance, even though the credential was successfully created and returned
by the plugin.

**Root cause:** Microsoft Graph `addPassword` is eventually consistent across the
Entra (AAD) directory. A password credential added to an app registration may not
be visible to authentication services for a brief period (typically a few
seconds) while the change propagates across the tenant's directory replicas.

**Guidance:** consuming clients should retry a transient 401 immediately after
issuance rather than treat it as fatal. The credential WILL work once directory
replication completes. Suggested retry pattern: on the first 401 within the
first 30s of issuance, wait 1-2 seconds and retry once; if the second attempt
also 401s, treat it as a real auth failure.

**Can NOT be reproduced against the fake:** the Azure cloud-fake
(`pkg/credenvelope/fakes/azure.go`) is an `httptest.Server` with instant
in-memory state, so it has no directory-replication lag. The phenomenon is
observable only against a real Entra tenant, and then only under specific
replication topologies.

---

## KI-004 — Exoscale/Vultr background reconciler does not auto-delete orphans — [KNOWN/ACCEPTED 2026-05-31]

**Status:** KNOWN/ACCEPTED (audit F1 residual, 2026-05-31). Safe direction (leak
over delete-live-cred). Manual reconcile with `ConfirmationHold=0` still works.

**Severity:** Medium — orphaned credentials leak until manual cleanup or natural
expiry; but TTL expiry is still enforced (short-lived credentials auto-expire
on lease end via normal revoke), so it's not a security hole.

**Symptom:** the background reconciler worker does not automatically delete
orphaned upstream credentials for Exoscale and Vultr. Orphans accumulate until
either they are manually cleaned via the `/reconcile` endpoint or they expire
naturally on their lease TTL.

**Root cause:** Exoscale's `GET /v2/api-key` and Vultr's `GET /v2/users` list
APIs return no creation timestamp — only `key-id`/`name`/`role-id` for Exoscale,
and `id`/`name`/`email`/`api_enabled`/`acls` for Vultr. The fail-closed
reconciler guard (audit F1 fix, Task 3) skips entities whose age is
unconfirmable (zero `CreatedAt`) under the 1h `ConfirmationHold`, to avoid
deleting a live just-issued credential during the create-then-track window. Since
neither cloud's lister can populate `CreatedAt`, EVERY orphan has zero `CreatedAt`
and is skipped on the background worker reconcile path.

**Guidance:**
- Use the manual `/reconcile` endpoint (which uses `ConfirmationHold=0`, so it
  deletes even zero-`CreatedAt` orphans) to clean Exoscale/Vultr orphans when
  needed.
- Or accept the leak: short-lived credentials expire on lease end via normal
  revoke anyway, so an untracked orphan is not a persistent security hole — it
  will be deleted when its lease revokes or will auto-expire on the native
  upstream TTL if one exists.
- The other 4 hard-revoke plugins (DigitalOcean, UpCloud, Azure, Akamai) DO have
  list-creation timestamps and their reconcilers now auto-delete confirmably-old
  orphans normally.

**Safe direction:** this is the intended safe interim behavior for clouds without
list timestamps — better to leak an orphan (which will be revoked on lease end
anyway) than to risk hard-deleting a live credential issued in the last hour.
