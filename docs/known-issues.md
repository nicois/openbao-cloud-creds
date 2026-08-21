# Known Issues / Follow-ups

Issues found during live testing and subsequent audits, each with a precise root
cause and the fix. KI-001/KI-002 came out of the original multi-cloud spike's
resilience assessment (against a live raft cluster, UpCloud) and are **RESOLVED**
(fix + red-baseline regression tests); KI-005 is resolved likewise. KI-003,
KI-004 and KI-006 are accepted, documented risks. Resolved entries are kept for the rationale
and history.

---

## KI-001 — `config`/`username` not loaded on backend init (credential-upcloud) — [RESOLVED 2026-05-30]

**Resolved:** `Factory` now calls `loadConfig` (before `loadAllMinterSets`) to
rehydrate config-derived backend fields from storage. Turned out to affect **7
plugins**, not just UpCloud — every HTTP-fake plugin stashed a config field
(api URL, username, region, endpoints, tenant) set only in `pathConfigWrite`.
Akamai's pre-existing `loadHost` was partial (restored `host` but not `apiURL`)
and was replaced by a full `loadConfig`. Regression: the `reload` category of the
conformance table (`pkg/plugintest/reload.go`, run from `conformance/` against all
ten plugins). Originally the injected-client plugins (AWS/GCP/OCI) could not
exercise reload through their fakes and skipped it; **that residual gap is closed
as of 2026-08-21** — `Harness.Inject` re-applies the fake client to every backend
instance, including the reload, so all ten now run the category.

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
Regression: the `perturbation` and `revoke` categories of the conformance table,
run against every plugin from `conformance/`. (No-revoke/soft-revoke plugins —
aws, gcp, ovh, oci — were never affected: their revoke makes no upstream call.)

**Severity:** Medium — noisy failing revokes; it leaks revoke-retry work
indefinitely.

> **Correction (2026-08-21):** the original text below said the upstream
> credential "still expires via TTL, so not a security hole". That is true only
> for the clouds whose credentials carry a native expiry (Azure, UpCloud). On DO,
> Exoscale, Vultr and Akamai the issued credential has **no upstream expiry**, so
> a credential left unrevoked persists until the owner-tagged reconciler deletes
> it — which is the real backstop, and on Exoscale/Vultr needs the manual
> `/reconcile` endpoint (KI-004). The plugins' fallback log line has been
> reworded accordingly. Full per-cloud picture in
> [`ttl-semantics.md`](ttl-semantics.md).

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
they are manually cleaned via the `/reconcile` endpoint, or (if a lease still
tracks them) deleted by that lease's revoke — they do **not** expire on their own.

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
- Or accept the leak: an orphan that still has a lease will be deleted when that
  lease revokes. Note that **neither Exoscale API keys nor Vultr sub-users have a
  native upstream expiry** — an orphan with no lease behind it (the KI-002 path,
  or a lost lease) does not lapse on its own, so manual `/reconcile` is the only
  cleanup. See [`ttl-semantics.md`](ttl-semantics.md).
- The other 4 hard-revoke plugins (DigitalOcean, UpCloud, Azure, Akamai) DO have
  list-creation timestamps and their reconcilers now auto-delete confirmably-old
  orphans normally.

**Safe direction:** this is the intended safe interim behavior for clouds without
list timestamps — better to leak an orphan (which will be revoked on lease end
anyway) than to risk hard-deleting a live credential issued in the last hour.

---

## KI-005 — TTL honesty gaps (OVH sub-1h roles; Azure/UpCloud renewal) — [RESOLVED 2026-08-21]

**Resolved:** see [`ttl-semantics.md`](ttl-semantics.md) for the full per-cloud
matrix and the changes. Summary of what was wrong and what was done:

**Severity:** Medium — an unaccounted-for live credential (OVH) and a lease that
outlived its credential (Azure/UpCloud); no privilege escalation in either case.

**Symptom 1 (OVH, credential outlives lease).** With `default_ttl=15m`, the lease
ended at 15 minutes but the OAuth2 token stayed valid for the rest of its hour:
OVH's token endpoint accepts no lifetime parameter (tokens are a fixed 1h) and
OVH exposes **no token-revoke API**, so neither mechanism the other plugins use to
bound a credential's life was available. The response envelope reported the
token's real 1h `expires_at` while the lease expired at 15m, so the two
disagreed. **Fix:** `pathRoleWrite` now rejects `default_ttl`/`max_ttl` below
3600s as well as above it, pinning OVH roles to exactly 1h.

**Symptom 2 (Azure/UpCloud, lease outlives credential — an OBC-002 violation).**
Both clouds fix the credential's expiry at mint time (`endDateTime` and
`expires_in` respectively, set from the role's default TTL) and neither can extend
it, but `pathCredsRenew` handed back another full TTL on every renewal. A renewed
lease therefore named a credential that had already stopped working. **Fix:** both
refuse renewal (matching AWS/GCP/OVH/OCI) and report `renewable: false`.

**Also corrected:** the DO/Exoscale/Vultr/Akamai revoke-fallback log line claimed
the credential would "expire via TTL"; those credentials have no upstream expiry,
so the message now names the owner-tag reconciler as the backstop (see the
correction note on KI-002).

**Not changed (accepted):** OCI's soft revoke — a rotation slot's token outlives
the lease until its scheduled rotation, by design; and the revoke-failure window
on the four clouds without a native expiry, bounded by the owner-tag reconciler
rather than by time. Both are recorded as residual gaps in `ttl-semantics.md`.

---

## KI-006 — capability-probe residue and unprobed clouds — [KNOWN/ACCEPTED 2026-08-21]

Capability verification (see [`minter-capability-verification.md`](minter-capability-verification.md))
mints a throwaway credential to prove a minter can mint. Three residual gaps come
with it, all accepted deliberately.

**Severity:** Low — bounded, short-lived, never handed to a caller; no privilege
escalation.

**Gap 1 — probes leave a credential behind on AWS, GCP and OVH.** None of the
three can revoke what the probe mints (STS sessions, impersonated access tokens
and OVH OAuth2 tokens expire on their own and have no revoke API). Each probe
therefore leaves one credential in existence that nobody holds, bounded only by
the lifetime asked for: **900s** on AWS (its documented floor), **60s** on GCP,
and **1h** on OVH (fixed, no choice). The credential is never returned to a
caller and never recorded in a lease. Operators who cannot accept this set
`verify_minter_capability=false`. Accepted because the alternative is leaving
verification off on precisely the clouds whose health checks are least
informative.

**Gap 2 — a probe whose own delete fails leaks an upstream entity until the
reconciler runs.** On the revocable clouds (DO, Azure, UpCloud, Exoscale, Vultr,
Akamai) a failed delete does not fail the probe — minting was what was being
proved. The probe credential carries the `cloud-creds-<role>-probe-` owner
prefix and is never recorded in lease tracking, so it is an orphan by
construction and the owner-tag reconciler reclaims it. On Exoscale and Vultr that
reclamation is itself still manual (see KI-004), so a failed probe delete there
needs an operator to clean up.

**Gap 3 — OCI capability is taken on trust.** OCI's two-auth-tokens-per-user cap
means a probe would consume a rotation slot, so OCI returns
`capability.ErrUnsupported` and the write proceeds with the skip logged. An
incapable OCI minter is therefore still discovered at slot-provisioning time
(a real `create-auth-token` at role write / rotation) rather than by a probe.

**Related open refinement (not a regression):** a privilege 403 seen at
*issuance* time still maps to `upstream_auth_failed` and counts toward
`AuthFailing`, withdrawing a minter that is live but unusable for one role. A
distinct `minter_insufficient_privilege` code was deliberately not added (it is a
spec change to the error-code model, and probes front-load the diagnosis) — see
[`decisions.md`](decisions.md).
