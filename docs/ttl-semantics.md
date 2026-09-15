# TTL semantics and TTL honesty (2026-08-21)

What a lease's TTL actually means on each cloud: whether the plugin can ask the
cloud for a *shorter*-lived credential, whether the issued credential expires by
itself, and what happens at lease end. This is the authoritative doc for the
per-cloud TTL story; `docs/techrfc.md` remains authoritative for the envelope
contract (OBC-002) that this doc explains how each cloud satisfies.

## The two directions of "honest"

A lease and the credential it names have two independent failure modes:

1. **Lease outlives the credential** — the client holds a lease OpenBao says is
   valid around a credential the cloud has already expired. Calls start failing
   mid-lease. This is the direction the techrfc forbids outright (OBC-002: "no
   cloud's strategy may produce a TTL longer than the credential's actual
   remaining validity"). **No plugin does this** (see the fix below for the two
   that could before 2026-08-21).
2. **Credential outlives the lease** — OpenBao considers the lease finished but
   the credential still works upstream. This is the *security*-relevant
   direction: it is a credential nobody is accounting for. It is closed by one of
   three mechanisms depending on the cloud: a mint-time lifetime equal to the
   lease, a hard revoke at lease end, or (OCI only) an accepted, documented
   window bounded by the rotation period.

Where neither a mint-time lifetime nor a revoke can close it — OVH, whose token
lifetime is fixed at 1h and which has no revoke API — the plugin now **rejects
the role** rather than issue a lease it cannot honour.

## Per-cloud matrix

| Cloud | Mint-time lifetime control | Issued credential expires by itself? | At lease end | Credential can outlive lease? | Role TTL bounds enforced at write |
|---|---|---|---|---|---|
| DigitalOcean (`credential_type=token`) | none (request carries only `name` + `scopes`) | no | hard revoke `DELETE /v2/tokens/{id}` | only if revoke fails (reconciler is the backstop) | none needed — any TTL is enforceable by revoke |
| DigitalOcean (`credential_type=spaces_key`) | **none, and none exists** — the Spaces API has no TTL, expiry or rotation field | no | hard revoke `DELETE /v2/spaces/keys/{access_key}` | only if revoke fails (reconciler is the backstop) | none needed — any TTL is enforceable by revoke |
| AWS | yes — `DurationSeconds` = role TTL | yes, exactly at lease end | nothing (STS cannot be revoked) | no | **900s ≤ TTL ≤ 43200s** (STS `DurationSeconds` range), both bounds on `default_ttl` and `max_ttl` |
| GCP | yes — `lifetime` = role TTL | yes, exactly at lease end | nothing (token cannot be revoked) | no | **TTL ≤ 43200s** (and ≤3600s in practice without the credential-lifetime-extension org policy). GCP documents **no minimum**, so no floor |
| Azure | yes — `endDateTime` = mint + role TTL | yes, exactly at lease end | hard revoke `removePassword` | no | none documented by Microsoft; renewal refused (below) |
| OVH | **none** — OAuth2 tokens are a fixed 1h, the token endpoint takes no lifetime parameter | yes, 1h after mint | nothing possible (**no token-revoke API**) | would, for any TTL < 1h — so those roles are **rejected** | **TTL must be exactly 3600s** for both `default_ttl` and `max_ttl` |
| UpCloud | yes — `expires_in` = role TTL | yes, exactly at lease end | hard revoke `DELETE .../tokens/{id}` | no | **TTL ≤ 8760h** (UpCloud's documented `expires_in` cap); no minimum — any positive value is honoured; renewal refused (below) |
| Exoscale | none (API keys have no lifetime) | no | hard revoke `DELETE /api-key/{id}` | only if revoke fails (see KI-004) | none needed |
| Vultr | none (sub-users have no lifetime) | no | hard revoke `DELETE /v2/users/{id}` | only if revoke fails (see KI-004) | none needed |
| Akamai | not used — the Identity API returns an `expiresOn` of its own (long, account-policy default); the plugin does not shorten it | effectively no (far beyond any lease) | hard revoke (delete API client) | only if revoke fails | none needed |
| Oracle (OCI) | n/a — phased rotation, not per-request minting | no; the auth token lives until its slot is rotated | **soft**: the lease is forgotten, the slot's token stays live until its scheduled rotation | **yes, by design** — bounded by the rotation period | lease TTL is clamped to `min(role default_ttl, time until that slot's next rotation)`, so the lease never overstates validity |

## Changes made 2026-08-21

- **OVH roles are pinned to exactly 3600s.** `pathRoleWrite` already rejected
  TTLs *above* 1h; it now also rejects TTLs *below* 1h
  (`plugins/credential-ovh/path_roles.go`, `minOVHTTL`). Rationale: OVH cannot
  mint a shorter token and cannot revoke one, so `default_ttl=15m` used to end
  the lease at 15m while the token stayed valid for the remaining 45 minutes,
  with the envelope's `expires_at` (the token's real 1h expiry) disagreeing with
  the lease. Rejecting the role is the only honest option.
- **Azure and UpCloud leases are no longer renewable.** Both pin the credential's
  expiry at mint (`endDateTime` / `expires_in`) and neither cloud can extend it,
  but `pathCredsRenew` used to hand back another full TTL — a lease that outlives
  its credential (direction 1 above). Both now refuse renewal with a clear
  message ("… is fixed at mint; issue a new credential instead"), matching
  AWS/GCP/OVH/OCI, and report `renewable: false` in the envelope. The clouds whose
  credentials have no upstream expiry (DO, Exoscale, Vultr, Akamai) remain
  renewable — extending those leases just defers the revoke, which is honest.
- **AWS/GCP bounds are symmetric and named.** The inline `900`/`43200` literals
  became `minSTSTTL`/`maxSTSTTL` and `maxGCPTTL`, and the missing
  counterpart checks were added (`max_ttl` below the STS floor, `default_ttl`
  above the ceiling) so no field can slip past a bound.
- **UpCloud gained its documented ceiling** (`maxUpCloudTTL` = 8760h): a longer
  TTL would be rejected by UpCloud at mint time, so it is caught at role write.
- **The revoke-fallback log line was corrected** on DO, Exoscale, Vultr and
  Akamai. When the issuing minter is gone and no fallback exists in the set
  (KI-002's resolved path), the old message said the credential was being left
  "to expire via TTL" — which is false on exactly these four clouds, because
  their credentials have no upstream expiry. It now says the credential is left
  for the owner-tag reconciler, which is the actual backstop.

## Residual gaps (accepted, documented)

- **OCI is soft by design.** A read hands out the freshest slot, and the lease
  ends before the slot rotates; the auth token remains valid until the scheduled
  rotation (bounded by the rotation period). This is the price of the strategy —
  OCI caps a user at 2 auth tokens, which rules out per-request minting. The
  lease never *overstates* validity, which is the invariant that matters for
  clients; operators should size the rotation period as the real blast-radius
  window and use the emergency-rotate endpoint for incident response.
- **Revoke-failure window on the four no-native-expiry clouds.** For DO (both of its
  credential types), Exoscale, Vultr and Akamai, a credential whose revoke cannot be performed
  (issuing minter gone with no fallback in the set — KI-002) does **not** lapse
  on its own. The owner-tagged reconciler deletes it, but for Exoscale and Vultr
  the background reconciler skips entities whose age is unconfirmable (KI-004),
  so cleanup there needs the manual `/reconcile` endpoint. The blast radius is
  bounded by the owner-tag scheme, not by time.
- **Akamai could shorten its credentials.** The Identity Management API lets a
  credential's `expiresOn` be set/updated; the plugin currently accepts the
  account-default (long) expiry and relies on revoke. Setting `expiresOn` to the
  lease end would add defence in depth for the revoke-failure case above. Not
  implemented — it needs verification against a real Akamai account (the deferred
  real-cloud pass, audit #7).
- **A DO Spaces key is the purest case of "revoke is the entire lifecycle" (2026-09-15).**
  DigitalOcean's Spaces API has no expiry field of any kind, so there is nothing to send
  and nothing to fall back on: revoke at lease end plus the owner-tag reconciler is the
  *only* bound on an issued key, and its secret is unrecoverable after create, so the
  lease's `internal_data` carrying the `access_key` is what makes revoke possible at all.
  The row above therefore belongs with Exoscale/Vultr/Akamai rather than with anything
  that expires. Two consequences worth naming: a Spaces role stays **renewable** (renewal
  just defers the revoke, which is honest), and the revoke-failure window below applies to
  it in full — with the extra sting that Spaces keys count against a per-account cap of
  200, so an unreclaimed one consumes capacity indefinitely rather than merely existing.
- **DO may have a native expiry the plugin does not use.** DO's control panel now
  requires an expiry when creating a personal access token, so the (undocumented)
  `POST /v2/tokens` endpoint may accept or even require one; the plugin sends only
  `{name, scopes}`. If it does, DO should send the lease TTL as the token's
  expiry for the same defence in depth. Unverified — see
  `docs/do-api-verification-2026-08-21.md` (D5).
- **No lower bound is invented where the cloud documents none.** Azure, GCP,
  UpCloud, DO, Exoscale, Vultr and Akamai accept arbitrarily short TTLs (Azure and
  GCP by shortening at mint, the rest via revoke), so the plugins do not impose a
  floor. Very short Azure TTLs interact with the Graph propagation lag (KI-003):
  a credential that takes seconds to become usable is not useful with a 30s TTL.
  That is a client-side sizing concern, not a validation rule.

## Role TTL defaults (uniform since 2026-08-22, A28)

`default_ttl` **15m** and `max_ttl` **1h** on every cloud that can honour them. They used
to vary by up to 400× across ten plugins carrying identical documentation, which made a
default an accident of which plugin an operator happened to write first.

Two clouds differ, and both are forced rather than chosen:

| Cloud | default_ttl | max_ttl | Why it differs |
|---|---|---|---|
| OVH | 3600s | 3600s | The token's lifetime is fixed at 1h by the cloud and there is no revoke API, so neither a shorter nor a longer TTL would be honest (see the OVH row above). |
| OCI | rotation_period/2 | rotation_period | Phased rotation: a read returns the freshest pre-provisioned slot and the lease TTL is the time until that slot's next rotation, so the role's TTL fields are bounds on the rotation schedule rather than on a credential's own lifetime. |
