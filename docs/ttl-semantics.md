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
   lease, a hard revoke at lease end, or — on the two credentials a *role* owns
   rather than a lease (OCI's rotation slots, DO's rotated Spaces key) — an
   accepted, documented window bounded by the rotation schedule.

A shared credential makes that second direction unavoidable rather than merely
accepted. The credential belongs to the role and is held by every reader, so one
reader's lease ending cannot delete it without breaking the others; what bounds
it is the next rotation plus the overlap, and an operator who needs it gone
sooner has `roles/<name>/revoke-upstream`. The bound is still enforced in the
direction the techrfc forbids: no lease may be longer than the overlap, so no
client can hold a lease past the deletion of the credential it names.

Where neither a mint-time lifetime nor a revoke can close it — OVH, whose token
lifetime is fixed at 1h and which has no revoke API — the plugin now **rejects
the role** rather than issue a lease it cannot honour.

## Per-cloud matrix

| Cloud | Mint-time lifetime control | Issued credential expires by itself? | At lease end | Credential can outlive lease? | Role TTL bounds enforced at write |
|---|---|---|---|---|---|
| DigitalOcean (`credential_type=token`) | none (request carries only `name` + `scopes`) | no | hard revoke `DELETE /v2/tokens/{id}` | only if revoke fails (reconciler is the backstop) | none needed — any TTL is enforceable by revoke |
| DigitalOcean (`credential_type=spaces_key`) | **none, and none exists** — the Spaces API has no TTL, expiry or rotation field | no | hard revoke `DELETE /v2/spaces/keys/{access_key}` | only if revoke fails (reconciler is the backstop) | none needed — any TTL is enforceable by revoke |
| DigitalOcean (`credential_type=spaces_key_rotated`) | **none, and none exists** — same API, same absent TTL field | no | **soft**: the lease is forgotten, the key stays live because every other reader is holding it | **yes, by design** — the key is the role's, and lives until `rotation_period` later plus `overlap_ttl` | `overlap_ttl` and `rotation_period` are required, `rotation_period ≥ 1h`, `overlap_ttl ≤ rotation_period`, and **`max_ttl ≤ overlap_ttl`** — the worst case is a read answered the instant before a rotation, so a lease no longer than the overlap can never outlive the key it names |
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
  just defers the revoke, which is honest), and an unreclaimed key consumes capacity
  indefinitely rather than merely existing, because Spaces keys count against a
  per-account cap of 200.
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

A `spaces_key_rotated` role keeps the uniform 15m/1h defaults, but they are now *bounded by
another of its own fields*: `max_ttl ≤ overlap_ttl`, so a role written with an overlap shorter
than an hour must lower `max_ttl` as well. The write is refused rather than clamped — a silently
shortened lease would look like the cloud misbehaving, and the operator who chose a 30-minute
overlap is the one who knows what the leases against it should be.

## A TTL is also a containment bound (2026-09-16)

The matrix above answers "when does this credential stop working if nothing goes wrong". Read
the same columns as an incident-response question — "how long does a *leaked* one keep working"
— and one distinction becomes the important one:

- **Where a credential can be deleted** (all three DO types, UpCloud, Azure, Exoscale, Vultr,
  Akamai), the TTL is not the bound: `roles/<name>/revoke-upstream` deletes every credential the
  role has issued, so containment is minutes and independent of the TTL.
- **Where it cannot** (AWS, GCP, OVH — the three rows whose "at lease end" cell is *nothing*),
  the role's `max_ttl` **is** the blast radius. There is no lever during an incident, only the
  one already bought at role write: 12h on AWS or GCP if the maximum was taken, 1h on OVH
  because the cloud fixes it. A shorter `max_ttl` on those three is a containment decision, not
  only a hygiene one, and it can only be made in advance.
- **OCI** is bounded by the rotation period rather than by either: a slot's token is shared by
  every holder, so containment is `rotate-slot/<role>/<slot_index>`, which replaces it now.
- **A rotated Spaces key** is the two answers at once, which is why it needs saying separately.
  Left alone it is bounded by the schedule, like OCI — the key a leak copied stops working at the
  next rotation plus the overlap, and 90 days is not containment. But the key *is* deletable, so
  both levers work: `roles/<name>/rotate` replaces it now and lets the overlap run, which is the
  right move when the credential is merely stale and clients must not break; `revoke-upstream`
  deletes it now and breaks every holder, which is the right move when it has leaked. The choice
  between them is the whole reason both exist.

Two rows deserve naming here because their honest TTL and their containment story diverge
sharply. **Akamai** does not shorten the credential at all (the Identity API's own `expiresOn`
is far beyond any lease), so revoke is the *only* bound — and therefore `revoke-upstream` is
the only containment. **DigitalOcean Spaces keys** have no expiry field in the API at all, same
conclusion. See KI-011 and [`decisions.md`](decisions.md).

## Two TTLs the matrix does not predict (2026-09-21)

Both are cases where the lease a client receives is **shorter** than the role's `default_ttl`, which
is the safe direction — but a client that sizes its refresh loop from the role definition rather than
from the `lease_duration` it was handed will be cut off early. Neither is visible in the matrix above,
because neither is a property of the cloud.

**A batch-token caller's lease is capped by the token's remaining life.** Probed against OpenBao
v2.6.1: a 20-minute lease requested by a batch token with 10 minutes left was issued at **599s**. A
batch token is not a stored entry, so it cannot be renewed and its expiry is fixed at login; core
will not let a lease outlive it. The role's `default_ttl` is therefore an upper bound for such a
caller, not the value they get. (Two other batch facts matter for containment rather than TTL: the
lease belongs to the token's **parent**, so revoking the parent's accessor does revoke the
credential; and the token has no accessor of its own, which is what `require_caller_identity=token_accessor`
refuses. See the batch-token note in [`decisions.md`](decisions.md).)

**A rotated Spaces key served past its rotation age gets what is left of the overlap.** When a
rotation fails and the key is still inside the window it may be served in, the response's TTL is
clamped to `deadline() - now` — the earliest moment that key could be deleted — so it shrinks as the
window closes. That keeps OBC-002 true (no lease outlives the credential it names) on the one type
where the credential's life is the role's schedule rather than the lease's. Past the window the read
is refused instead, carrying the rotation's own error code. See the failed-rotation note in
[`decisions.md`](decisions.md).
