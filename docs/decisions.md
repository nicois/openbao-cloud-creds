# Design decisions

Short notes on choices that aren't obvious from the [techrfc](techrfc.md) and would otherwise need to be re-derived from scratch.

## Why a shared Spaces key is a third credential type, and what sharing costs (2026-09-16)

The requirement was a client that periodically re-fetches a Spaces credential: normally it must be
handed the one that already exists, and when that one is old enough a replacement is minted while
the old one keeps working for a stated window. The lifecycle is therefore OpenBao's, and the
client's only obligation is to keep re-reading. That is `credential_type=spaces_key_rotated`.

The per-lease type cannot answer it, for two reasons that both come from the same place. A fleet of
N clients on a cron spends N keys against DigitalOcean's **per-account** cap of 200, so the cap
starts bounding the fleet; and every read hands out a different credential, so a consumer that
caches one is holding a key that will be deleted when the lease it came from ends. Sharing inverts
both: one key per role however large the fleet, and a credential whose replacement is scheduled
rather than tied to whoever happened to read it.

**What sharing costs, in three parts, all of them accepted rather than overlooked:**

- **The credential outlives the lease that read it** — the direction this repo closes on every JIT
  cloud. It cannot be closed here: one reader's lease ending must not delete a key every other
  reader is holding. It is *bounded* instead, by the next rotation plus `overlap_ttl`, and the
  direction the techrfc actually forbids (a lease outliving its credential, OBC-002) is still
  enforced by `max_ttl ≤ overlap_ttl`.
- **A lease is no longer a disposal mechanism.** The revoke callback is registered and deliberately
  does nothing upstream, exactly as OCI's rotation slots do. An operator who needs the credential
  gone has the two levers below; a client who wants to stop using it stops reading.
- **The mount stores the secret.** DO returns a Spaces secret exactly once, and the contract is to
  hand the same credential back to a reader who asks again, so either it is in storage or the
  contract is unimplementable. This one is *not* bounded by anything — it is a real widening of what
  a compromise of the mount's storage yields, from a handle for deleting a credential to a live
  credential. OCI's slots already made the same trade, which is what makes it a known price rather
  than a new one.

**A third `framework.Secret`, not the second one with a flag,** because the flag could not work.
`framework.Secret.Renewable()` is `(Renew != nil)`, so a type that registers a renew callback
advertises `renewable=true` no matter what any field says — and OpenBao **revokes a lease whose
renewal fails**, which here would destroy a credential every other reader is using. The revoke
callback differs too. Registering the lifecycle as its own secret type makes both dispatches
structural rather than conditional on a field read at revoke time.

**`spaces_key` stays exactly as it was, beside it.** Where the reader owns what it holds and a lease
revoke should delete it, a per-lease key is the right answer and the shared one would be wrong — and
both lifecycles are wanted on one mount, which is why all three DO roles are exercised together.

## Why rotation jitter is subtracted from the period, never added (2026-09-16)

`rotation_period` reads as a promise: this credential will not be in service for longer than that.
An operator writing 90 days is answering a policy question about how long one key may be used, so
jitter that could push a rotation *later* would make the real ceiling `period + jitter` — and the
number that satisfied the policy would be one nobody wrote down. Subtracting keeps the field the
operator set as the field the operator gets.

Jitter exists at all to break synchronisation, not to add randomness for its own sake: every role
first read in the same deploy would otherwise come due in the same minute, each minting a second key
against the shared 200-key cap and each adding to a mint burst against a shared rate limit. It
defaults to a tenth of the period rather than to zero because that is a failure an operator would
not think to ask to be protected from; `0` is available for whoever wants a predictable date.

It is rolled **once, when the key is minted**, and stored on the record. Recomputed per read it
would move the rotation date under a client watching its TTL, and "is this key due?" would stop
being a question two nodes answer the same way. A jitter at or above the period is refused, because
subtracting one would schedule the rotation at or before the mint.

## Why `roles/<name>/rotate` keeps the overlap and `revoke-upstream` does not (2026-09-16)

Both replace a shared credential; they exist separately because they answer different incidents.

A credential that is merely *stale* — a compliance date, a departing engineer, an operator who wants
the next 90 days to start now — needs the rotation brought forward without cutting anyone off, so
the replaced key keeps its full `overlap_ttl` and clients pick the new one up on their next read.
A credential that has *leaked* needs to stop working, and breaking every holder is the accepted cost
of that. The report `roles/<name>/rotate` returns names `replaced_deleted_at`, which is the one date
the operator has to pass on to whoever is still holding the old key; the secret is deliberately
absent from it, because a credential read is the only place a Spaces secret is handed out.

Not one endpoint with a flag, for the reason the containment note below gives about zero-deletion
successes: a lever that half-does containment is worse than one that refuses, because a responder
mid-incident reads success as contained. Two names make the choice explicit, and `rotate`'s help
text points at the other one.

The two also disagree about `disabled`, in opposite directions and both deliberately. `rotate`
loads the role through `loadRole` and is therefore refused on a disabled role, because rotating
**mints**, and stopping this mount from acting upstream on that role's behalf is the whole job of
the flag. A purge reads storage directly and works on a disabled role, because disable-then-purge is
the sequence the levers exist for.

## Why deletion is two declared facts in the test harnesses, not one (2026-09-16)

Until a role owned its credential, two different statements agreed on every row: *a lease ending
deletes the credential*, and *the cloud can destroy a credential this role already issued*. So one
flag carried both, and the purge suite read the containment lever off the hard-revoke flag.

A shared credential separates them in the one direction that matters. A lease ending must **not**
delete it, while an operator containing an incident must still be able to — DigitalOcean will delete
a Spaces key on demand whoever is holding it. Reading the lever off hard revoke would have asserted
that `revoke-upstream` *refuses* on exactly the role where it works: the harness agreeing with the
bug instead of catching it.

So `plugintest.Harness` and `baotest.Case` each declare both facts, and the combination that cannot
be true — hard revoke on a cloud that cannot delete an issued credential — fails loudly rather than
being quietly permitted. That check earns its place because `pkg/baotest` is imported by another
repository: a purge assertion skipped by an unset field is invisible there, while a `t.Fatalf`
naming the missing field is not.

`SharesOneCredential` is declared for the same reason rather than measured. The scenario could
compare two reads' `credential_id`s and adapt to what it found, but then a plugin that stopped
sharing would produce a suite that agreed with it. Stated, a regression in either direction fails.
It also fixes how far the upstream credential count may move per read — zero after the first — which
is what catches a read that mints when it should have re-served.

## Why containment is two levers, and why neither of them is deleting the role (2026-09-16)

A credential this plugin issued is believed to have leaked. Until 2026-09-16 an operator's options
were: revoke leases one at a time, or delete the role. **Deleting the role is worse than no action
at all**, because it looks like containment and achieves nothing — the lease core keeps the live
leases renewable, and on the four clouds whose credentials carry no upstream expiry (DO, Exoscale,
Vultr, Akamai) a credential in a client's hands works until a lease revoke reaches the cloud, which
now never comes. Revoking leases individually is only available for the leases someone can
enumerate, and an incident does not hand you lease ids. It hands you a role name.

So containment is expressed as two levers, both addressed by role name:

- **`disabled=true` on the role** — stop issuing more. It was already honoured at issuance on all
  ten plugins — the stored role carried it and issuance refused on it — and could not be *set* on
  any of them, because no role write path accepted the field. Now every one does.
  It needs nothing but the flag (no other role field, no healthy cloud), because an operator paged
  at 3am has neither the role definition nor a working upstream.
- **`roles/<name>/revoke-upstream`** — destroy what the role already issued, on the six clouds that
  can delete an issued credential.

**They are independent, and that is the requirement, not a convenience.** A responder must be able
to stop the bleeding without destroying live credentials their own services are using, and to
destroy what leaked without taking issuance down. The purge therefore leaves the role issuing, and
`disabled` deletes nothing.

**The scope of both is the role**, because the role is already the privilege boundary — it is what
`minter_set` binds, what the capability probe verifies, and what the envelope records — so it is
also the honest containment boundary. This is the answer to techrfc **QN-007** ("per-role switch or
also a per-cloud kill switch?"): per-role, and the question's premise was wrong twice over. The
switch it asked about (`disable_auto_delete`) would have halted the *reconciler's* deletes, i.e.
disabled the one thing that reclaims a leaked credential nobody holds a lease for; and a per-mount
kill switch is not a lever a responder wants, because it takes down every unaffected role in the
mount. What was actually missing was the ability to delete credentials *faster*, not more slowly.

**The lever an operator has is per-cloud, and on three clouds there is none.** Nothing deletes an
STS session, a GCP impersonation token or an OVH OAuth2 token, so on AWS/GCP/OVH the role's
`max_ttl` **is** the blast radius (≤12h, ≤12h, exactly 1h) and the only action available is having
stopped the next one. OCI is different again: a phased-rotation credential belongs to a slot and is
shared by every client that has read it, so the lever is `rotate-slot/<role>/<slot_index>`, which
replaces it now for all of them. On all four the endpoint **refuses** with `unsupported`, naming the
cloud's reason and that cloud's own remedy — the remedy is a parameter of
`upstreampurge.UnsupportedPath` rather than a constant precisely because handing OCI the
expiry answer would have an operator sit out a TTL they could have cut short.

**Why refuse rather than report zero deletions.** A `200` carrying `deleted=0, complete=true` is the
one genuinely dangerous answer: mid-incident it reads as "there was nothing out there", and the
responder stops looking for a lever. A refusal also means the endpoint can exist on all ten clouds,
which is what lets a runbook be written once — a 404 would send the reader to check whether they had
the path wrong.

## Why revoking upstream arms a durable intent instead of deleting synchronously (2026-09-16)

The obvious implementation deletes every one of the role's credentials inside the request. A role
with thousands of live credentials makes that one upstream API call each, against the same account
quota the mount issues from — so it either exceeds the request deadline (leaving the operator with
no idea what was destroyed) or spends the account's whole quota and takes issuance down. That turns
a leak of *some* credentials into an outage for *all* of them, during an incident.

So a write **arms a durable intent** (`purge/<role>`), runs one bounded pass inline, and returns
progress; the `upstream-purge` worker on the active node continues in equally bounded passes. The
operator's single call is what survives a restart and a failover, which is what makes it acceptable
to answer them before the work is finished — and `GET` on the same path reports where it got to, in
the same schema, including for a role nobody has ever purged.

**The cutoff (the arm time) is load-bearing in two ways.** Without it a purge on a mount that keeps
issuing never terminates; and it would delete the credentials issued *during* the response,
including the ones the responder just minted to run the response with. It also makes the report
answerable: `remaining` is "how much of what you named is left", not a moving target.

**Pacing is deliberately NOT the reconciler's `max_deletes_per_pass` or cadence.** Those bound the
*risk* of a pass that infers what is an orphan; this bounds the *pace* of deleting exactly what an
operator named, which carries no such risk. Sharing them would mean an operator who tightened the
reconciler for safety had unknowingly slowed their own incident response, so the purge has its own
`DefaultMaxDeletes` (50 — an ordinary role finishes in the inline pass) and its own `SweepInterval`
(1 minute, versus the reconciler's hours, because containment is urgent and a sweep with nothing
armed costs one storage list).

**The source of truth is the mount's own `active-*/` tracking records**, not a cloud listing. They
already exist for the reconciler and the capacity counter, they name the role, and they are readable
when the cloud is not. A record is deleted only *after* its credential is gone upstream — the record
is the only thing that makes the credential addressable, so losing it first strands the credential
as an orphan reclaimable by nothing but the owner-tag reconciler. A `404` from the cloud is success
(the credential is gone, which is what was asked); a `429` ends the pass rather than counting as a
failure, because the callers sharing that quota are waiting on it.

**The purge does not go through the plugin's own role loader.** Every plugin's `loadRole` refuses a
disabled role with `role_disabled`, and disable-then-purge is the sequence this pair of levers
exists for: routed through it, the endpoint answers the operator's second call with "this role is
disabled" and leaves them re-enabling the role — reopening issuance mid-incident — to destroy what
leaked. `resolvePurgeTarget` reads `roles/<name>` directly, and the conformance case
`RevokingUpstreamWorksOnADisabledRole` was proven to catch the defect by injecting exactly that
refusal into one plugin.

**Why the minter is chosen the way a lease revoke chooses one** (issuing minter if still in the set,
else any healthy minter in it): a credential belongs to the account rather than to the key that
created it, and the issuing minter is quite likely the one that has just been rotated out *because*
it leaked. Azure is the exception where a record field is load-bearing — the delete addresses the
application holding the password, so it comes from the tracking record and only falls back to the
role, since a role re-pointed at another application would send the delete somewhere that never held
that password, which Graph answers as success.

## Why a role picks the credential type, and why DO Spaces keys are that second type (2026-09-15)

KI-009 left `credential-do` in a peculiar position: complete, correct, the origin of the shared
fake — and unable to mint anything, because `POST /v2/tokens` is refused at DigitalOcean's edge
gateway for every PAT. `POST /v2/spaces/keys` is a different proposition (published spec,
`bearer_auth`, granular `spaces_key:*` scopes) and is reachable with the minter the plugin already
holds, so it is what this cloud can actually issue. See
[`cloud-credential-research.md`](cloud-credential-research.md) for that evidence.

**The type is a ROLE field (`credential_type`), not a second plugin, a second mount, or a config
setting.** A plugin per credential type would duplicate config, minter sets, the recovery state
machine and the reconciler for one cloud, and an operator would have to keep two mounts' minter
credentials in step. A config-level setting would make the choice per *mount* — but the choice is
about what a particular consumer needs, which is exactly what a role already expresses. Roles are
also where privilege is written, and the two types' privilege vocabularies are disjoint (`scopes`
versus `grants`), so the field that selects the type belongs beside the fields it governs.

`token` is the default, because every role written before the field existed omits it and must keep
issuing precisely what it issued before. The fields of the *other* type are then **refused** rather
than ignored: `scopes` on a Spaces role would let an operator believe they had narrowed a
credential they had not, and an ignored field is the failure mode that survives review, because
the role reads correctly.

Consequences that are not obvious until they bite:

- **Two secret types** (`do_token`, `do_spaces_key`), because OpenBao dispatches revoke on the
  secret type and the revokes are different endpoints keyed on different identifiers. One type for
  both would send every revoke down one path.
- **Two tracking prefixes**, and therefore reconciler ids that carry their class — see below.
- **The credential kind stops being a per-plugin constant.** It is now
  `credentialKindFor(role.credentialType())`, which is what the shape-pinning design anticipated
  ("becomes a function of the role when a cloud gains a second"); the pin check in `pathCredsRead`
  needed no change.
- **Only one of the two can be verified against real DigitalOcean**, so the conformance registry
  had to gain a *variant* rather than treating "do" as one subject.

## Why S3 is its own credential kind, with `endpoint` and `region` inside the credential (2026-09-15)

The handover note proposed reusing `KindKeySecret` — an access-key/secret-key pair — since a
Spaces key *is* one. That was rejected: the S3 API is a de-facto standard, so the shape that
addresses it deserves a name, and the name has to be big enough for every backend that will serve
it. `KindS3Credentials` is `{access_key_id, secret_access_key, endpoint, region}` plus
`session_token` where the issuing cloud grants a temporary one, and it is deliberately expected to
be served by more than one plugin: Exoscale SOS, Linode/Akamai Object Storage, Cloudflare R2,
MinIO, AWS S3 itself.

**`endpoint` and `region` live in the `credential` block, not in `metadata`.** An S3 client cannot
be constructed without them and neither is derivable from the key material: every S3-compatible
vendor uses a different host, and SigV4 signs a region string whether or not the vendor routes on
it. A client that had to fetch one from metadata and the other from the credential — or worse,
infer the host from which cloud it asked — would be back to hard-coding per-cloud knowledge, which
is the thing naming a shape exists to remove. They are therefore **required** of every plugin
declaring this kind, including where the cloud's own API returns neither (DigitalOcean does not;
the plugin derives the endpoint from the role's `region`, and an operator whose buckets sit behind
another host overrides it with the role's `endpoint`).

Two related calls:

- **Not `KindSigV4Session`**, though both are signed with SigV4. That kind is an expiring STS
  session: three fields, a session token, no endpoint. This one is a long-lived object-storage key
  with an endpoint and no session token. Neither substitutes for the other, so a client has to be
  able to refuse the one it cannot use — which is the entire point of a pinnable kind.
- **AWS-style key names, not DigitalOcean's.** DO returns `access_key`/`secret_key`; the block
  emits `access_key_id`/`secret_access_key`. The kind is named for the protocol, so its keys are
  spelled the way every S3 client already spells them; letting one vendor's field names into a
  shared shape would make the second plugin serving it either wrong or inconsistent. The
  registry-wide one-kind-one-key-set conformance test is what holds the next one to it.

Adding a kind is additive and does **not** bump `api_version` (still `"4"`) — an unknown kind is
already a refusal a client can act on.

## Why Spaces grants are parsed, and why they are a distinct `ScopeKind` (2026-09-15)

This plugin passes token `scopes` through unvalidated, on the grounds that DO adds scopes and a
pass-through needs no code change. Grants are handled the *opposite* way, for one reason: a list
mixing `fullaccess` with per-bucket grants has **no established meaning**. DO's spec asserts both
halves of a contradiction — it documents a `400` whose description is "Cannot mix fullaccess
permission with scoped permissions", and it also says a fullaccess permission "will be prioritized
if fullaccess and scoped permissions are both added". Nothing available here settles which the API
does, and no probe has been run.

That is what makes the check worth having rather than a reason to wait for the answer: refusing the
combination at role write is correct under **either** reading. If DO refuses the mix, an operator
learns at role write instead of at every issuance. If DO prioritises `fullaccess`, a role that
reads as least-privilege would have issued an account-wide key, silently, with nothing downstream
able to notice. Refusing requires recognising the permission values, so they are recognised. The
cost is that a permission DO adds later needs a one-line change; the alternative is a typo
(`readwite`) minting a key whose privilege nobody has established.

Also refused: `read`/`readwrite` against `*` (DigitalOcean expresses account-wide only as
`fullaccess`, and a silently widened grant is the failure this exists to prevent), and
`fullaccess` attached to a single bucket — the spec's only example of that permission pairs it with
an empty bucket, the whole account, and says nothing about what naming a bucket beside it does).

`ScopeKindGrants` is separate from `ScopeKindScopes` even though both render as `a:b` pairs,
because the halves mean opposite things: a scope's left half is a resource *type* a verb applies
to across the account (`droplet:create`), while a grant's left half is one named *instance*
(`backups:read`). A client that read grants as scopes would conclude that a credential confined to
one bucket could act on every bucket. Account-wide is rendered `*` everywhere a human or a client
sees it, and only becomes DO's empty-bucket form on the wire, because a blank field reads as a
missing one in a role definition or an audit record.

## Why prefix-scoped S3 credentials are NOT built, and what would change that (2026-09-15)

Asked directly: can a client request a Spaces credential confined to an object-key prefix it
supplies, so one customer's key cannot reach another customer's data inside a shared bucket? Not
built, on three separate grounds — any one of which is sufficient, which is why this is a decision
rather than a backlog item.

**DigitalOcean has no prefix vocabulary.** The spec's `grant` schema is exactly `bucket` +
`permission`, both required, and nothing else — no path, no resource pattern, no condition block.
The finest grain a Spaces key has is one whole bucket, and `fullaccess` is not even that (it is
account-wide whichever bucket it names, which is what `checkGrantPrivilege` refuses). There is
nothing to send, so no amount of plugin work produces a prefix-scoped Spaces key.

**A client-supplied prefix is not an isolation boundary.** If the caller names the prefix, the same
token and the same role can name a different one on the next call, so the result is a convention
rather than a control. Isolation requires that something *authorizes* the choice, and that something
is necessarily server-side: the role, or the ACL path. The OpenBao-idiomatic form is role-per-
customer plus a templated policy (`…/creds/customer-{{identity.entity.name}}`), which makes the
boundary an authorization fact and needs no new plugin surface at all. This is also why no plugin
here takes a privilege-narrowing request field: `creds/<role>` accepts `role`, `credential_kind`
(a parse-shape pin) and `shard_key` (affinity), none of which can widen or narrow privilege.

**Where prefixes are genuinely wanted, AWS already does it with no code change.** `inline_policy`
and `policy_arns` on an AWS role become STS **session policies**, which can only intersect — so
`arn:aws:s3:::bucket/customers/acme/*` on a per-customer role is the whole feature, today. The other
S3 backends are bucket-scopable at best (Exoscale, Linode) or coarser (OVH per-user, GCS per-SA).
Prefix scoping is a property of clouds with a policy language, not of the `s3_credentials` kind.

Two conditions would reopen it, and only these two:

1. **DigitalOcean adds a prefix or condition to `grant`.** Then the question is worth re-asking from
   scratch — including whether a role should carry a template with a constrained request-supplied
   substitution, which is the only client-supplied form that is not privilege self-selection. Such a
   design also needs a `pkg/plugintest` assertion that a request can never *widen* a role, and
   `metadata.scope` reporting the resolved value rather than the template, or an audit record would
   not say what was issued.
2. **Bucket-per-customer becomes acceptable.** The isolation unit on DO *is* the bucket, so this
   works now — bounded by **100 buckets per account** (raisable by support, but binding before the
   200-key cap, and buckets cannot move between accounts so sharding an existing estate is no
   lever). Fine for tens of customers; orders of magnitude short of the driving figure in
   [`object-storage-credential-audit.md`](object-storage-credential-audit.md), which is why that
   audit's per-customer verdict rests on quota alone.

## Why reconciler ids carry their credential class (2026-09-15)

`pkg/reconciler` moves opaque ids between a lister and a registry, which is the right shape — but
it means the two classes are indistinguishable to it. So both sides speak `token:<id>` and
`spaces_key:<access key>`, and `/reconcile`'s `found` list now reports those class-prefixed ids
(an operator-visible change).

Two independent reasons, neither cosmetic:

- `DeleteEntity` receives nothing but an id, and the classes are different endpoints. A bare id
  would have to be guessed at, and a guess deletes from an id space the credential may not belong
  to — which on a 404 reports success and leaves a live credential in place. An unclassed id is
  therefore **refused**, not defaulted to a token.
- Ownership is decided by membership of a set. The id spaces are independent, so the same string
  can name a live credential in one class and an orphan in the other; one key space would let a
  tracked token shield a Spaces key from reclamation forever.

**A class that cannot be listed warns and is skipped; only a pass where *every* class failed is an
error.** That asymmetry is the point rather than laxity: on real DigitalOcean `GET /v2/tokens` is
fenced, so an all-or-nothing pass would disable orphan reclamation for Spaces keys — the class
that works, and the one that needs it most, since a Spaces key has no upstream expiry and counts
against a per-account cap until something deletes it. Skipping is safe in the direction that
matters: an unlisted credential is never nominated for deletion, so a partial listing can only
under-reclaim. Every class failing is different — then the pass has learned nothing, and an empty
listing would be indistinguishable from an empty account.

## Why the conformance registry has variants, not one subject per plugin (2026-09-15)

One plugin now serves two credential types that share nothing the shared suites assert: different
endpoint, credential kind, scope kind, secret type, tracking prefix, revoke, and mint-refusal
knob. A harness declares one of each, so a single `do` entry would have exercised the lease
contract, the owner-tag invariant and the error taxonomy for the type that **cannot** be minted
against real DigitalOcean and not for the type that can. `do-spaces` is therefore a second
subject drawn from the same `Factory`, and the same reasoning applies to `e2e/`. Nothing about the
categories changed; what changed is what counts as a subject.

The third credential type, a day later, needed no new argument: `do-spaces-rotated` registered by
the same rule, and it is the one that would have been hidden worst — its lease is non-renewable, its
revoke deletes nothing, and a read re-serves rather than mints, so a single `do` entry would have
asserted the opposite of all three about it and passed.

## Why a real-cloud recording is withheld until its secret is known (2026-09-15)

The recorder scrubs fail-closed and refuses to write anything bearing a registered secret, a
`dop_v1_` token, a uuid or an email — but it can only refuse what it has been *told*, and the
mint response's field names were the very thing the probe existed to verify. A response carrying
key material under a name nobody anticipated would have been scrubbed by key name at best and
written verbatim at worst, into a public repository.

So the mint's recordings are **held in memory** until the caller has decoded the response and
registered the actual values (`withhold()` / `release(secret, accessKey)`). Registration checks
the real string rather than a guessed shape, which is the only version of this that is not itself
an assumption. Two smaller things fell out of it:

- **An access key travels in the DELETE *URL***, which structural JSON scrubbing never sees, and
  it had also become part of the recording's filename. Id-shaped path segments are now collapsed
  in both.
- **The fail-closed gates return errors instead of calling `t.Fatalf`**, which is what makes them
  testable at all; `real_cloud_record_gate_test.go` exercises them with no credentials.

Because the Spaces recordings' *values* are the account's own and are redacted, fixture parity
cannot byte-compare them: `fake_parity_test.go` compares sorted `path: type` shapes instead. And
until a real run exists, the fake is pinned to shapes written from DO's published spec — the
lesser of the two checks, explicitly labelled as such in the test.

## Why the Spaces listing pages, and why a partial one is an error (2026-09-15)

Found by re-reading DO's published spec rather than the notes taken from it — which is the check
still available with no credential, and it found the fake *and* the client wrong in the same way.
DigitalOcean paginates `GET /v2/spaces/keys` at `per_page=20` by default (max 200) and returns
`links.pages.next` plus a required `meta.total`. Both sides ignored all of it: the fake answered
every listing in one page, so the client's single unparameterised `GET` looked correct while against
real DO it would have seen **20 of up to 200** keys.

Three decisions came out of the fix.

**All-or-error, never a partial listing.** `ListSpacesKeys` walks every page and returns nothing at
all if the traversal cannot complete. This is the credential type where truncation does the most
damage: a Spaces key has **no upstream expiry**, so the owner-tag reconciler is the only thing that
ever reclaims a leaked one, and a key the listing omits is indistinguishable from a key that was
deleted — the reconciler reads it as *gone upstream* and stops tracking it, so it lives until
somebody finds it by hand, still consuming the account's cap. A listing *error* is the safe
direction, because a failed pass deletes nothing. The `spacesListMaxPages` bound (50 × 200) is a
runaway stop, and it errors rather than returning what it has, for the same reason.

**Pages are requested by number, not by following `links.pages.next`.** DO supplies a ready-made
URL and it is tempting to follow it. That URL comes from the response body, and the request carries
the *minter's* bearer token — following an upstream-chosen address would let a compromised or
misconfigured API walk the minter credential to a host of its choosing. The link's **presence** is
read as "more pages exist"; the address is always this client's own.

**The fake sorts before it pages.** Not cosmetic: paging over Go's randomised map iteration puts one
key on two pages and another on none, so a client that pages *correctly* would look broken
intermittently. Manufacturing a bug that belongs to the fake alone is the one failure a fake must
never have. Sorted on access key, the only field guaranteed unique.

The token listing beside it is deliberately **not** paginated, and says so in a comment.
`/v2/tokens` is absent from the spec (KI-009) and fenced for every PAT, so a page size and envelope
invented for it would be a shape nothing can ever verify — the opposite of what a fake is for.

Ordering note worth keeping, because it recurs: the client's paging test **passed vacuously** until
the fake was corrected, since the fake handed back all 45 seeded keys in one page. Fix the fake
first, then the client's test can fail honestly.

## Durability of an issued credential, and where orphans come from (2026-09-02)

Two questions that get asked separately and answer each other: is a credential durably tracked
before a client sees it, and how is an untracked one ever cleaned up.

### A client cannot receive a credential whose lease was not persisted

Verified in OpenBao's own source rather than assumed (`vault/expiration.go`,
`vault/request_handling.go` — v2.6.x):

1. The plugin returns `resp.Secret`.
2. Core calls `expiration.Register`, which builds the lease entry and calls `persistEntry` →
   `leaseView.Put(ctx, &ent)`. A **synchronous storage write**, under the per-lease lock, atomic
   with `updatePending`.
3. Only when `Register` returns does core set `resp.Secret.LeaseID` and let the response continue
   to the client.
4. If **anything** in `Register` fails, a deferred rollback routes a **Revoke** to the plugin,
   deletes the lease entry and removes the token index — then returns an error to the client.

So the ordering is guaranteed by core, for every plugin, and a failed lease write does not merely
leave the credential untracked: it actively revokes it. Nothing in this project needs to arrange
that, and nothing should try to.

The residual case is narrow and worth naming: the rollback is explicitly best-effort ("errors here
are ignored to do as much cleanup as we can"). If the lease write fails **and** the compensating
revoke also fails, the credential survives untracked and the client gets an error.

### The half core cannot help with

Core is only involved once the plugin has returned. Between the upstream mint and the plugin's own
`active-*/` tracking write there is a window core cannot see, and two things can go wrong in it:

| Failure | Recoverable? |
|---|---|
| The mint's HTTP response is **lost** (timeout, reset) after the cloud created the credential | **No** — the plugin never learned the id. Only owner-tag reconciliation can find it |
| The tracking write **fails** after a successful mint | **Yes** — the id is in hand, so the plugin revokes immediately. This is the only moment it can |

The second is a rule this project has always had and, until now, tested nowhere. It is now the
`revoke` category's `TrackingWriteFailureRevokesUpstream`, declared per plugin via
`Harness.TrackingPrefix` and asserted on all six hard-revoke clouds: storage is wrapped so writes
under that prefix fail, and the case requires the response to be an error AND the upstream count to
return to its baseline. Skipped where revoke is soft or absent (AWS, GCP, OVH, OCI) — there the
credential self-expires, so an untracked one is harmless and the write is metrics-only.

Adding it caught something worth recording about the prefixes: they are **not uniform**.
`active-tokens/` on DO, UpCloud, Azure and Exoscale; `active-users/` on Vultr; `active-clients/` on
Akamai. Declaring the wrong one produces a Put that succeeds and a green test that asserts nothing —
which is why the field is per-harness rather than a shared constant, and why it was briefly
mistaken here for two plugins being defective.

### Why the reconciler is the backstop and not the primary mechanism

The first row above is irreducible: minting and recording cannot be one operation, so a lost
response always loses an id. That is what the owner-tag scheme is for, and what shapes it:

- every credential's **name** carries this mount's owner prefix, so an orphan is attributable
  without any local record;
- the reconciler deletes only what matches that prefix and has no local entry;
- a **confirmation hold** protects the ordinary case — an entity younger than the hold, or whose age
  cannot be established, is skipped, because it may be a credential still inside its
  create-then-track window. Fail-closed by construction: an unknown `CreatedAt` is never deleted.

So: core guarantees the lease, the plugin guarantees the tracking record or revokes, and the
reconciler mops up the one case neither can — periodically, conservatively, and only for credentials
it can prove are ours.

## Why a minter set also scales past a per-account credential cap (2026-09-03)

Several clouds limit how many credentials one account may hold at once. OCI allows **two** auth
tokens per user, which is why that cloud uses phased rotation instead of JIT at all; AWS allows two
access keys per IAM user, which is why minter rotation there needs a grace-period sweep rather than
a create-then-delete. A cap that is low but not crippling is a third case, and it has an answer the
design already contains: each minter's cap is its own, so a set of *M* minters has a ceiling of
(limit × M).

What was missing is for selection to know it. Without that, issuance fails when the *preferred*
minter is full even though a sibling has room — and it fails for whoever asks next rather than for
whoever is holding the credentials.

`pkg/mintercapacity` supplies the count and selection acts on it: a minter at its limit is passed
**over**, and the next in affinity order serves. That makes capacity a third reason to add a minter,
beside redundancy and rate-limit sharding — all three point the same way, which is convenient.

**When every minter is full the code is `pool_exhausted`, not `upstream_auth_failed`.** The
distinction is the whole value of the feature at that point: nothing is wrong with the credentials,
and an operator told "auth failed" would rotate one and find it changed nothing. The message names
the usage (`minter-1=8/8 minter-2=8/8`) and the fix (add a minter, or wait for leases to expire).
`pool_exhausted` was already in the vocabulary for OCI's "every rotation slot is unavailable", and
the client's action is identical — retry later, or ask for capacity — so no code was added, per the
rule that a new code is only justified when a client would act differently.

**The count comes from our own records, not from the cloud.** An upstream listing would be
authoritative but costs an API call per issuance, against the very quota being conserved. So it
counts the `active-*/` tracking entries, which are written at mint and deleted at revoke. That
undercounts in two ways worth stating: it cannot see credentials created in the same account by
anything else, and it cannot see orphans whose tracking record was lost in the create-then-track
window. The real ceiling may therefore arrive earlier than predicted, which is why the cloud's own
refusal still has to be handled — this avoids wasted calls and enables the warning; it is not
authoritative.

**The default is unenforced, and that is not laziness.** Most of these caps are undocumented. A
guessed limit would refuse issuance the cloud would have allowed, which is worse than not knowing —
so `minter_credential_limit` defaults to 0, nothing is counted at all in that case, and setting it
is how an operator opts in. The one cloud where a number is assumed is the private DigitalOcean
driver, at 8, pending confirmation from the vendor.

**The warning fires at 80%, not at the ceiling.** The remedy is adding a minter, which takes human
time; a signal that coincides with the failure is too late to be one. It is a log line rather than a
metric because plugin metrics reach nobody in this deployment (A12), and it names the minter and the
usage so the log alone is actionable.

## Why minter selection has affinity, and why rendezvous hashing (2026-09-02)

A minter set began as redundancy: several credentials so that one failing does not stop issuance.
It said nothing about WHICH minter serves a given read, and the answer was Go's map iteration
order — effectively random per request.

Random is wrong when the upstream meters per **account**. DigitalOcean limits requests per account,
so credentials minted by different accounts draw on separate budgets, and a set spanning accounts is
a way to multiply the throughput available to a fleet of workers. That only pays off if a worker's
requests land consistently on one account.

**Isolation is the larger half of the argument, not balancing.** With random selection every client
draws on every budget: one heavy client degrades all of them, and exhausting any single account
affects everybody. With stable affinity a client draws on one budget, so a heavy or misbehaving
client exhausts its own shard and the others are untouched. It is a bulkhead.

**Rendezvous (highest-random-weight) hashing, not `hash % N`.** Modulo reshuffles nearly every
client when the set changes size, and a set changes size for ordinary reasons — a minter retired,
rotated in, added for capacity. Rendezvous moves only about 1/N. It also yields a total ORDER rather
than one choice, which is what makes "best-effort" precise: a client prefers its own shard and falls
to its second preference when that minter is unhealthy or in a rate-limit cooldown —
deterministically, so the fallback is as stable as the primary. Affinity is a preference, never a
constraint, and redundancy is unchanged. Both properties are asserted numerically in
`pkg/minteraffinity`: 10000 keys over 5 minters land within 3% of an even share, growing 4→5 moves
about 20% of clients, and removing a minter moves *nobody* who was not on it.

### The key is the whole design, and the obvious choice is wrong

An OpenBao identity entity is shared by every client authenticating through the same auth role —
with AppRole the alias is the role id, so a hundred workers on one role are ONE entity. Keying on
`EntityID` would hash the entire fleet to a single minter and the feature would silently do nothing,
which is the worst kind of not working. So `minteraffinity.Key` prefers, in order:

1. an explicit `shard_key` on the request — the only reliably per-worker option, and stable for
   exactly as long as the caller wants;
2. the **client token accessor** — one token per worker is the ordinary shape, so this is per-worker
   in practice. The accessor, not the token, which is a secret. Semi-stable: re-authenticating moves
   a worker to another shard, which costs a budget migration and nothing else;
3. the entity id, coarse but better than nothing;
4. nothing — in which case the order is **randomised**, not fixed, because concentrating every
   keyless caller on one minter would be worse than the behaviour this replaced.

### Whether it multiplies anything is a per-cloud fact, and on three clouds it does not

Affinity chooses a *minter*. Whether that gives the client a separate rate-limit budget depends on
where the issued credential's **identity** comes from — and the plugins divide in two, which is
verifiable from the mint call rather than a matter of opinion:

**A correction, and the reason to distrust the rest of this table.** It was built by reading each
mint call to see where the credential's identity comes from. That answers **ownership**, and I used it
to answer **metering** — which are different questions, as a measurement then showed.

Measured on DigitalOcean 2026-09-03: two credentials minted from ONE account, 25 requests spent on the
first, and the second's counter fell by **one** — its own request. The public API meters **per token**,
at 5000/hour each. So a DigitalOcean credential is *owned* by the minter's account and *metered* on
itself, and affinity does not multiply a client's throughput there at all. The row below said it did.

Every "Yes" that has not been measured is therefore an inference of the kind just refuted, and should
be read as "unknown, and probably worth checking the same way": mint two credentials from one minter,
spend one, read the other's counter.

| Cloud | The mint call | The credential's identity is | Does affinity multiply the client's quota? |
|---|---|---|---|
| **DigitalOcean** | `POST /v2/tokens` | the minter's account | **No — measured.** Metered per token (5000/h each), so a client's throughput is not account-limited |
| UpCloud | `POST /1.3/account/tokens` | the minter's account | Unknown (was inferred "yes") |
| Vultr | `POST /v2/users` (sub-user) | a sub-user of the minter's account | Unknown (was inferred "yes") |
| OVH | OAuth2 `client_credentials`, `MintToken(ctx)` — no target argument | the minter's own OAuth client | Unknown (was inferred "yes") |
| Exoscale | `CreateAPIKey(ctx, name, role.RoleID)` | the minter's organization; `role.RoleID` only *scopes* it | Unknown (was inferred "yes") |
| Akamai | `CreateClient(ctx, name, apiAccess, groupAccess)` | an API client under the minter's contract | Unknown (was inferred "yes") |
| **AWS** | `AssumeRole{RoleArn: role.IAMRoleARN}` | **the target role, named on the ROLE** | **No** |
| **GCP** | `GenerateAccessToken(ctx, role.ServiceAccountEmail, …)` | **the impersonated SA, named on the ROLE** | **No** |
| **Azure** | `AddPassword(ctx, role.AppObjectID, …)` | **the app registration, named on the ROLE** | **No** |
| OCI | phased rotation — no minter is selected at issuance | the OCI user the slot was provisioned for | N/A |

On the bottom three the minter only *authorises* the operation; every credential a role issues has
the same identity whichever minter minted it, so two clients on two minters draw on one budget. No
key, and no set composition, changes that. Getting a second budget there means a second **role**
pointing at a second target identity, and then the client chooses it by asking for that role —
which is ordinary configuration, not affinity.

Affinity is still not pointless where it does not multiply a client's quota, and after the
DigitalOcean measurement this is most of its value rather than a footnote: it spreads the
**mint-time** calls — `AssumeRole`, `generateAccessToken`, Graph `addPassword`, DigitalOcean's
`CreateToken` — across minters, and those are metered too. On DigitalOcean the minting side is
10000/hour on the private console API and demonstrably shared across sessions, while each issued
credential gets its own 5000/hour. So the ceiling affinity raises is **issuance rate**, not worker
throughput.

That is a smaller claim than the feature was introduced with, and worth restating plainly: at roughly
two calls per issuance (mint plus revoke) a single minting budget of 10000/hour caps a mount at a few
thousand issuances an hour, and more minters raise that. The isolation argument is unaffected — a
heavy client still exhausts its own shard of the minting budget rather than everybody's.

### What it cannot do

It multiplies nothing if the set's minters share an account: two credentials in one account draw on
one budget, and no hashing changes that. There is no portable way to check — an account is not a
concept the cloud-agnostic layer has — so it is a property of how an operator populates the set, and
a foot-gun worth stating rather than hiding.

### Why it is in conformance

Nine plugins wire selection individually, and the failure mode of getting it wrong is **silence**: a
plugin that drops the key, or ignores the order, serves every request correctly from one minter and
looks perfectly healthy. `lease/MinterAffinityPinsAClientAndSpreadsTheFleet` catches both — one key
must reach one minter across repeated reads, and twenty keys must reach more than one. It needs a
two-minter set (`Harness.WriteSetWithMinters`), so a harness that cannot write one skips rather than
passing vacuously.

## Why a thin uniform-envelope plugin per cloud (not one super-plugin, not pure SDK wrappers)

Considered three approaches:

1. **One super-plugin** with a cloud-selector field. Rejected: a panic in any cloud's code would take down credential issuance for all clouds, and the binary would link every cloud's SDK (large surface, much larger blast radius for a CVE in any one SDK).
2. **Pure cloud SDK wrappers, no envelope.** Rejected: clients have to branch on cloud type to parse responses, which defeats the entire goal.
3. **Thin per-cloud plugin behind a uniform envelope.** Chosen. Plugin failures are isolated by OS-level process boundary (OpenBao plugins run as separate processes); each binary links only its own SDK; clients dispatch on `cloud` only when they actually need cloud-specific keys, not for envelope fields.

## Why minter validation is `(≥1 never_expires) OR (≥2 with ≥7d gap)`

Two failure modes drove this rule:

- **Single expiring minter** — when it expires, credential issuance stops. The plugin can't seamlessly rotate to a different minter because there isn't one. Rejected at config load.
- **Two expiring minters that expire close together** — both could expire in the same operator-attention window, defeating the point of having two. Rejected unless the gap is ≥7 days.
- **`never_expires=true` as escape hatch** — relaxes both rules because a permanent fallback by definition doesn't run out. The expectation is operators set this only for credentials that genuinely don't expire (e.g., AWS IAM access keys absent organizational rotation policy). A Prometheus alert on `expires_in_seconds < 14d` doesn't fire for `never_expires` minters, so onboarding review must catch any abuse.

## Why metrics are keyed on `entity_id`, not OpenBao role name

The metric exists to answer "is this cloud entity safe to delete?" — that's a question about a cloud entity, not a logical role. The same cloud entity (e.g., a single IAM role ARN) can back multiple OpenBao roles with different scopes. Keying on the OpenBao role would make a stale metric for one role hide active use through another, leading to deletion of an entity that's actually in use.

So `entity_id` is the cloud-side identity an operator might delete:
- AWS: IAM role ARN being assumed (via STS)
- GCP: SA email being impersonated
- Azure: parent app registration (NOT the per-lease client secret)
- DO: the minter PAT (NOT the per-lease minted token)
- UpCloud / Exoscale / Vultr / Akamai / OVH: the minter credential (NOT the per-lease issued credential)
- OCI: the user whose auth-token slots are rotated

## Why per-node metrics with eventual consistency, not single-writer

OpenBao plugin storage writes go through raft consensus. A naive "every read writes a `last_access_at` timestamp" design would put raft consensus on the credential-issuance hot path — unacceptable both for latency (50–200ms per write in multi-cloud topologies) and for write amplification.

Instead each plugin instance accumulates accesses in memory and flushes a per-node-tagged keyspace every 15 minutes. Conflict-free — each node owns its own keyspace. The query API merges across nodes and reports a `staleness_seconds` field so callers know how fresh the answer is. This trades strong consistency for one cheap raft write per node per flush interval.

## Why phased rotation (rather than a credential pool, or pure JIT for everything)

Considered three approaches for clouds without native short-TTL primitives:

1. **JIT for every cloud** — would work for DO, doesn't work for clouds whose token-creation API is rate-limited, slow, or absent. Doesn't generalize.
2. **Credential pool** (M pre-provisioned credentials, hand out the next available) — solves rate limits but the TTL semantics are dishonest: a pool credential has the same lifetime as the longest-lived item in the pool, not the time until it's rotated out.
3. **Phased rotation** — N slots, each rotated on schedule with phase offsets so ages stagger across [0, T). Read handler hands out the freshest slot; the lease's `expires_at` is exactly that slot's next-rotation time. TTL is honest, no rate-limit risk on the hot path, and rotation is fully scheduled.

Phased rotation is essentially a pool with rotation discipline, where the discipline is what makes the TTL honest.

## Why DO is the reference implementation (not AWS)

DO is the simplest cloud that exercises every load-bearing piece of the design:

- Has a JIT-capable native API (`POST /v2/tokens`) — **refuted twice over**; see the 2026-08-21 corrections below. The endpoint is undocumented *and* refuses PAT authentication (KI-009), so DO cannot in fact mint headlessly
- Has revocation (`DELETE /v2/tokens/{id}`) — same endpoint family, same refusal
- Has no native short-TTL primitive (so the plugin owns the TTL contract)
- The cloud SDK is small
- Test accounts are cheap

It was chosen as the reference precisely because it owns the full lifecycle (envelope, lease tracking, recovery, reconciler, metrics) with nothing delegated upstream — every load-bearing piece gets exercised.

> **Correction, later on 2026-08-21 (supersedes the correction below):** a real-account probe found `POST /v2/tokens` refused at DigitalOcean's **edge gateway** for a full-access PAT, not merely for a scoped one — the path is not open to bearer-token auth at all (KI-009). So the first bullet is not "overstated", it is false: DO has no headless JIT-capable API. DO stays the reference for the *code shape* and as the origin of the DO fake, and it is no longer presented as production-viable; the reasoning is in [Why `credential-do` stays the reference implementation even though it cannot mint](#why-credential-do-stays-the-reference-implementation-even-though-it-cannot-mint) below.

> **Correction (2026-08-21):** "Has a JIT-capable native API" overstated the case. DO's `POST /v2/tokens` / `DELETE /v2/tokens/{id}` are **not public documented API** — DigitalOcean's public OpenAPI spec has no `/v2/tokens` path and DO documents PAT creation as control-panel-only, so the reference implementation depends on a control-panel-internal endpoint with no stability contract. Notably, `docs/object-storage-credential-audit.md` rejected DO Spaces *for exactly this reason*; the two positions were inconsistent. We keep DO as the reference — the endpoint works, it is what the control panel itself uses, and the documented OAuth alternative needs interactive authorization so cannot mint headlessly — but the dependency is now stated wherever the endpoint appears, and verifying it is the first item of the deferred real-cloud pass (#7). Full findings: [`docs/do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md).

> **Correction (2026-05-30):** This section originally argued AWS was a poor reference because "most of the credential lifecycle is delegated to the upstream OpenBao `aws` engine." That premise turned out false — OpenBao's AWS engine only supports IAM-user `iam_tags` (no STS `session_tags`), and there is no OpenBao GCP or Azure engine at all. As a result AWS/GCP/Azure were built as full JIT plugins calling the cloud APIs directly, with the same lifecycle machinery as DO. DO remains the reference for being the simplest, but the "delegate to upstream engine" distinction no longer applies to any cloud. See `docs/cloud-credential-research.md`.

## Why minter sets (named, role-bound) rather than one flat minter list per cloud

The original model had a single per-cloud minter list in `config`, and any role drew from any healthy minter (the multiple-minter mechanism existed only for rotation/failover). That forces **one maximally-privileged minter per cloud**, which breaks down for three reasons:

- **Capability separation is real on some clouds.** An Azure service principal authorized to manage app registration A (via `addPassword`) typically has no rights on app B; Akamai/Linode API-client creation is scoped per group/contract. Different role classes genuinely require different privileged minting credentials — a single minter cannot mint them all.
- **Operational separation.** Operators want discrete minting credentials per purpose (e.g. a backup-issuing minter distinct from an admin-issuing one), rotated and owned independently.
- **Audit provenance.** When an issued credential is misused, you want to trace which minting credential produced it.

So minters are grouped into named **sets** (`minter-sets/<name>`), each independently validated by the OBC-006 rule, and every role carries a **required** `minter_set`. Issuance mints only from the bound set — deliberately **no cross-set failover**, because the whole point is isolation: a compromise or misconfiguration of set A's minters cannot issue set B's credentials. The issuing set+minter are stamped into `metadata.minter_set`/`minter_id` (which bumped the envelope to api_version 2) and lease internal_data. The reconciler is the one exception: it cleans orphaned upstream entities across all sets by owner-tag, since orphan cleanup is a mount-wide safety property, not a per-role one.

Operators achieve least-privilege by granting each set's minters only the upstream rights its bound roles need. For capability isolation without sets, multiple mounts *look* like an alternative — but **do not point two mounts at the same cloud account** until the owner tag carries a mount identity (A19 in [`audit-2026-08-22.md`](audit-2026-08-22.md)). The reclaim filter is the bare `cloud-creds-` prefix while the "known" set is a per-mount storage view, so each mount sees the other's **live** credentials as orphans and deletes up to ten per pass, silently. Minter sets keep the isolation inside one mount, make provenance first-class, and avoid that entirely.

## Why revoke tolerates a missing issuing minter and an already-deleted credential (KI-002)

Hard-revoke plugins delete the upstream credential on lease revoke using the
minter that issued it. Two cases broke this: (a) the issuing minter was removed
from its set after issuance (re-seed), so the plugin could not build a client to
delete; (b) the credential was already deleted (double revoke), so the upstream
delete returned 404. Both previously returned errors, which OpenBao retries
forever.

Decision: (a) revoke falls back to any healthy minter in the same set, and if
none remains, treats revoke as a successful no-op (logged); (b) a 404/not-found
on the upstream delete is treated as success. This weakens the "revoke always
performs the upstream delete" property in these edge cases, which is acceptable
because the real guarantee is TTL expiry — every issued credential has a bounded
lifetime. A clean no-op lets the lease release rather than accumulating infinite
failed retries.

## Why a strict golangci-lint v2 config (the "slow-accretion" smell set)

The repo adopted a deliberately strict `.golangci.yml` (v2, ~20 linters:
complexity — gocyclo/gocognit/cyclop/funlen/nestif/maintidx; magic-numbers and
repeated-literals — mnd/goconst; duplication — dupl/gocritic; dead/comment-rot —
unused/unparam/ineffassign/wastedassign/godox/godot/predeclared; plus a tuned
revive ruleset), pinned to golangci-lint v2.13.1 and run per-module in CI.

Decision: enforce it across every module with zero `//nolint` suppressions.
Rationale: with one plugin per cloud and ten near-parallel plugins, the failure
mode is *drift* — a helper that subtly diverges, a magic number that means
something different in one cloud, copy-paste that rots. The complexity and
duplication linters fire on exactly that drift, which is what pushed the
genuinely-shared code into `pkg/` (telemetry, localexpiry, ownertag) instead
of ten copies. The no-nolint rule is load-bearing: when a linter fires, the fix
is to restructure (extract a helper, name a constant, drop a dead param), not to
suppress — suppressions are where drift hides. Carried-forward exceptions live
in the config itself (not inline), e.g. the `(io.Closer).Close` errcheck
exclusion and `revive`'s disabled `unused-parameter`/`unused-receiver` for the
SDK-mandated handler signatures. Test files are excluded from the
complexity/literal linters (test code legitimately repeats literals and is
structurally loose).

## Why minter rotation retires with a grace period instead of deleting immediately

> **Corrected 2026-08-22 (A29).** The paragraph below originally justified the grace
> with "the other nodes keep the old minter in their in-memory snapshot", which
> describes a model OpenBao OSS does not have: only the ACTIVE node loads the mount
> table and runs a backend, and standbys forward requests rather than serving them,
> so there is never a second live backend holding a stale snapshot. The grace is
> still right, for the failure that CAN happen — see the corrected reasoning
> immediately below. The conclusion did not change; the reason it rests on did.

Minter sets are loaded into memory only at `Factory` construction and on a
minter-set write — there is no periodic reload. **One backend instance is live at a
time** (the active node's), so the hazard is not a peer with a stale snapshot; it is
*the same mount at a different moment*, and a stale actor that has not yet noticed
it is no longer the one in charge:

- **Failover.** The new active node builds a fresh backend from storage. Any
  in-flight issuance on the outgoing node was using the minter that storage no
  longer names, and a lease whose credential was minted by it still has to be
  revocable — with a minter the new node can also reach.
- **A partitioned former leader.** Raft stops its *storage* writes, not its
  outbound HTTPS. A worker tick that began before it lost leadership keeps talking
  to the cloud, using whatever set it last loaded. Deleting the retired credential
  the instant the successor is swapped in makes those calls fail against a
  credential that no longer exists, and there is no fencing token in the plugin API
  to stop them.
- **The operator's own copy.** A minter is frequently pasted into a set from a
  password manager or a Terraform variable. An immediate upstream delete means a
  mis-typed successor leaves the operator with two dead credentials instead of one
  live one.

If rotation deleted the old upstream credential the moment it minted and swapped in
the successor, each of those becomes an unrecoverable wedge rather than a slow
handover — the KI-001 class of "the surviving actor holds stale config" failure.

Decision: rotation is grace-separated. `RotateMinter` mints the successor,
validates the prospective set, health-checks the successor, swaps it in, and
marks the old minter retired by stamping `RetiredAt` — but does **not** delete
the old upstream credential. A separate retired-sweep deletes the upstream
credential only after `minter_retire_grace` has elapsed (default 7d, which must
exceed the worst-case node-reload interval). The retired minter is excluded from
new-issuance selection (`selectMinter` skips it) and from set validation
immediately, so it stops being a live issuance path at once, but it stays
upstream-alive for the grace window so stale-snapshot nodes can keep minting
until they reload. The sweep is keyed off `RetiredAt`, deliberately separate
from the conservative owner-tag orphan reconciler.

## Why role TTLs are bounded at write time, and why OVH roles are pinned to exactly 1h

A lease TTL is a promise about a credential. The plugin can keep that promise two
ways: ask the cloud for a credential whose native lifetime *equals* the TTL
(AWS `DurationSeconds`, GCP `lifetime`, Azure `endDateTime`, UpCloud `expires_in`),
or hard-revoke at lease end (DO, Exoscale, Vultr, Akamai). Where the cloud offers
neither, the TTL is unenforceable — and an unenforceable TTL is worse than an
error, because the operator believes a credential died when it did not.

Decision: reject at role-write time any TTL the cloud cannot honour, rather than
accept it and diverge at issue time.

- **Upper bounds** (AWS 43200s, GCP 43200s, UpCloud 8760h, OVH 3600s) turn a
  guaranteed upstream 4xx at read time into a clear config error at write time.
- **Lower bounds** exist only where the cloud has a documented minimum (AWS STS:
  900s) or where a shorter TTL would be *dishonest* (OVH). We do **not** invent
  floors for clouds that document none — Azure, GCP, UpCloud, DO, Exoscale, Vultr
  and Akamai all honour arbitrarily short TTLs, either by shortening at mint or by
  revoking.
- **OVH is pinned to exactly 3600s.** Its OAuth2 token endpoint takes no lifetime
  parameter (tokens are a fixed hour) and OVH publishes no token-revoke API, so
  *neither* mechanism is available. `default_ttl=15m` used to end the lease at 15
  minutes while the token stayed valid for the remaining 45 — with the envelope's
  `expires_at` (the token's real expiry) contradicting the lease. Since the only
  TTL OVH can honour is 1h, that is the only TTL a role may declare.

The same reasoning drove making Azure and UpCloud leases non-renewable: both fix
the credential's expiry at mint and cannot extend it, so renewing granted a lease
that outlived its own credential. Refusing renewal (as AWS/GCP/OVH/OCI already
did) keeps the envelope's `renewable` field truthful.

OCI is the deliberate exception in the other direction: phased rotation means a
slot's token outlives the lease until its scheduled rotation. The lease never
overstates validity — TTL is clamped to the time until that slot's next rotation —
but the credential is not destroyed at lease end. That is the accepted cost of the
only strategy OCI's 2-token-per-user quota permits. Full matrix in
`docs/ttl-semantics.md`.

## Why minter capability is probed, not inferred (and why probes default on)

A health check answers "is this credential live?"; issuance needs "may this
credential mint what this role asks for?" No cloud in scope lets us ask the
second question directly:

- **No introspection.** DO has no scope-introspection API (scopes are fixed at
  creation and never reported back). UpCloud does not report `can_create_tokens`
  on the account endpoint. Akamai's `GET /api-clients/self` reports grants, but
  what a client may *delegate* is a separate matter.
- **The health call is deliberately unprivileged.** AWS answers
  `sts:GetCallerIdentity` for any valid signature — no policy needs to permit it
  — so it cannot fail for a permissions reason. GCP's self-signed-JWT exchange
  proves only that the minter SA's own key is live; impersonation is
  `roles/iam.serviceAccountTokenCreator` **on each target SA**.
- **The privilege is per-role, not per-minter.** Azure `addPassword` needs
  ownership of *that* app registration; Vultr refuses to grant a sub-user an ACL
  the creating key lacks; Exoscale must be allowed to grant *that* role-id.

Considered inferring capability from a role/scope comparison instead of calling
the cloud. Rejected: it means reimplementing each cloud's authorization model
locally, and being wrong in the permissive direction produces exactly the bug we
are trying to prevent (a config write that passes and a credential read that
403s). The only trustworthy oracle is the cloud itself.

Decision: probe by minting. Create a credential with the same request shape a
real issuance would use, then delete it — at minter-set write, at role write, and
before a rotation commits.

**Default on.** The failure this prevents is silent (a healthy-looking minter),
delayed (until the first read), misattributed (it lands on a caller, not on the
operator who caused it), and hard to diagnose from the far end (an upstream 403
with no local explanation). A verification that is off by default would be
enabled exactly by the operators who already know the failure mode. The cost is
one throwaway credential per distinct `(minter, mint shape)` at configuration
time, which is bounded and paid on a cold path. `verify_minter_capability=false`
is the escape hatch, and it is named in every rejection message so a probe that
cannot succeed in a particular environment is not a dead end.

**Probing at role write is not just symmetry.** It stops an operator defining a
role whose minting key is unsuitable, and its side effect is deliberate: a minter
set must exist and demonstrably work before roles can bind to it, which pins the
configuration order (`config` → `minter-sets` → `roles`) instead of leaving the
sequence to chance.

**Every active minter is probed, not one.** Minter selection picks arbitrarily
among a set's selectable minters, so a single incapable minter makes issuance
fail *intermittently* — the harder failure to diagnose — rather than not at all.

## Why probe cost is accepted on the three clouds that cannot revoke

AWS, GCP and OVH cannot revoke what a probe mints (STS sessions, access tokens
and OVH OAuth2 tokens all expire on their own and have no revoke API). A probe on
those clouds therefore *leaves a credential in existence that nobody holds*.

Decision: accept it, and bound it by asking for the shortest lifetime the cloud
accepts — AWS's documented 900s floor, 60s on GCP, and OVH's fixed 1h (no choice
there). The probe credential is never returned to a caller, never recorded in a
lease, and (where the cloud names credentials at all) carries the owner-tag
prefix. The alternative — skipping verification on precisely the clouds whose
health checks are the *least* informative (`GetCallerIdentity` requires no
policy; GCP's health call cannot see impersonation grants at all) — would leave
the biggest gap unverified. Operators for whom even a 900s unheld session is
unacceptable turn probes off explicitly.

For the same reason, a *failed delete* never fails a probe on the revocable
clouds: minting was what was being proved, and the probe credential's name
carries the `cloud-creds-<role>-probe-` owner prefix, so the owner-tag reconciler
reclaims it (probes are never recorded in lease tracking, so they are orphans by
construction).

## Why OCI is not capability-probed

OCI caps a user at **two** auth tokens. That cap is the entire reason the OCI
plugin uses phased rotation rather than JIT. A probe would have to consume one of
those two tokens, so it would either fail in the steady state (both slots already
provisioned) or, worse, succeed by displacing a slot a live lease is drawing
from. Verification would break issuance in order to prove issuance works.

Decision: OCI's checks return `capability.ErrUnsupported`, which `Verify` counts
as *skipped* rather than failed — the set/role write proceeds and the
operator-facing log records the skip. The uniform hooks still exist on the OCI
plugin (including the shared precondition that a named minter set must exist
before a role binds to it), so the surface stays uniform across all ten plugins;
only the probe itself is absent. OCI also needs it least: slot provisioning is
itself a real `create-auth-token` call made at role-write/rotation time, so an
incapable minter already surfaces as a failed provision to the operator who
configured it — which is the outcome probes buy elsewhere.

## Why an Akamai rotation successor inherits the incumbent's grants verbatim

Akamai's rotation successor is a *new api client*, not a new credential for an
existing one, so its grants have to be stated at creation. The first
implementation constructed an Identity-Management-only grant — enough for the
successor to manage api clients, and therefore enough to rotate again — which
quietly narrowed the minter on every rotation: after one rotation the set's
minter could no longer delegate the `apiAccess` its bound roles hand out, while
still passing `GET /api-clients/self` forever.

Decision: read the incumbent's own `apiAccess`/`groupAccess` (`GetSelf`) and
replicate them onto the successor, upgrading only the Identity Management api to
READ-WRITE so the successor can rotate in turn. If the incumbent's own grants
cannot be read, the rotation **fails closed** rather than falling back to a
constructed grant — a successor with unknown grants is exactly the thing being
prevented. `rotation_params.group_id` remains an explicit override for the case
where the incumbent reports no group access of its own.

This is also the sharpest case for the pre-commit capability probe: the copy can
still come back narrower than the incumbent (a group the authorizing user has
since lost, an api removed from them), and only a probe mint detects that before
the successor is swapped in.

## Why a runtime `minter_insufficient_privilege` error code was NOT added

The companion proposal was to distinguish a privilege 403 seen at *issuance* time
with a new `minter_insufficient_privilege` error code, and to stop such a 403
dragging the minter's recovery state machine to `AuthFailing`.

Decision: excluded from this work. Two reasons. It is a **spec change** — a new
`error_code` is a contract change for every client and requires a techrfc
revision, which is explicitly out of scope for a verification feature. And probes
largely remove the need: the privilege gap is now diagnosed at configuration time
by the operator who caused it, leaving a runtime privilege 403 as the residual
case of a privilege revoked upstream *after* configuration.

The residual behaviour is therefore unchanged and conservative-but-blunt: such a
403 maps to `upstream_auth_failed` and counts toward `AuthFailing`, withdrawing a
minter that is live but unusable for *this* role and may still be usable for
others. That remains an open refinement, recorded here so it is not mistaken for
a closed gap.

## Why cloud-agnostic tests live in one conformance table, not ten plugin files

Ten near-identical plugins mean every invariant is stated ten times. That is
survivable for *behaviour* (a shared `pkg/` helper fixes it) but not for *tests*:
a missing test looks exactly like a passing one, so coverage drifts silently and
per-cloud regressions accumulate one plugin at a time. The historical evidence is
in this repo — KI-001 (config not reloaded in `Factory`) turned out to affect 7
plugins, not the 1 it was reported against, and the reload suite that caught it was
`t.Skip`ped on 3 plugins for a reason nobody was re-reading.

Decision: every invariant that is *about the plugin's own state* — persist,
refuse, not-persist, not-delete, survive reload, tolerate double revoke — is
written once in `pkg/plugintest` as a suite parameterized by `plugintest.Harness`,
and applied to all ten plugins from a single `registry` table in the test-only
`conformance/` module. `pkg/plugintest` still imports no plugin (every plugin
imports it), so `conformance/` is where the two meet; being test-only, it does not
weaken per-plugin module isolation. Five categories today: `reload`,
`perturbation`, `revoke`, `capability`, `reconciler-safety`.

Three properties are load-bearing, and each is enforced by a test rather than by
convention:

1. **Registration is mandatory.** `TestEveryPluginIsRegistered` reads `../plugins`
   from disk and fails in both directions, so a new plugin cannot ship without
   entering the table.
2. **Every category is applied to every plugin.** `ValidateHarness` fails a
   harness that neither wires a category's required fields nor declares it in
   `Harness.Skips`. Adding a category therefore cannot land half-applied: it must
   be wired or explicitly waived on all ten.
3. **Gaps are declared, not buried.** A category that genuinely does not apply is
   `Harness.Skips[category] = "<why, about the cloud>"`, printed by
   `TestConformanceMatrix` as one reviewable line. An empty reason is rejected.
   There are five such gaps and each is a fact about the cloud — aws/gcp/ovh
   reconcile prunes only local tracking entries (`pkg/localexpiry`) because an STS
   session, an impersonation token and an OAuth2 token are not listable upstream
   entities; OCI cannot be capability-probed (2-token cap) and its in-process fake
   cannot plant a foreign token.

What deliberately did **not** move: the cloud's own vocabulary. Mint shapes, ACL
and apiId strings, deny knobs on the fakes, and anything touching unexported
symbols stay per-plugin. A harness adapter reads as a translation of the cloud into
the shared vocabulary — `DenyMint`/`AllowMint` are just two function values —
which is what makes it possible to state the assertion once. This reverses the
earlier "not added" position in `docs/minter-capability-verification.md`, which
correctly observed that *making* a minter incapable is per-cloud but wrongly
concluded that the *consequences* were too.

A side effect worth its own note: the ten `resilience_test.go` files are deleted,
and the AWS/GCP/OCI reload skip is gone. Those three skipped reload only because
the old per-plugin harness re-ran `Factory` without re-injecting the fake client;
`Harness.Inject` is applied to every backend instance, including the reload, so the
skip was an artifact of the harness rather than a property of the cloud. Prefer
suspecting the harness over accepting a skip.

The philosophy is written up for future sessions in `AGENTS.md`, which is the file
to read before adding a test, a category, or a plugin.

## Why a non-renewable secret registers *no* `Renew` callback (rather than refusing inside one)

KI-005 stopped six plugins handing back a fresh TTL for a credential whose expiry
was fixed at mint, by making their `pathCredsRenew` return an error. That was the
right intent and the wrong mechanism, and the difference cost the client its
credential.

`framework.Secret.Renewable()` is defined as `s.Renew != nil`, and that value is
what `Response()` copies onto the lease. A registered callback that always errors
therefore still advertises `renewable: true`. Worse, OpenBao's expiration manager
treats a **failed renewal as grounds to revoke the lease** — so a client that read
the plugin's own advertisement and renewed had its credential hard-revoked on the
clouds that hard-revoke. Refusing politely inside the callback was strictly worse
than either honest alternative (KI-008).

Two fixes were available: drop the callback, or keep it and assign
`resp.Secret.Renewable = false`. Dropping it wins because the callback's absence is
the *single* source of truth the framework reads — there is no second field to
drift out of sync, and core refuses the renewal before any plugin code runs, so the
plugin cannot get it wrong at a later date. Each affected plugin keeps a comment at
its now-empty `framework.Secret` naming that cloud's reason (STS `DurationSeconds`,
GCP `lifetime`, OVH's fixed hour, Azure `endDateTime`, UpCloud `expires_in`, an OCI
slot's next scheduled rotation), because an empty struct literal invites someone to
"helpfully" add the callback back.

DO, Exoscale, Vultr and Akamai keep their callbacks: their credentials have no
upstream expiry, so renewal genuinely means "defer the revoke", which works.

The invariant is now fenced for all ten plugins by the `lease` conformance
category, which asserts the envelope and the lease agree — the two structures are
built in the same handler from the same inputs and nothing but a test keeps them
honest.

## Why AWS and GCP derive the lease TTL from the upstream expiry, not the role TTL

Both clouds return the expiry they actually granted (STS may grant less than the
requested `DurationSeconds`; the mint round trip itself consumes wall-clock). The
envelope published that real expiry while the lease was built from the role's TTL,
so a 900s lease could name an 899s credential — a lease outliving its credential,
which is exactly what techrfc OBC-002 forbids, and a client watching the lease
would keep using a dead credential for the difference.

The lease is now built from the same number the envelope publishes. A one-second
floor (`minLeaseTTL`) is applied deliberately: a zero `TTL` means "use the mount
default" to core, which for a near-expiry credential is the worst possible reading
of "expired".

This was found by the `lease` category within minutes of it existing, on the two
clouds whose expiry is echoed back by the API rather than chosen by the plugin —
which is a good argument for asserting agreement between structures rather than
asserting each structure separately.

## Why background workers start in `InitializeFunc`, not in `Factory`

`startWorkers` was reachable only from `pathConfigWrite` and `pathMinterSetWrite`,
so a backend that OpenBao built any other way — a plugin reload, a mount remount,
an unseal, a raft leader failover — served credentials perfectly while running no
health checks, flushing no metrics, sweeping no orphans, warning about no expiring
minters, and (on OCI) rotating no slots. Silent, and indefinite: nothing recovered
until an operator happened to re-write config (KI-007).

`Factory` looks like the obvious place and is not. It also runs for constructions
that must not touch the network — a config-less test backend, tooling — and this
repo has an explicit rule against a config-less backend reaching the real cloud
API (now that capability probes exist, that rule has teeth). `InitializeFunc` is
the hook core calls precisely once per backend instance, on the active node, after
mount setup / unseal / reload, with storage available. So `initialize` rehydrates
config and minter sets first and then starts the workers, and `startWorkers` still
early-returns on `b.config == nil` for the case where nothing has been configured
yet.

It must be idempotent, because an unseal after a reload calls it again; the
`reload` conformance category drives it twice and then issues, for that reason.
What is *not* asserted is worker liveness — that a health check actually ran —
which needs a clock seam or a bounded poll per harness. Recorded as the residual on
G2 in `docs/openbao-integration-gaps.md` rather than left as an implied guarantee.

## Why there is an `e2e/` layer at all, given a ten-plugin conformance table

The conformance table drives `logical.Backend` in-process. That is the right place
for almost everything, and `AGENTS.md` says so. But two production facts are
structurally outside it: the plugin runs as a **separate process** (so `resp.Data`
and the lease's `internal_data` are JSON on the wire, not the Go values the test
handed back), and **core** owns the mount table, the expiration manager, plugin
reload and `req.ID`. An in-process test cannot be wrong about those; it simply
cannot see them.

The evidence settled it: within an hour of `e2e/` existing it found two live
defects (KI-007, KI-008), neither of which any in-process test could have caught,
and KI-008 only because a real expiration manager acted on the lease. Auditing what
the new layer *could not* reach then found a third (KI-001 still open on
AWS/GCP/OCI).

The layer is deliberately kept thin and its findings are pushed *down*: when e2e
finds something, the regression guard ships in `pkg/plugintest` where it runs on
all ten plugins in milliseconds. e2e is for discovery and for the boundary itself,
not for fencing. Clouds it cannot reach (AWS/GCP/OCI, which inject clients instead
of talking to an HTTP endpoint) are declared in its registry the same way
`Harness.Skips` declares conformance gaps — a gap that prints is a gap someone can
act on.

Above it sits one more layer, planned but unbuilt: real clouds via CI secrets,
whose purpose is proving the fakes resemble what they stand in for
(`docs/free-account-viability.md`). The `cloud_real` build tag is currently carried
by no file, and that is recorded as a gap rather than described as coverage.

## Why DO's health check stays `GET /v2/account` after a scoped PAT failed it

A real-account probe on 2026-08-21 found that a granular (scoped) DO PAT gets 403
on `GET /v2/account` — the plugin's health check — while `GET /v2/regions` returns
200. So that health check reports a live credential as dead, and the recovery state
machine would drive such a minter to `AuthFailing` on false grounds. The obvious
fix is to probe a scope-free endpoint instead. It was rejected.

The repo's own doctrine is **health ≠ capability**
(`docs/minter-capability-verification.md`): health proves the credential is live,
the capability probe proves it may mint. Judged by that doctrine `/v2/account` is
the wrong endpoint, and `/v2/regions` the right one. But the same probe's second run
established something stronger (R1, KI-009): `/v2/tokens` is refused at DO's edge
gateway for *every* PAT, so there is no mint-capable DO PAT to be under-privileged
in the first place. The false-alarm state the change would fix is unreachable twice
over — a DO minter that gets past the capability probe against real DO does not
exist, and against the fake `/v2/account` answers 200.

That leaves a change with no behavioural benefit, which would trade a
higher-signal endpoint (one that fails when the minter is under-privileged, right
at the point an operator has pasted the wrong PAT) for a lower-signal one, and
churn the DO fake and its callers for it. The finding is real and worth having, so
it is recorded where it helps instead: as `forbiddenMintHint` on the capability
probe's 403, which is the error an operator with the wrong PAT actually sees, and
in `docs/do-api-verification-2026-08-21.md` (R1, R2). Should DO ever ship a
PAT-management scope, least-privilege minters become possible and this decision
must be revisited — the health endpoint would then need to move.

## Why `credential-do` stays the reference implementation even though it cannot mint

The real-cloud probe established that `POST /v2/tokens` is refused at DigitalOcean's
edge gateway for any personal access token (KI-009). The plugin's mint path cannot
work in production, and there is no headless alternative on DO: OAuth tokens need
interactive authorization, and Spaces keys are a different credential type that this
repo puts out of scope. Three options were weighed.

**Delete the plugin.** Rejected. Its value to this repo was never DigitalOcean:
`credential-do` is the structure the other nine plugins follow, and the DO fake it
was written against is what the conformance and e2e layers exercise most heavily —
including the two categories (`reload`, `lease`) that exist because bugs were found
through it. Deleting a working reference and its test infrastructure to register a
complaint about one cloud's gateway would cost coverage across ten plugins and buy
nothing.

**Keep it and say nothing.** Rejected outright. An operator would configure a minter
set, and — because the capability probe defaults on — get a 403 whose message
("You are not authorized to perform this operation") invites a hunt for a privilege
that does not exist. That is the failure mode this repo's whole capability doctrine
was built to prevent.

**Keep it, demote its claim, and make the cloud's refusal legible.** Taken. The
plugin remains the code-shape reference and the origin of the DO fake; it is no
longer described anywhere as production-viable. The upstream 403 is translated at
minter-set/role write time by `forbiddenMintHint`, which states the conclusion DO's
own error cannot. And the finding is pinned rather than remembered: the probe asserts
the fence and **fails as good news** if DO ever allows the mint, and
`fake_parity_test.go` keeps the recorded evidence for it honest in ordinary
credential-free test runs.

The deeper lesson is about the layer, not the cloud. This repo had already flagged
the undocumented endpoint as an accepted risk (D1) and reasoned carefully about it
from the spec — and the spec-based reasoning reached "undocumented but working",
which was wrong in the way that mattered. Only a real credential against the real
API distinguished "DO does not document this" from "DO does not permit this", and it
took two runs and one response header (`X-Response-From`) to do it. Nine clouds
remain unprobed on that basis
([`free-account-viability.md`](free-account-viability.md)); this is the argument for
finishing that work rather than trusting ten fakes that agree with our reading of
ten sets of docs.

## Why the AWS real-cloud probe injects its recorder through a per-call option

The DO probe records by swapping `doClient.httpClient.Transport`, which works because
that client is a struct the test package can reach into. AWS's client is an SDK type
built by `newRealSTSClient`, so the obvious moves were to add a test-only constructor
taking an `http.Client`, or to widen `STSClient`.

Neither was needed. `STSClient`'s methods already end in
`optFns ...func(*sts.Options)` — the SDK's per-operation options — because that is
simply what the AWS SDK's method signature looks like. Passing
`func(o *sts.Options) { o.HTTPClient = ... }` on each call gives the recorder the wire
bytes while everything else stays the plugin's: its factory, its credential handling,
its signing, its decoding. **No production code exists for the test's benefit**, which
is the property that makes this layer's evidence worth anything — a probe that drives a
purpose-built seam is testing the seam.

Generalised: prefer a seam production code already has, even an incidental one, over a
new exported hook. The rule is in [`AGENTS.md`](../AGENTS.md).

## Why KI-010 is documented rather than fixed

The AWS probe found that an STS `ValidationError` reaches clients as
`error_code: internal` and is recorded as a fault against a healthy minter. The
tempting one-line fix — add a `ValidationError` branch to `classifyAWSError` returning
`http.StatusBadRequest` — changes nothing a client can see: `ClassifyUpstream` maps 400
through `default` to `ErrInternal` as well. Saying what actually happened needs a **new
`error_code`** (`upstream_request_invalid` or similar), and that is a spec change: the
techrfc's error model, plus every client pinning `metadata.api_version`. Adding an error
code to make one plugin's error message nicer, in the same change that introduced the
test which found it, is how a stable contract stops being stable.

So the finding is pinned instead — `fake_parity_test.go` asserts AWS's envelope shape
*and* the current (wrong) classification, so a fix must be deliberate and must update
[`known-issues.md`](known-issues.md) — and the options, including the `iam:GetRole`
alternative that would close the underlying `MaxSessionDuration` gap at the other end,
are written down there for whoever decides.

The related judgement: the probe **declares** the `MaxSessionDuration` gap rather than
skipping it, and accepts an optional `CLOUDREAL_AWS_LOWCAP_ROLE_ARN` to turn the
declaration into a live assertion. Demonstrating that gap needs a role capped below the
plugin's ceiling, which the minter deliberately cannot create — its IAM grant is
assume-only. An uncovered case that prints why it is uncovered is the same discipline as
`Harness.Skips`; a `t.Skip` would have looked like a pass.

## Why the AWS minter credential is one environment variable, not two

`free-account-viability.md` originally planned `CLOUDREAL_AWS_ACCESS_KEY_ID` +
`CLOUDREAL_AWS_SECRET_ACCESS_KEY`, mirroring AWS's own convention. The probe takes a
single `CLOUDREAL_AWS_KEY=access_key_id:secret_access_key` instead, because that is
already the format a minter's `token` takes inside a minter set
(`iam_minter_client.go` builds exactly this string for a rotation successor). One
variable means the operator pastes the same value into the test environment and into
`minter-sets/<name>`, there is one thing to rotate, and a half-updated pair cannot
authenticate as one key with another's secret.

## Why adding an `error_code` does not bump `api_version`

Because it cannot, and the attempt would be worse than useless.

An `error_code` travels in the error *string* — `credenvelope.ErrorResponse` returns
`logical.ErrorResponse("<code>: <message>")` — because OpenBao surfaces only
`resp.Error()` to a client on an error response and drops `Data` side-channels. So an
error response carries **no envelope**, and `metadata.api_version` exists only inside an
envelope, which is only ever built on success. A client cannot read `api_version` off a
response that carries an `error_code`. Bumping it to announce a new code would announce
the change on the one class of response where the change never appears, while forcing
every client to re-pin for a compatible addition.

The rule adopted instead: the vocabulary is **additive**, and a client MUST treat an
unrecognised code exactly as `internal`. New codes ship in a documented spec revision;
removing or redefining a code is breaking and does need a bump. `api_version` keeps
meaning one thing — the envelope's shape — which is what makes it useful.

This also settles the question the audit was asked: there is no "version churn" to
amortise, so the reason to batch the additions was the cheaper one — each addition costs
a techrfc edit, a `design.md` table row and a client-side switch arm, and one revision
covering five real failure modes is kinder than five revisions.

## Why `logical.ErrorResponse` is banned by lint rather than by convention

166 error responses had accumulated with no `error_code` — every config, role,
minter-set, reconcile and rotate path — while API-002 claimed all error responses
carried one. Nobody decided that; it happened because `credenvelope.ErrorResponse` and
`logical.ErrorResponse` look equally reasonable at a call site, and a missing code is
invisible in review. It does not look like a defect; it looks like a message that
happens not to have a prefix.

Signature design gets half of it: `credenvelope.ErrorResponse(code ErrorCode, msg
string, ...)` cannot be called without a code. The other half is removing the
alternative, so `forbidigo` forbids `logical.ErrorResponse` outside
`pkg/credenvelope/errors.go`. The contract is now a property of the build.

Considered and rejected: making `ErrorCode` a struct with an unexported field, so an
arbitrary string literal could not be passed either. It would buy compile-time
protection against an *invented* code, which is not the failure that happened, at the
cost of an idiomatic wire-shaped type (constants, `switch`, direct comparison in tests).
The realistic failure is forgetting the code, and lint plus the signature cover that.

## Why `unsupported` is a code and `upstream_conflict` is not

Both were candidates in the same revision; the test applied was whether a client would
**act** differently.

`unsupported` earns it. `minter-sets/<set>/rotate` exists on all ten plugins for a
uniform surface, and four of them reject it permanently (DO, OVH, Vultr, OCI). Tooling
that walks the clouds needs to tell "this cloud never will" from "you configured it
wrong" — the first means stop asking, the second means fix input. Reporting both as
`config_invalid` would send an operator hunting for a setting that does not exist,
which is exactly the mistake KI-009's `forbiddenMintHint` exists to prevent elsewhere.

`upstream_conflict` (HTTP 409) does not. Entity names are plugin-generated from the role
and request id, so a genuine conflict is a plugin bug or a quota in disguise — there is
no "retry with a different name" a client could perform. 409 therefore folds into
`upstream_request_invalid` with the other content rejections, and if a real 409 ever
turns up in a real-cloud run, the recording will say what it actually means.

`consent_required` was removed in the same pass: it was specified in `design.md`,
mapped to 501, and emitted by nothing. Since no code path ever produced it, no client
can have observed it, so removing it breaks nobody — and leaving it would keep implying
a behaviour that does not exist.

## Why capability probes are rate-limited but not health-gated, and cached but not capped

A capability probe is a real mint against the cloud's real quota. It was outside
every mechanism this project has for bounding real mints, which produced three
distinct problems and three answers that do not all point the same way (A29 in
[`audit-2026-08-22.md`](audit-2026-08-22.md)).

**Rate limiting: yes, and in both directions.** A probe refused while a cooldown is
open, and a probe's own `429` opening one. There is nothing to weigh here — the
quota is shared with the read path by definition, so a probe outside the breaker
hammers a cloud that has just refused a caller.

**Health gating: deliberately not.** The obvious implementation is
`StateMachine.TryAcquire`, which couples the cooldown to serviceability. It is
wrong here, for a reason that only shows up in the recovery path: an operator
replacing a failed credential writes *the same minter id*, so a state machine still
in `auth_failing` from the old credential would refuse the write that repairs it.
The set would be unfixable except by turning verification off. So probes consult
`InRateLimitCooldown` and never claim the half-open probe, which stays reserved for
issuance for the reason already recorded in `pkg/recovery/ratelimit.go`.

**Recording: successes and rate limits only.** A probe that mints is a successful
upstream mint and is recorded as health. A probe *refused on privilege grounds* is
not a fact about the credential — it is a fact about one role's mint shape — and
recording it as a credential failure would walk a minter serving nine other roles
toward `auth_failing` because a tenth role was written wrong. Those refusals
release the half-open claim (`ReleaseProbe`) and record nothing.

**Caching: yes, one hour by default, and the staleness is the point of the trade.**
A cached verdict can be an hour old, so revoking a grant upstream and then writing a
role can have the role accepted on an earlier probe's word. Accepted deliberately:
the consequence is bounded, because issuance then fails at read time with the
upstream's own refusal — the probe exists to make that *rarer* and earlier, not to be
the last line of defence against it. Against that, the uncached behaviour was a full
(minters × roles) re-mint on every configuration write, so an idempotent `terraform
apply` paid for the whole fan-out each run and every OVH probe in it left a live
one-hour token that no API can revoke. Only successes are cached, so a fixed grant
takes effect on the next retry; the fingerprint covers the minter's stored form, so
replacing a credential under an existing id re-proves it.

**Capping: deliberately not.** A cap generous enough for a legitimate set (five
minters, thirty roles) never fires; one tight enough to fire blocks that set from
ever being written unless the operator disables verification altogether — trading a
cost problem for a security one, which is the wrong direction. Dedup plus the cache
bound the cost. What a cap was really aimed at is an *unintended* fan-out, and that
is served by logging the probe count above a threshold, where an operator can see it
without being stopped by it.

## Why persisted entries carry a schema version but not unknown-field preservation

Every mutation in this codebase is read-struct → change one field → write the WHOLE
struct back, and `encoding/json` silently drops fields it does not know. So a binary
that predates a field *erases* it on any write — and on a minter set that erasure is
A13 by another route: losing `retired`/`retired_at` un-retires a rotated-out minter,
cancels the sweep that was going to delete its upstream credential, and returns a
credential the operator has already replaced to the selection pool.

The strictly stronger answer is field preservation: decode into a
`map[string]json.RawMessage`, mutate the known keys, re-encode everything. It also
means every persisted type loses its Go struct as the single description of itself,
every read path gains a decode step that cannot be type-checked, and a field's
meaning stops being visible where it is declared. That is a large, permanent tax on
every entry to survive a case — a downgrade — that a version check turns into a clear
error instead.

So: `cloudconfig.Versioned`, stamped on write, checked on load, and the check refuses
only the FUTURE. An entry from a newer schema is not loaded, not rewritten, and the
error names the entry and says to upgrade the binary on that node; an entry with no
version (written before this existed) is read as current, which during alpha is the
ordinary case. The operator keeps an intact entry and a specific instruction, which
is a better outcome than a partially-preserved one nobody can audit.

What this deliberately does not provide is a migration mechanism. There are no
migrations yet — `SchemaVersion` is 1 — and inventing a framework for a transition
that has never happened would be guessing at its shape. The version is the
prerequisite: it is what makes the *first* migration possible to write and detectable
if forgotten. `AGENTS.md` carries the rule for new persisted types.

## Why a revoke that cannot succeed releases the lease instead of failing

OpenBao retries a failed revoke indefinitely, so returning an error is a promise that
a later attempt might work. A missing `internal_data` key is the exact opposite: it
will be missing on every attempt, forever. The old behaviour therefore produced the
worst of both — a lease wedged permanently in `sys/leases`, and the upstream
credential it could not name alive anyway.

Releasing the lease is the lesser harm, and it is logged at ERROR rather than WARN
because it genuinely needs a person: we cannot identify the upstream credential, so
the owner-tag reconciler will only reclaim it once its own tracking entry is gone.
The alternative — keeping the lease as a marker of the problem — keeps a marker
nobody reads and a retry loop nobody wants, and still leaks the credential.

## Why the credential shape is named in the envelope and pinnable on the request

The `credential` block is deliberately cloud-specific — an AWS session is three
fields, EdgeGrid is four, a GCP token is two — so a client had exactly one way to know
what it was about to parse: knowing which cloud it had asked, and hard-coding the
shape. That holds until a cloud serves a *second* shape, and clouds do. AWS SES over
SMTP needs `{username, password}`: the SMTP password is a deterministic HMAC
derivation from an IAM secret and the region (no API call, nothing extra stored), but
SMTP `AUTH` carries only two values and an STS session credential is a *triple* — there
is nowhere to put the session token. So SES-over-SMTP cannot be served by the same
AssumeRole path as everything else on that cloud, and the moment it exists "which
cloud" stops determining "which shape".

Two things follow, and the second is the one worth the API change.

**The envelope states the shape** (`metadata.credential_kind`), so an unpinned reader
still learns what it received instead of inferring it.

**The client may pin the shape it can parse** (`credential_kind=<kind>` on a credential
read), and a mismatch is a specific, non-retryable-as-is error. That inverts the
compatibility problem: adding a shape becomes *additive*, because an older client
either keeps receiving the shape it asked for or receives an error naming both shapes —
never a payload it silently misparses. Without the pin, adding a shape to a cloud is a
breaking change for every client of that cloud, whether or not the operator meant it to
be.

Decisions inside that:

- **The pin is optional, not required.** Omitting it serves the read (and reports the
  kind), which is how a human explores with `bao read` and how every client written
  before this existed keeps working. Requiring it would buy a guarantee nobody asked
  for and make the ergonomic path the one people work around. A pin is a client
  *capability declaration*, and a client that has none makes no claim.
- **It is checked before the role is loaded or anything is minted.** A caller that
  cannot parse the answer must not cost an upstream credential, and on the four clouds
  whose credentials have no natural expiry a minted-then-discarded credential is a leak
  the reconciler has to clean up. The conformance and e2e cases both assert the upstream
  count is unchanged on a refused pin, because "refuse after minting" would pass a
  naive test.
- **It earns a new `error_code`.** The rule here is that a code exists only if a client
  would act differently, and this is the one refusal a client can resolve *without an
  operator*: a library that can parse two shapes retries asking for the other.
  Everything else in the "do not retry, fix config" bucket needs a human.
- **A kind names a payload, not a cloud.** GCP and OVH both emit
  `{access_token, token_type}` and both declare `oauth2_bearer`, so pinning it is a
  statement about parsing rather than about geography. That is enforced by a test over
  the registry — two clouds sharing a kind must declare identical key sets — because it
  is a claim about ten separate plugins. Where a shape is genuinely cloud-specific the
  name says so; inventing a generic name for EdgeGrid's quadruple would describe nothing.
- **The served kind is a per-plugin constant wherever a cloud serves one shape, and a
  function of the role where it does not.** A constant was the honest encoding while
  every cloud served one shape, with a comment at each site saying it becomes a role
  function when a cloud gains a second. That happened on 2026-09-15: `credential-do`
  issues either a scoped token or an S3-compatible Spaces key, selected by the role, so
  it now calls `credentialKindFor(role.credentialType())`. The prediction held — the
  enforcement point was already right, and the change stayed inside that one plugin.

What this does NOT decide is whether SES-over-SMTP gets built. It needs a long-lived
IAM key, which is a phased-rotation problem (the OCI strategy) rather than a JIT one —
see the SES note in that section. The shape mechanism is worth having regardless,
because it is the thing that has to exist *before* a second shape, not after.

## Why the reconciler's delete cap is per class, and expired orphans get their own budget

`max_deletes_per_pass` (default 10) exists because reconciler deletion is **inferred**: an
upstream credential is an orphan because this mount cannot find it in its own records. A
subtly incomplete owned-set therefore nominates *live* credentials — that is exactly what
A1 was, where a rotation successor was owner-tagged but not lease-tracked and got deleted
out from under its set — and a low cap is what bounds the damage and leaves a human time to
notice.

That reasoning does not apply to a credential the cloud has already expired. Nothing can
use it, so deleting it cannot break a workload; it is housekeeping.

Until now both were charged to one budget, spent in the order the cloud listed them — and
listers sort oldest-first, so **expired credentials come first**. A pass with ten of budget
and twelve expired orphans ahead of two live ones spent the whole cap on credentials that
could not have hurt anyone, and the two actual exposures waited for the next pass. The
priority was exactly inverted, on the one dimension the cap is supposed to be careful about.

So `UpstreamEntity` gained an optional `ExpiresAt` and the budget became two counters.

- **Separate counters, not an exemption for expired orphans.** The tempting version is to
  stop counting them at all. It was rejected because *"expired"* is derived data too: a
  node whose clock is hours fast, or a lister misreading the upstream's expiry field,
  reclassifies live credentials as inert — and an exemption would then delete them without
  bound, in the one scenario where the cap is the only thing left. Two counters keep the
  runaway bound (at most 2× the cap per pass, the same order of magnitude) while
  guaranteeing the thing that was broken: expired clutter can never starve a live orphan.
  The accepted cost is that a purely-expired leak still drains at the cap per pass. It is
  clutter, it costs only listing size, and nothing else reclaims it.
- **Unknown expiry counts as LIVE.** Most listings report no expiry, and the four
  hard-revoke clouds issue credentials with *no upstream expiry at all* — so treating
  unknown as inert would put nearly everything on the housekeeping budget and erase the
  distinction. Unknown means unknown, and unknown belongs under the conservative cap.
- **No reordering.** Priority comes from the accounting, not from a sort, so the pass still
  walks the listing in its own oldest-first order — the right order among equals. An earlier
  attempt did partition live-before-inert; two budgets subsume it and are simpler.
- **The scan continues past an exhausted budget** (`continue`, not `break`). This was a
  reporting defect the 1025-orphan real-cloud run made obvious: a pass draining a leak of
  1025 logged `orphans_found=11` — ten deleted plus the one that tripped the cap — because
  the loop stopped counting when it stopped deleting. An operator draining a real leak could
  not see how much was left. `Scanned` was right; `found` was not.
- **`expired` is in the `/reconcile` response**, added to the uniform schema. Without it
  the numbers look broken: `deleted` can legitimately exceed the configured cap now, and
  nothing else distinguishes that from a cap that is not working. The `TargetLocalExpired`
  clouds (AWS/GCP/OVH) report it equal to `deleted`, which is true by definition — an
  expired credential is the only thing those passes reclaim.

## Why the timer-driven confirmation hold is an hour, and named

The minimum age an orphan must reach before deletion was a bare `1 * time.Hour` repeated in
six `workers.go` files, with only the *manual* path's 5-minute floor (`MinConfirmationHold`)
documented. It is now `reconciler.WorkerConfirmationHold`, one value, because it is the
answer to "what stops the reconciler racing an issue" and that should be greppable.

An hour is far above the 5-minute floor deliberately — a worker runs unattended. It covers
three races, in increasing order of how easily an hour beats them:

1. **The create-then-track window.** A credential exists upstream for a moment before this
   mount records it, and in that window it is indistinguishable from an orphan.
2. **Handover between cluster nodes.** Background work runs on the active node only
   (`pkg/clusterrole`), so a failover moves the reconciler to a node whose storage view is
   whatever replication has delivered. A tracking record written just before the handover
   may be invisible to the promoted node's first pass, which would read a live credential as
   an orphan. An hour is orders of magnitude more than raft needs, and waiting costs
   nothing — an orphan an hour old is just as reclaimable.
3. **Clock disagreement.** The age compares the *cloud's* creation timestamp against the
   *local* clock, so the two come from different sources. Minutes of skew cannot cross an hour.

A test keeps the worker's hold at or above the manual floor, since the two are set
independently and the unattended one must not be the weaker.

## Why minter self-rotation exists on six clouds and is refused on four (2026-09-15)

Every plugin serves `minter-sets/<set>/rotate`, but only Azure, UpCloud, AWS, Akamai, GCP and
Exoscale implement `RotateMinter`; DO, OVH, Vultr and OCI reject before any state change. That
split is not effort left undone — it was verified against each cloud's API on 2026-06-01, and
each side of it rests on an external fact that can change, so it is recorded rather than left
as an absence of code.

Feasible means a minter can mint a successor **of its own privileged kind**, and that the
successor is itself mint-capable — otherwise the chain rotates once and then wedges. That is a
different call from the JIT mint path: DO's `CreateToken` mints a scoped short-lived token, never
a successor PAT, which is why `RotateMinter` is new per-cloud client code and not a reuse. On four
of the six the successor inherits capability structurally — an Azure secret authenticates as the
SP with its own `addPassword` right, an AWS access key carries the IAM user's policy including
`iam:CreateAccessKey`, a GCP key authenticates as the SA with its key-create role, and an Akamai
client created at `READ-WRITE` on the Identity-Management API can create further clients. UpCloud
and Exoscale instead carry an explicit input forward (`can_create_tokens: true`, the
key-management `role_id`), which is why those two are the ones with a field to get wrong.

The four refusals are API-level impossibilities, not policy:

- **DigitalOcean** has no token-management scope in its catalog (`token:*` does not exist), so a
  created token could never be granted the right to create further tokens. KI-009 fences the
  endpoint anyway.
- **OVH**'s `client_credentials` grant mints short-lived *access tokens*; nothing there mints a
  new client credential.
- **Vultr** has one account-wide API key, and regenerating it invalidates the old one
  immediately — so there is no make-before-break overlap, which is exactly what grace-separated
  retirement needs.
- **OCI** minter users are 2-auth-tokens-tight, the same cap that forces that cloud onto phased
  rotation for its *issued* credentials.

Two of the six carry a live caveat. **GCP's** `iam.disableServiceAccountKeyCreation` org policy is
enforced *by default* for organizations created on or after 2024-05-03, so `keys.create` fails
outright in most modern organizations; the client detects that policy's sentinel and names it,
because reported as a generic failure it sends an operator to rotate a credential that is fine.
**Exoscale** is the lowest-confidence of the six: the exact IAM action identifier for key creation
is not enumerated in Exoscale's public documentation, so the operator pre-provisions a
key-management role and the successor reuses that same `role_id`. It is fake-tested like the rest,
but it is the one to confirm against a live account before relying on it.
