# Can each cloud be exercised for real, on a free account?

**Status:** assessment 2026-08-21. Motivated by [`openbao-integration-gaps.md`](openbao-integration-gaps.md)
G9: `cloud_real` is a documented build tag that **no file carries**, so the claim
every cloud fake makes — that it resembles the API it stands in for — is
currently untested. This document answers two questions:

1. For each cloud, can an account be created **free** (or near-free) that holds
   enough privilege to exercise that plugin's minter end to end?
2. What the CI layer above the in-repo fakes should look like, given that its
   purpose is not "test the cloud" but **prove the fakes are realistic**.

Nothing here is implemented yet. It is the plan and the evidence behind it.

> **Confidence is stated per cloud and it matters.** Signup terms, trial credits
> and which API a trial account may call change frequently and are not always
> documented. Where a claim was not verifiable from the plugin's own code or from
> a stable API reference it is marked *unverified* with the specific thing to
> check first. Treat *unverified* as "budget an hour to find out", not as a fact.

## What "sufficient access" means here

A real-cloud pass is only worth running if it drives the same code paths the
fakes stand in for. Per cloud that is up to six upstream operations, not one:

| Capability | Why it must be reachable | Where it is used |
|---|---|---|
| health check | the minter recovery state machine's only input | `healthCheckInterval` worker |
| **mint** | the whole point | `pathCredsRead` |
| **revoke** | the TTL bound on the six hard-revoke clouds | `pathCredsRevoke` |
| list (with a creation timestamp) | the owner-tag reconciler's orphan sweep | reconcile worker |
| capability probe (mint **then** delete) | runs at minter-set write and role write, on by default | `capability.go` |
| minter key create/delete | `minter-sets/<name>/rotate` on the 6 rotation-capable clouds | `RotateMinter` |

So "an account exists" is not the bar. The bar is *an account whose minter
credential can mint, revoke, list and (where implemented) rotate itself*. The
last row is the one most likely to need a privilege an operator would not grant
by default.

## Summary

| Cloud | Free/near-free account | Payment method at signup | Cost to run the suite | Verdict | Confidence |
|---|---|---|---|---|---|
| **AWS** | yes — permanent free tier | card | **$0** (IAM + STS are unmetered) | **best first target** | high |
| **GCP** | yes — $300/90d trial, then free tier | card | **$0** (IAM Credentials calls are free) | **viable** | high on cost, medium on post-trial project rights |
| **Azure** | yes — Entra tenant needs no subscription | card for a *subscription* only | **$0** (app registrations + secrets are Entra-free-tier) | **viable, and cheapest to keep** | medium-high |
| **DigitalOcean** | account is free; card/PayPal verification | card or PayPal ($5 hold) | **$0** (PATs are free) | **viable, and the highest-value target** | high on account, **the endpoint itself is the unknown** |
| **OCI** | yes — Always Free, indefinite | card (verification hold only) | **$0** (auth tokens are free) | account viable, **plugin blocked** (signing is a stub, G8) | high on account |
| **Exoscale** | trial organisation with credit | card or business verification | **$0** (IAM roles + API keys are free) | probably viable | medium, unverified |
| **UpCloud** | trial after identity verification | card or ID check | **$0** (account tokens are free) | probably viable | medium, unverified |
| **OVH** | account creation is free | none to create the account | **$0** (OAuth2 clients are free) | probably viable | medium, unverified |
| **Vultr** | no free tier — **$10 minimum deposit** | card, deposit consumed slowly | ~$0 running, $10 sunk | viable but not free; **API-key IP allowlist is the real obstacle** | medium |
| **Akamai** | **no** — Control Center access is contract-gated | n/a | n/a | **not viable without a commercial relationship** | medium-high that it is *not* obtainable |

Nine of ten clouds are reachable for roughly the price of one $10 deposit. The
tenth (Akamai) is not, and that should be recorded as a permanent gap rather than
left looking like work nobody got to.

## Per cloud

### AWS — free tier, $0, everything reachable

IAM and STS are unmetered, so the entire suite (assume-role mints, access-key
rotation, `GetCallerIdentity` health checks) costs nothing on a permanent free
tier account, forever — not just during a trial window.

What the test account needs:

- an IAM user for the minter, with `sts:AssumeRole` on the target role;
- a target role whose trust policy names that user (`iam_role_arn` on the role);
- for rotation: `iam:CreateAccessKey`, `iam:DeleteAccessKey`, `iam:ListAccessKeys`
  scoped to the minter user itself (`arn:aws:iam::<acct>:user/${aws:username}`).

Worth knowing: the capability probe **cannot revoke what it mints** on AWS, so it
pins the requested lifetime to the documented 900s floor (KI-006 gap 1). On a
real account that means each minter-set/role write leaves one STS session alive
for 15 minutes. Harmless, but it will appear in CloudTrail and should not be
mistaken for a leak.

**Confidence: high.** No trial-expiry cliff, no quota that a test run can exhaust
(access keys cap at 2 per user, which is exactly what rotation needs and no more —
a failed rotation that leaves both slots occupied will wedge the next one, so the
sweep step matters).

### GCP — trial then free tier, $0, one thing to verify

`iamcredentials.googleapis.com` `generateAccessToken` calls are free, and service
account key create/delete (what `RotateMinter` uses) are free. The $300/90-day
trial is not needed for cost; it is only relevant to whether the project stays
usable.

What the test account needs:

- a project with the IAM Credentials API enabled;
- a *minter* service account with a JSON key;
- a *target* service account granted `roles/iam.serviceAccountTokenCreator` to
  the minter (this is the per-target grant that the plugin's health check
  deliberately does **not** prove — see `minter-capability-verification.md`);
- for rotation: `iam.serviceAccountKeys.create` / `.delete` on the minter SA.

**Unverified:** whether a project whose billing has lapsed after the trial can
still enable/call `iamcredentials`. Check by letting a throwaway project sit
without billing and calling `generateAccessToken`. If it cannot, GCP needs a
billing account attached (still $0 spend, but a card on file that stays).

Note the 10-keys-per-SA cap: a rotation test that fails mid-way leaves keys
behind, so the post-run sweep must delete keys by owner prefix.

### Azure — cheapest to keep alive, no subscription needed

This is the one cloud where the plugin's whole surface lives in a product tier
that is free *by design* rather than free *by trial*: app registrations and
`addPassword` / `removePassword` are Entra ID free-tier operations, and Microsoft
Graph does not meter them. An Azure *subscription* (the thing the $200/30-day
credit applies to) is not required to have a tenant with app registrations in it.

What the test account needs:

- an Entra tenant;
- an app registration to act as the minter service principal, with
  `Application.ReadWrite.OwnedBy` (admin-consented — you are the tenant admin) and
  ownership of the target app registration(s) the roles name;
- target app registrations for the roles to mint secrets on.

`Application.ReadWrite.OwnedBy` rather than `.All` is deliberate and is also the
best real-world exercise of the capability probe: it is exactly the privilege
shape where a minter is live but unable to mint for a *particular* role, which is
the case a health check cannot see.

**Confidence: medium-high.** The one thing to verify is whether a brand-new
tenant with no subscription attached permits admin consent for that Graph
permission without any Entra-paid feature.

### DigitalOcean — viable, and the single most valuable thing to test

Account creation needs a payment method (card, or PayPal with a small hold);
promotional credit is usually attached and irrelevant, because PATs are free.

DO is where a real-cloud pass would buy the most, because it is the one plugin
whose central assumption is **known to be undocumented**: `POST /v2/tokens` and
`DELETE /v2/tokens/{id}` are not in DigitalOcean's public OpenAPI spec (see
[`do-api-verification-2026-08-21.md`](do-api-verification-2026-08-21.md)). The
fake implements what the plugin believes the endpoint does. Only a real call can
tell us whether:

- a PAT may call `/v2/tokens` at all, or whether the endpoint only accepts a
  control-panel session cookie / OAuth token (**if this fails, the reference
  plugin's mint path does not work in production** — that is the finding worth
  the whole exercise);
- the scope strings are accepted as the plugin passes them through (role `scopes`
  is an unvalidated pass-through, so a rejected scope surfaces only upstream);
- a PAT can mint a PAT whose scopes are a subset of its own, and what the error
  looks like when it is not.

Because there is no PAT-management scope, DO minter rotation is (still) infeasible
and out of scope for the real pass — the run covers mint, revoke, list, reconcile
and probe.

**Confidence: high** that the account can be created for ~$0; the point of the
test is precisely that confidence in the endpoint is *low*.

### OCI — account is free, the plugin is what blocks

Oracle Cloud's Always Free tier is indefinite (a card is taken for identity
verification), and auth tokens are free. The blocker is in this repo, not at
Oracle: `plugins/credential-oci/oci_client.go` returns
`upstream_auth_failed: OCI request signing not implemented in this build` for all
four methods, so OCI cannot be driven against anything real — fake or cloud
(G8). Implementing OCI request signing is the prerequisite, and it is a
prerequisite for the e2e layer too, so it pays for itself twice.

Also note the two-auth-tokens-per-user cap: it is why OCI returns
`capability.ErrUnsupported` from the probe, and it means a real run must not leave
tokens behind or the next run has no slot. Serialise OCI runs (CI concurrency
group) and sweep unconditionally.

### Exoscale — probably viable, verify the trial's API rights

Exoscale issues trial organisations with credit; IAM roles and API keys are free,
and both `POST /api-key` and `DELETE /api-key/{id}` are documented public API.
The plugin's shape (an API key scoped to an IAM role) is a good fit for a test
organisation because the role can be given almost nothing.

**Unverified:** whether a trial organisation may create IAM roles and API keys
before any payment. Verify that first; everything else follows.

Remember KI-004 when writing the sweep: Exoscale's list API returns no creation
timestamp, so the *background* reconciler will not delete orphans — the CI sweep
must call the manual `/reconcile` endpoint (which uses `ConfirmationHold=0`).

### UpCloud — probably viable, verify API access on a trial

`POST /1.3/account/tokens` supports a native `expires_in`, which makes UpCloud the
cleanest cloud in the repo for TTL semantics and a good real-cloud citizen: the
credential expires by itself even if a test crashes before revoke.

**Unverified:** UpCloud requires identity verification at signup, and historically
some API surfaces have been gated until an account is out of trial. Verify that a
verified trial account can (a) call the API at all and (b) create account tokens.

The minter needs a sub-account whose API access is enabled, and the *username*
matters: it is precisely the field whose loss on reload was KI-001, so a real run
that survives a `bao plugin reload` is a direct regression test for that bug.

### OVH — probably viable, verify IAM service accounts on a bare account

An OVH account (NIC handle) can be created without buying anything, and OAuth2
clients cost nothing. The plugin mints via `client_credentials` against OVH's
OAuth2 token endpoint.

**Unverified:** whether creating an IAM *service account* (the OAuth2 client the
minter needs) requires at least one active OVH service on the account. If it
does, the cheapest active service is what the pass costs.

Two OVH facts shape the run: tokens are a fixed 1h with **no revoke API**, so
role TTLs are pinned to exactly 3600s, and the probe leaves a 1h token behind
each time (KI-006). Nothing to clean up, nothing to bound it either — factor that
into how often the OVH job runs.

### Vultr — not free, and the IP allowlist is the real problem

Signup requires a minimum deposit (historically $10). Sub-user creation
(`POST /v2/users`) is free, so the deposit is sunk cost rather than running cost.

The practical obstacle is not money: **Vultr API keys carry an IP access-control
list**, and GitHub-hosted runners have unpredictable egress addresses. Options,
in order of preference: run the Vultr job on a self-hosted or fixed-egress runner;
or widen the allowlist to `0.0.0.0/0` on a *dedicated throwaway account only*
(never on an account with resources); or skip Vultr in CI and run it manually.
Do not let this decision be made implicitly by a job that mysteriously 403s.

Also KI-004 applies (no list timestamp → manual `/reconcile` in the sweep), and
sub-users are real account identities, so the owner-prefix discipline matters
more here than anywhere else.

### Akamai — not obtainable free; record it as a permanent gap

The Akamai plugin talks to the **Akamai Control Center Identity & Access
Management API** (EdgeGrid-signed API-client creation), which is *not* the Linode
/ Akamai Connected Cloud API. A Linode account — which is trivially creatable
with a card and credit — does **not** grant EdgeGrid credentials for the Control
Center identity API. Akamai CDN/security trials exist but are sales-gated,
time-boxed, and not something CI can depend on.

Consequence: the Akamai fake will remain unvalidated against reality unless
someone with an Akamai contract runs the pass and contributes recordings. Two
things follow, and both should be done rather than left implicit:

1. State it in the fixture-parity matrix as a declared gap with this reason (the
   same discipline `Harness.Skips` enforces for conformance — a gap that prints
   is a gap someone can act on).
2. Treat the Akamai plugin's rotation path as the least-verified code in the repo:
   it is the only one that copies the incumbent's `apiAccess`/`groupAccess` onto
   the successor, and a mis-copy there is a privilege bug that the fake, written
   from the same reading of the docs as the plugin, cannot catch.

## The CI layer: real clouds via GitHub secrets

The goal is stated deliberately narrowly. **This layer exists to prove the fakes
are realistic**, not to gate merges on cloud availability. That framing decides
every design question below: it must be schedulable rather than blocking, it must
turn what it learns into artefacts the *offline* tests consume, and a cloud with
no account must be a *declared* absence, not a green tick.

### Triggers and gating

```yaml
on:
  workflow_dispatch:
    inputs:
      cloud: { description: "single cloud, or 'all'", default: all }
  schedule:
    - cron: "0 4 * * 1"     # weekly is enough; the fakes do not drift daily
```

Never `pull_request`, and explicitly **never `pull_request_target`** — a fork PR
must not be able to reach these secrets. Each cloud gets its own GitHub
[environment](https://docs.github.com/actions/deployment/targeting-different-environments)
(`cloud-real-aws`, …) holding that cloud's secrets, with required reviewers on
the environments whose accounts are not disposable. One environment per cloud,
not one shared, so a compromised job reaches one account.

Enablement is explicit and visible:

```yaml
jobs:
  cloud-real:
    strategy:
      fail-fast: false                      # one cloud's outage must not hide the rest
      matrix:
        cloud: [aws, gcp, azure, do, exoscale, upcloud, ovh, vultr]
    environment: cloud-real-${{ matrix.cloud }}
    concurrency: cloud-real-${{ matrix.cloud }}   # quota collisions (OCI tokens, GCP keys) are real
```

with `vars.CLOUDREAL_ENABLED_<CLOUD>` deciding whether the job runs, and — the
part that matters — **a job that is enabled but missing a secret must fail, not
skip**. A silent skip on a missing credential is how a suite ends up green while
testing nothing, which is exactly the shape of G9.

Secret naming, flat and mechanical, mapped by one small per-cloud loader in the
`cloud_real` test files: `CLOUDREAL_AWS_ACCESS_KEY_ID`,
`CLOUDREAL_AWS_SECRET_ACCESS_KEY`, `CLOUDREAL_AWS_ROLE_ARN`,
`CLOUDREAL_GCP_SA_KEY_JSON`, `CLOUDREAL_DO_TOKEN`, and so on. The loader lists
the names it needs per cloud; a missing one names itself in the failure.

### Guardrails (these are not optional on a real account)

- **Dedicated throwaway accounts only.** No account that holds anything, and no
  account that shares an organisation with one that does.
- **One owner prefix for the whole layer** (`cloud-creds-cirun-…`), so every
  artefact a run creates is reclaimable by the owner-tag reconciler the plugins
  already have. This is the existing safety invariant doing double duty; do not
  invent a second scheme.
- **A sweep step with `if: always()`**, per cloud, calling the plugin's
  `/reconcile` with `ConfirmationHold=0` (mandatory on Exoscale/Vultr, which have
  no list timestamps — KI-004) plus a direct delete of minter keys created by
  rotation. A run that fails before revoke is normal; a run that leaves residue is
  not.
- **Budget alarms** on the two clouds where a mistake can cost money (AWS
  Budgets, GCP budget alert). The suite should spend $0; an alarm at $1 catches a
  test that starts creating the wrong kind of resource.
- **No secrets in logs.** The recorder (below) scrubs fail-closed; CI logs run
  with `--json` off and no request tracing.

### What it produces: fixture parity

A real-cloud run that only says "PASS" has taught the repo nothing durable — next
month's fake is still written from a reading of the docs. So the run's *output* is
the deliverable:

1. **Record.** The `cloud_real` tests wrap the plugin's HTTP transport in a
   recording `RoundTripper` that writes `testdata/<cloud>/<operation>.json`:
   status, the response body, and the subset of headers the plugin reads. Bodies
   are scrubbed by a per-cloud rule set that is **fail-closed** — a recording
   containing a high-entropy string that no rule claimed fails the recorder rather
   than being written. (A leaked real credential in `testdata/` would be worse
   than the gap this layer closes.)
2. **Publish.** The job uploads refreshed recordings as an artefact and opens a PR
   rather than pushing: a change in a recording is a change in what the cloud
   does, and a human should see it.
3. **Replay, offline, on every ordinary `go test`.** A new suite (fixture parity)
   takes each recording and asserts that the *fake's* response for the same
   operation carries the same fields, with the same types, and that the plugin's
   parser extracts the same values from both. No credentials needed, so it runs
   in normal CI, for every cloud that has ever been recorded.

That third step is the whole point: it converts one privileged run into a
permanent, credential-free regression test, which is what "ensure our mock
endpoints are realistic" actually requires. It also gives the Akamai gap a
precise shape — Akamai simply has no recordings, and the parity matrix prints
that.

### Suggested order of work

1. **AWS + GCP fakes with HTTP endpoint overrides** (G8). This is the biggest
   single win and needs no cloud account: it brings two more clouds into the
   existing `e2e/` layer *and* is a precondition for recording them.
2. **OCI request signing** (G8, and the prerequisite for any OCI testing at all).
3. **The recorder + fixture-parity replay suite**, wired up against the fakes
   first (a fake recording proves the machinery before a real credential is
   involved).
4. **AWS, then Azure, then DigitalOcean** for the first real accounts — cheapest,
   then most permanently free, then highest-value-unknown.
5. Exoscale / UpCloud / OVH once their trial-rights questions above are answered.
6. Vultr once the runner-egress decision is made.
7. Akamai: declare the gap; revisit only if someone with a contract appears.

## Cross-references

- [`openbao-integration-gaps.md`](openbao-integration-gaps.md) — G8 (which clouds
  cannot be driven e2e) and G9 (the unused `cloud_real` tag) are the gaps this
  plan closes.
- [`minter-capability-verification.md`](minter-capability-verification.md) — what
  the probe mints per cloud, i.e. what a real account must permit.
- [`ttl-semantics.md`](ttl-semantics.md) — which clouds leave a credential alive
  if a run dies before revoke.
- [`known-issues.md`](known-issues.md) — KI-004 (manual `/reconcile` on
  Exoscale/Vultr) and KI-006 (probe residue) both constrain the sweep step.
