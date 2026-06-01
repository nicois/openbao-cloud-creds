# Design decisions

Short notes on choices that aren't obvious from the [techrfc](techrfc.md) and would otherwise need to be re-derived from scratch.

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

- Has a JIT-capable native API (`POST /v2/tokens`)
- Has revocation (`DELETE /v2/tokens/{id}`)
- Has no native short-TTL primitive (so the plugin owns the TTL contract)
- The cloud SDK is small
- Test accounts are cheap

It was chosen as the reference precisely because it owns the full lifecycle (envelope, lease tracking, recovery, reconciler, metrics) with nothing delegated upstream — every load-bearing piece gets exercised.

> **Correction (2026-05-30):** This section originally argued AWS was a poor reference because "most of the credential lifecycle is delegated to the upstream OpenBao `aws` engine." That premise turned out false — OpenBao's AWS engine only supports IAM-user `iam_tags` (no STS `session_tags`), and there is no OpenBao GCP or Azure engine at all. As a result AWS/GCP/Azure were built as full JIT plugins calling the cloud APIs directly, with the same lifecycle machinery as DO. DO remains the reference for being the simplest, but the "delegate to upstream engine" distinction no longer applies to any cloud. See `docs/cloud-credential-research.md`.

## Why minter sets (named, role-bound) rather than one flat minter list per cloud

The original model had a single per-cloud minter list in `config`, and any role drew from any healthy minter (the multiple-minter mechanism existed only for rotation/failover). That forces **one maximally-privileged minter per cloud**, which breaks down for three reasons:

- **Capability separation is real on some clouds.** An Azure service principal authorized to manage app registration A (via `addPassword`) typically has no rights on app B; Akamai/Linode API-client creation is scoped per group/contract. Different role classes genuinely require different privileged minting credentials — a single minter cannot mint them all.
- **Operational separation.** Operators want discrete minting credentials per purpose (e.g. a backup-issuing minter distinct from an admin-issuing one), rotated and owned independently.
- **Audit provenance.** When an issued credential is misused, you want to trace which minting credential produced it.

So minters are grouped into named **sets** (`minter-sets/<name>`), each independently validated by the OBC-006 rule, and every role carries a **required** `minter_set`. Issuance mints only from the bound set — deliberately **no cross-set failover**, because the whole point is isolation: a compromise or misconfiguration of set A's minters cannot issue set B's credentials. The issuing set+minter are stamped into `metadata.minter_set`/`minter_id` (which bumped the envelope to api_version 2) and lease internal_data. The reconciler is the one exception: it cleans orphaned upstream entities across all sets by owner-tag, since orphan cleanup is a mount-wide safety property, not a per-role one.

Operators achieve least-privilege by granting each set's minters only the upstream rights its bound roles need. For capability isolation without sets, multiple mounts would also work, but sets keep it within one mount and make provenance first-class.

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
revive ruleset), pinned to golangci-lint v2.12.2 and run per-module in CI.

Decision: enforce it across every module with zero `//nolint` suppressions.
Rationale: with one plugin per cloud and ten near-parallel plugins, the failure
mode is *drift* — a helper that subtly diverges, a magic number that means
something different in one cloud, copy-paste that rots. The complexity and
duplication linters fire on exactly that drift, which is what pushed the
genuinely-shared code into `pkg/` (telemetry, metricspath, localexpiry) instead
of ten copies. The no-nolint rule is load-bearing: when a linter fires, the fix
is to restructure (extract a helper, name a constant, drop a dead param), not to
suppress — suppressions are where drift hides. Carried-forward exceptions live
in the config itself (not inline), e.g. the `(io.Closer).Close` errcheck
exclusion and `revive`'s disabled `unused-parameter`/`unused-receiver` for the
SDK-mandated handler signatures. Test files are excluded from the
complexity/literal linters (test code legitimately repeats literals and is
structurally loose). See `docs/superpowers/specs/2026-05-31-golangci-config-upgrade-design.md`.

## Why minter rotation retires with a grace period instead of deleting immediately

Minter sets are loaded into memory only at `Factory` construction and on a
minter-set write — there is no periodic reload. On a raft cluster the rotate
request is served by exactly one node; the other nodes keep the old minter in
their in-memory snapshot until they next reload (failover, restart, or a
subsequent minter-set write). If rotation deleted the old upstream credential
the moment it minted and swapped in the successor, every other node would still
be trying to mint with a credential that no longer exists upstream — issuance
would wedge cluster-wide (the KI-001 class of "the surviving node holds stale
config" failure).

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
