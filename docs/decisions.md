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
- AWS: IAM role ARN being assumed
- GCP: SA email being impersonated
- Azure: parent app registration (NOT the per-lease ephemeral SP)
- DO: the minter PAT (NOT the per-lease minted token)
- UpCloud: current slot's upstream token ID

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
- Has no native short-TTL primitive (so the plugin owns the TTL contract — there's no upstream engine to fall back on)
- The cloud SDK is small
- Test accounts are cheap

AWS would be a poor reference: most of the credential lifecycle is delegated to the upstream OpenBao `aws` engine, so an AWS-first implementation would shortcut around the parts (envelope, lease tracking, recovery, reconciler, metrics) that this project actually needs to validate.
