# Minter Sets — Design Spec

**Status:** Approved (2026-05-30)
**Scope:** All 10 plugins + shared packages. Pre-alpha — no migration/back-compat required.

## Problem

Today each cloud mount has a single flat list of minters in `config`. Any role draws from any healthy minter (failover/rotation only). This forces **one maximally-privileged minter per cloud**, which is wrong for:

- **Azure** — an SP authorized to manage app registration A (`addPassword`) typically has no rights on app B. Roles targeting different apps need different minters.
- **Akamai/Linode, AWS, GCP** — minting authority is scoped (per group/contract, per assumable-role, per impersonatable-SA). Distinct purposes need distinct privileged credentials.
- **Operational/audit** — operators want discrete minting credentials per purpose, and provenance tracing when an issued token is misused.

## Solution

Promote **minter sets** to a first-class concept. A minter set is a named, independently-validated group of minter credentials. Roles bind to exactly one set. The issuing set + minter are recorded in the credential for provenance.

### Configuration model

- `cloud-creds/<cloud>/config` — operational settings only (`flush_interval`, `reconcile_cadence`, `bootstrap_delay`, `max_deletes_per_pass`, plus per-cloud fields like `region`, `*_api_url`). **No longer holds minters.**
- `cloud-creds/<cloud>/minter-sets/<name>` — write / read / delete / list. Each set holds its own minter list, independently validated by `ValidateMinterSet` (the existing `(≥1 never_expires) OR (≥2 with ≥7d gap)` rule applies **per set**).

### Role model

- Roles gain a **required** `minter_set` field. Role write fails (`400`) if the named set does not exist at write time.
- Credential issuance selects a healthy minter **from the role's bound set only**. If every minter in that set is auth-failing → `upstream_auth_failed` (the failure is now scoped to the set, not the whole mount).

### Provenance (envelope contract change)

The response envelope `metadata` gains two fields:
- `minter_set` — the set name the credential was minted from
- `minter_id` — the specific minter within that set

This is an envelope-shape change, so **`api_version` bumps `"1"` → `"2"`** and the techrfc envelope section is updated. `minter_id` is also retained in lease `internal_data` (as today) for revocation.

## Shared package changes

### `pkg/credenvelope`
- `EnvelopeParams` + `Metadata` gain `MinterSet string` and `MinterID string`.
- `ToMap()` emits them under `metadata`.
- `APIVersion` constant → `"2"`.

### `pkg/cloudconfig`
- Add `MinterSet` type: `{ Name string; Minters []Minter }`.
- `ValidateMinterSet` already validates a `[]Minter`; reused per set.
- Add `ValidateSetName(name)` (non-empty, matches `GenericNameRegex` charset).

## Per-plugin changes (×10)

Each plugin (`credential-<cloud>`):

1. **backend.go** — state becomes `minterSets map[string]map[string]*minterState` (set → minterID → state). Add a `minter-sets` path group.
2. **path_minter_sets.go** (new) — CRUD for `minter-sets/<name>`; validates each set on write; instantiates a recovery state machine per minter.
3. **path_config.go** — remove minter handling; keep operational/cloud settings.
4. **path_roles.go** — add required `minter_set` field; validate the set exists on write; persist it on the role.
5. **path_creds.go** — `selectMinter(setName)` picks a healthy minter from the named set; envelope gets `MinterSet`/`MinterID`; revoke/health/metrics use the (set, minter) tuple.
6. **health_check.go / workers.go** — health-check iterates every minter in every set.
7. **telemetry.go** — minter metrics gain a `minter_set` label.
8. **tests** — config no longer takes minters; a `minter-sets/<name>` write + a role with `minter_set` is the new setup path. Update all test helpers (e.g. `setupConfiguredBackend`).

OCI (phased rotation) binds its **slots** to a role's minter set the same way — the slot provisioner authenticates with a minter from the role's set.

## Metrics keying

`entity_id` metrics are unchanged in meaning, but the per-minter health gauges (`cloud_creds_upstream_*`) gain a `minter_set` label so provenance is visible in Prometheus too.

## Out of scope

- Cross-set failover (a role uses only its set, by design — that's the isolation guarantee).
- Per-minter capability introspection (operators are responsible for granting each set's minters the rights its bound roles need).

## Testing

- Per-set validation: a set with one expiring minter is rejected; a set with `never_expires` is accepted.
- Role bound to a nonexistent set → `400`.
- Role bound to set A cannot mint via set B's minters (isolation): inject auth failure on set B, confirm set A role still issues.
- Envelope carries correct `minter_set`/`minter_id` and `api_version: "2"`.
- Registration smoke test still passes for all 10.
