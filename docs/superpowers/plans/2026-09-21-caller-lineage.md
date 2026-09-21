# Caller Lineage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make "which unit obtained this credential, and which service does that unit belong to" both *recorded* and *enforceable* on every cloud, from identity OpenBao itself vouches for — so a role can refuse to issue to a unit whose parent is gone, and `issued/` names the parent of every outstanding credential.

**Architecture:** A new `pkg/lineage` resolves a caller's parent from the identity store — the only substrate every mount can read — through `logical.SystemView.EntityInfo`, which plugins already hold (`pkg/clusterrole` takes the same interface). It plugs into the three seams `pkg/requester` already uses: a role field checked before a minter is selected, a stamp on the tracking record, and a published field on `issued/`. The contract is **substrate-neutral**: any provisioner that writes the agreed keys into alias metadata satisfies it, so the ten credential plugins never depend on a particular auth method existing.

**Tech Stack:** Go 1.27 workspace (per-module `go.mod` + `go.work`), OpenBao SDK v2 (`sdk/v2/logical`, `sdk/v2/framework`), `pkg/plugintest` conformance suites, `pkg/baotest` HTTP scenario, golangci-lint v2.

---

## The aim, stated precisely

Today a tracking record answers *what* was issued, *by which minter*, and — since provenance
(2026-09-20) — *which token accessor and entity* asked for it. That last answer stops one hop short of
the question an incident asks. An entity id names a unit only if the auth method gave that unit its own
alias; with approle it names a **role**, because `Alias.Name` is the RoleID, so every unit sharing a
role collapses to one entity. And nothing anywhere says which *service* a unit belongs to.

This plan closes the hop that can be closed inside these plugins, and only that hop:

1. **Record the parent.** Every tracking record, on all ten clouds, gains
   `requested_by_parent_entity_id`, `requested_by_unit_id` and `requested_by_lineage_source`, published
   through the `issued/` allowlist. A report joins service → unit → credential without resolving token
   accessors, and the answer survives the caller's token being revoked, because an entity outlives its
   tokens.
2. **Enforce the parent.** A new role field `require_caller_lineage` (`none` default / `parent` /
   `live_parent`) refuses before a minter is selected. `live_parent` is the load-bearing value: it
   re-reads the parent's own entity and refuses when it is **absent (deleted) or `Disabled`**. So
   disabling one service's entity stops every unit beneath it from obtaining new credentials, on all
   ten clouds, immediately, with no sweep, no background worker and no cross-mount read.
3. **Refuse to guess.** Lineage is read only from fields a client cannot write (alias metadata, entity
   metadata — both set by the auth method or an operator, never by the request), there is no override
   parameter, and two aliases naming *different* parents resolve to nothing rather than to one of them.
   Misattribution is worse than a gap: a report that names the wrong service sends a responder to the
   wrong place while the compromised one keeps its access.

**Non-goals, explicitly.** This plan does not replace approle, build the provisioning side, build the
report, or make containment instant. Deleting or disabling a parent entity stops *new* issuance
immediately and stops the unit's own OpenBao access immediately (`request_handling.go` denies a token
whose entity is disabled or absent), but the cloud credential the unit already holds lives until its
lease ends and the plugin's revoke fires — `roles/<name>/revoke-upstream` remains the only lever that
reaches the cloud sooner, and on AWS/GCP/OVH nothing does.

**Second subsystem, planned separately.** The reference *substrate* — an auth plugin that gives each
unit its own alias, records the parent from `req.EntityID` in the same call that mints the unit's
credential, and sweeps its own records — is independent software with its own tests and its own release
surface. It gets its own plan (see "Follow-up plan" at the end). This plan is complete and useful
without it: an existing approle deployment satisfies the contract by writing two keys into an entity
alias's `custom_metadata`, which is a privileged one-time write per unit and needs no new mount.

## Substrate contract (what this plan consumes)

Two keys, fixed by this repo so ten clouds and any provisioner agree, read from the caller's entity:

| Key | Meaning | Where it may be written |
|---|---|---|
| `cloud_creds_parent_entity_id` | the entity id of the unit's parent (a service) | alias `custom_metadata`, alias `metadata`, or entity `metadata` |
| `cloud_creds_unit_id` | the provisioner's own stable name for this unit | the same three places |

Resolution order is alias `custom_metadata`, then alias `metadata`, then entity `metadata`, and the
winning source is recorded. Rationale for the order: `custom_metadata` is written by an operator or
provisioner and is never touched by a login, while alias `metadata` is rewritten on every login by the
auth method (last-writer-wins across everything sharing that alias — harmless when the alias is
per-unit, wrong when it is a shared RoleID, which is exactly why the source is recorded rather than
assumed). Neither is writable by the requesting client.

Rejected alternatives, so they are not re-litigated: **config-driven key names** (two knobs × ten
mounts, and a typo silently yields "no lineage"; adding them later is additive), and **group
membership** as the primary source (`GroupsForEntity` works and needs no metadata write, but a group
name is not an entity id, so `live_parent` could not check the parent — it is a reasonable *second*
resolver and is deliberately deferred).

## File structure

**New module** — `pkg/lineage/` (one module per `pkg/` package, as `pkg/requester` is):
- `pkg/lineage/go.mod` — module `github.com/nicois/openbao-cloud-creds/pkg/lineage`, `replace` to `../credenvelope`.
- `pkg/lineage/lineage.go` — key constants, `Lineage` struct, `Resolve`, `Stamp`, the `Requirement` vocabulary, `Enforce`, `RoleFieldDescription`. One file: it is one responsibility (turn a request plus a system view into a recorded, enforceable parent) and the whole of it is ~200 lines, matching `pkg/requester`'s shape.
- `pkg/lineage/lineage_test.go` — table tests over a mapping system view.
- `pkg/lineage/systemview_test.go` — `mapSystemView`, a `logical.StaticSystemView` that answers per entity id (the SDK's returns one entity for every id, which cannot express parent≠child).

**Modified:**
- `go.work` — add `./pkg/lineage`.
- `pkg/credenvelope/errors.go` — add `ErrCallerUnparented` and list it in `AllCodes()`.
- `pkg/issuedlist/issuedlist.go:78-83` — publish the three new fields in `Fields()`.
- `pkg/plugintest/harness.go` — a `Harness.SystemView` hook so a conformance subject can be built over an identity the test controls.
- `pkg/plugintest/lineage.go` — new conformance category (new file, one per category, as `provenance.go` is).
- `pkg/plugintest/conformance.go` — register the category.
- Each `plugins/credential-*/`: `consts.go` (field-name const), `path_roles.go` (field + validate + persist + read-back), `path_creds.go` (enforce + stamp), `go.mod` (require + replace `pkg/lineage`).
- `conformance/harness_*_test.go` — declare the category per subject.
- `pkg/baotest/scenario.go` — assert lineage reaches `issued/` over HTTP.
- `docs/techrfc.md`, `docs/design.md`, `docs/decisions.md`, `CLAUDE.md` — the error code is a spec change; the role field is API.

---

### Task 1: `pkg/lineage` resolves a parent from alias metadata

**Files:**
- Create: `pkg/lineage/go.mod`, `pkg/lineage/lineage.go`, `pkg/lineage/lineage_test.go`, `pkg/lineage/systemview_test.go`
- Modify: `go.work:22` area (add `./pkg/lineage` in sorted position)

- [x] **Step 1: Create the module and add it to the workspace**

```bash
mkdir -p pkg/lineage
cd pkg/lineage
cat > go.mod <<'EOF'
module github.com/nicois/openbao-cloud-creds/pkg/lineage

go 1.27.0

require (
	github.com/nicois/openbao-cloud-creds/pkg/credenvelope v0.5.0
	github.com/openbao/openbao/sdk/v2 v2.6.2
)

replace github.com/nicois/openbao-cloud-creds/pkg/credenvelope => ../credenvelope
EOF
cd ../..
```

Then add `	./pkg/lineage` to the `use (...)` block in `go.work`, keeping the list sorted (it sits
between `./pkg/issuedlist` and `./pkg/localexpiry`). Confirm the SDK version matches the rest of the
repo before committing to `v2.6.2`:

```bash
grep -h "openbao/sdk/v2 v" pkg/requester/go.mod
```

Use whatever version that prints.

- [x] **Step 2: Write the failing test**

Create `pkg/lineage/systemview_test.go`:

```go
package lineage

import "github.com/openbao/openbao/sdk/v2/logical"

// mapSystemView answers EntityInfo per entity id. The SDK's StaticSystemView returns the
// same entity for every id, which cannot express "the parent is a different entity" — the
// one relationship these tests exist to cover.
type mapSystemView struct {
	logical.StaticSystemView
	entities map[string]*logical.Entity
}

func (m *mapSystemView) EntityInfo(entityID string) (*logical.Entity, error) {
	return m.entities[entityID], nil
}

// aliasWithCustom builds an entity whose single alias carries custom_metadata.
func aliasWithCustom(id string, custom map[string]string) *logical.Entity {
	return &logical.Entity{ID: id, Aliases: []*logical.Alias{{Name: id, CustomMetadata: custom}}}
}
```

Create `pkg/lineage/lineage_test.go`:

```go
package lineage

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestResolveReadsTheParentFromAliasCustomMetadata(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{
		"child": aliasWithCustom("child", map[string]string{
			MetaParentEntityID: "service", MetaUnitID: "unit-7",
		}),
		"service": {ID: "service"},
	}}

	got := Resolve(&logical.Request{EntityID: "child"}, view)

	if got.ParentEntityID != "service" {
		t.Errorf("ParentEntityID = %q, want %q", got.ParentEntityID, "service")
	}
	if got.UnitID != "unit-7" {
		t.Errorf("UnitID = %q, want %q", got.UnitID, "unit-7")
	}
	if got.Source != SourceAliasCustomMetadata {
		t.Errorf("Source = %q, want %q", got.Source, SourceAliasCustomMetadata)
	}
}

func TestResolveIsEmptyWithoutAnEntity(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{}}

	got := Resolve(&logical.Request{}, view)

	if got.ParentEntityID != "" || got.Source != "" {
		t.Errorf("Resolve on an entity-less request = %+v, want zero", got)
	}
}
```

- [x] **Step 3: Run the test to verify it fails**

Run: `go test github.com/nicois/openbao-cloud-creds/pkg/lineage/...`
Expected: FAIL — `undefined: MetaParentEntityID`, `undefined: Resolve`.

- [x] **Step 4: Write the minimal implementation**

Create `pkg/lineage/lineage.go`:

```go
// Package lineage records and enforces WHICH PARENT the caller of a credential belongs to, so an
// issued credential names a unit's service and not merely the token that asked.
//
// # Why this is not pkg/requester, which already records the caller
//
// Provenance records what core hands every backend: the token accessor and the entity id. That names
// a SESSION and an ENTITY, and on the commonest auth method an entity is not a unit — approle sets
// Alias.Name to the RoleID, so every unit sharing a role resolves to one entity (see the 2026-09-21
// notes in docs/decisions.md). So provenance answers "which role logged in", and the question an
// incident asks — "which unit, and whose is it" — needs one more hop.
//
// # Where lineage may come from, and why nowhere else
//
// Only from fields the requesting client cannot write: an alias's custom_metadata (written by an
// operator or provisioner, never touched by a login), an alias's metadata (written by the auth method
// at login), or the entity's own metadata. There is NO request parameter, for the reason pkg/requester
// gives: a forgeable value here would let one unit record another's lineage against a credential it
// obtained, which is worse than recording nothing.
//
// The identity store is also the only substrate available: mount storage is barrier-isolated, so a
// registry kept by another mount is unreadable here, while SystemView.EntityInfo is readable by every
// plugin.
package lineage

import (
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Metadata keys a provisioner writes and every plugin reads. Fixed here rather than configurable: ten
// mounts with a spelling knob each is ten places a typo reads as "this unit has no parent", and
// accepting a second spelling later is additive.
const (
	// MetaParentEntityID is the ENTITY ID of the parent, not a name: it is what EntityInfo takes,
	// which is what lets a role check that the parent is still present and enabled.
	MetaParentEntityID = "cloud_creds_parent_entity_id"
	// MetaUnitID is the provisioner's own stable name for this unit, recorded but never checked —
	// it is for a human reading a report, and an entity can be renamed while this cannot.
	MetaUnitID = "cloud_creds_unit_id"
)

// Source names where a resolved lineage came from. Recorded because the three differ in who could
// have written them: a login rewrites alias metadata on every use, so on a SHARED alias that value is
// whichever unit logged in last, while custom_metadata is written deliberately and stays put.
type Source string

const (
	SourceAliasCustomMetadata Source = "alias_custom_metadata"
	SourceAliasMetadata       Source = "alias_metadata"
	SourceEntityMetadata      Source = "entity_metadata"
)

// Field names stamped onto a tracking record, spelled `requested_by_*` to match pkg/requester so one
// report reads one vocabulary.
const (
	FieldParentEntityID = "requested_by_parent_entity_id"
	FieldUnitID         = "requested_by_unit_id"
	FieldSource         = "requested_by_lineage_source"
)

// Lineage is what this mount could establish about the caller's parent. A zero value means nothing
// was established, which is a legitimate answer and not an error.
type Lineage struct {
	ParentEntityID string
	UnitID         string
	Source         Source
}

// Resolve reads the caller's lineage from the identity store, or returns a zero Lineage.
//
// Returns rather than errors on every absence: a root token has no entity, a mount may serve callers
// nobody has adopted, and a role that does not demand lineage must keep issuing to them. Enforce is
// where absence becomes a refusal.
//
// Two aliases naming DIFFERENT parents resolve to nothing. Picking one would be a coin flip between
// two services, and a credential attributed to the wrong service is worse than one attributed to
// none — a responder chases the wrong unit while the real one keeps its access.
func Resolve(req *logical.Request, view logical.SystemView) Lineage {
	if req == nil || req.EntityID == "" || view == nil {
		return Lineage{}
	}
	entity, err := view.EntityInfo(req.EntityID)
	if err != nil || entity == nil {
		return Lineage{}
	}

	var found Lineage
	for _, alias := range entity.Aliases {
		if alias == nil {
			continue
		}
		for _, candidate := range []struct {
			meta   map[string]string
			source Source
		}{
			{alias.CustomMetadata, SourceAliasCustomMetadata},
			{alias.Metadata, SourceAliasMetadata},
		} {
			next := fromMetadata(candidate.meta, candidate.source)
			if next.ParentEntityID == "" {
				continue
			}
			if found.ParentEntityID != "" && found.ParentEntityID != next.ParentEntityID {
				return Lineage{}
			}
			if found.ParentEntityID == "" {
				found = next
			}
		}
	}
	if found.ParentEntityID != "" {
		return found
	}
	return fromMetadata(entity.Metadata, SourceEntityMetadata)
}

func fromMetadata(meta map[string]string, source Source) Lineage {
	if meta[MetaParentEntityID] == "" {
		return Lineage{}
	}
	return Lineage{
		ParentEntityID: meta[MetaParentEntityID],
		UnitID:         meta[MetaUnitID],
		Source:         source,
	}
}
```

Note the import block has only `logical` at this point. Task 3 adds `fmt` and `credenvelope` along
with the first code that uses them; do not import them early, or `make lint` fails on unused imports.

- [x] **Step 5: Run the test to verify it passes**

Run: `go test github.com/nicois/openbao-cloud-creds/pkg/lineage/...`
Expected: PASS (2 tests).

- [x] **Step 6: Add the cases the first two do not reach**

Append to `pkg/lineage/lineage_test.go`:

```go
func TestResolveFallsBackThroughTheSources(t *testing.T) {
	for _, tc := range []struct {
		name   string
		entity *logical.Entity
		want   Source
	}{
		{
			name: "alias metadata when custom is empty",
			entity: &logical.Entity{ID: "child", Aliases: []*logical.Alias{{
				Name: "child", Metadata: map[string]string{MetaParentEntityID: "service"},
			}}},
			want: SourceAliasMetadata,
		},
		{
			name: "entity metadata when no alias carries it",
			entity: &logical.Entity{
				ID:       "child",
				Metadata: map[string]string{MetaParentEntityID: "service"},
				Aliases:  []*logical.Alias{{Name: "child"}},
			},
			want: SourceEntityMetadata,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := &mapSystemView{entities: map[string]*logical.Entity{"child": tc.entity}}
			got := Resolve(&logical.Request{EntityID: "child"}, view)
			if got.ParentEntityID != "service" || got.Source != tc.want {
				t.Errorf("Resolve = %+v, want parent %q from %q", got, "service", tc.want)
			}
		})
	}
}

func TestResolveRefusesToChooseBetweenTwoParents(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{"child": {
		ID: "child",
		Aliases: []*logical.Alias{
			{Name: "a", CustomMetadata: map[string]string{MetaParentEntityID: "service-a"}},
			{Name: "b", CustomMetadata: map[string]string{MetaParentEntityID: "service-b"}},
		},
	}}}

	if got := Resolve(&logical.Request{EntityID: "child"}, view); got.ParentEntityID != "" {
		t.Errorf("Resolve with conflicting aliases = %+v, want zero: naming one of two "+
			"services is misattribution", got)
	}
}
```

- [x] **Step 7: Run and verify all four pass**

Run: `go test -race github.com/nicois/openbao-cloud-creds/pkg/lineage/...`
Expected: PASS.

- [x] **Step 8: Commit**

```bash
git add go.work pkg/lineage
git commit -m "feat(lineage): resolve a caller's parent from the identity store"
```

---

### Task 2: `caller_unparented` error code

**Files:**
- Modify: `pkg/credenvelope/errors.go:59-65` (declaration block), `:85-92` (`AllCodes`)
- Test: `pkg/credenvelope/errors_test.go`

The code is a spec change (CLAUDE.md: techrfc + `docs/design.md` table + `AllCodes()`), and it earns one
because the client's action differs from `caller_unidentified`: re-presenting under a service token does
not help, the caller's provisioner has to record its lineage.

- [x] **Step 1: Write the failing test**

Append to `pkg/credenvelope/errors_test.go`:

```go
func TestCallerUnparentedIsInTheVocabulary(t *testing.T) {
	if !slices.Contains(AllCodes(), ErrCallerUnparented) {
		t.Errorf("AllCodes() omits %q, so the conformance taxonomy cannot accept it",
			ErrCallerUnparented)
	}
}
```

Add `"slices"` to that file's imports if it is not already there.

- [x] **Step 2: Run it to verify it fails**

Run: `go test github.com/nicois/openbao-cloud-creds/pkg/credenvelope/... -run Unparented`
Expected: FAIL — `undefined: ErrCallerUnparented`.

- [x] **Step 3: Add the code**

In `pkg/credenvelope/errors.go`, directly after the `ErrCallerUnidentified` declaration:

```go
	// ErrCallerUnparented: the role requires the caller's LINEAGE and this mount could not
	// establish it — no parent recorded against the caller's entity, or a parent that is now
	// absent or disabled. Its own code rather than reusing ErrCallerUnidentified because the
	// remedy is different and not the caller's to apply with a different token: core named the
	// caller fine, and what is missing is the provisioner's record of whose unit it is (or the
	// parent has been disabled deliberately, in which case the refusal is the system working).
	ErrCallerUnparented ErrorCode = "caller_unparented"
```

And in `AllCodes()`, extend the second line so it reads:

```go
		ErrCredentialKindUnsupported, ErrCallerUnidentified, ErrCallerUnparented,
```

- [x] **Step 4: Run the test to verify it passes**

Run: `go test github.com/nicois/openbao-cloud-creds/pkg/credenvelope/...`
Expected: PASS.

- [x] **Step 5: Record the spec change**

In `docs/design.md`, add a row to the error-code table immediately below the `caller_unidentified` row:

```markdown
| `caller_unparented` | 403 | The role sets `require_caller_lineage` and this mount could not establish the caller's parent, or the parent's entity is absent or disabled | **No** — the caller's provisioner must record its lineage, or an operator has disabled the parent deliberately |
```

In `docs/techrfc.md:168`, extend the roles-endpoint row: after the `require_caller_identity`
sentence, add — `and `require_caller_lineage` (`none` default / `parent` / `live_parent`, added
2026-09-21) which refuses a caller whose parent this mount cannot establish, or whose parent entity is
absent or disabled; refusals carry `caller_unparented`.`

- [x] **Step 6: Commit**

```bash
git add pkg/credenvelope docs/design.md docs/techrfc.md
git commit -m "feat(errors): add caller_unparented to the code vocabulary"
```

---

### Task 3: the requirement vocabulary and `Enforce`

**Files:**
- Modify: `pkg/lineage/lineage.go`, `pkg/lineage/go.mod` (no change if Task 1 already requires credenvelope)
- Test: `pkg/lineage/lineage_test.go`

- [x] **Step 1: Write the failing test**

Append to `pkg/lineage/lineage_test.go`:

```go
func TestEnforce(t *testing.T) {
	child := aliasWithCustom("child", map[string]string{MetaParentEntityID: "service"})
	orphan := aliasWithCustom("orphan", map[string]string{MetaParentEntityID: "gone"})

	for _, tc := range []struct {
		name     string
		entities map[string]*logical.Entity
		entityID string
		value    string
		refused  bool
	}{
		{
			name:     "none issues to a caller with no lineage at all",
			entities: map[string]*logical.Entity{"bare": {ID: "bare"}},
			entityID: "bare", value: string(RequireNone), refused: false,
		},
		{
			name:     "parent refuses a caller with no lineage",
			entities: map[string]*logical.Entity{"bare": {ID: "bare"}},
			entityID: "bare", value: string(RequireParent), refused: true,
		},
		{
			name: "parent accepts a recorded parent without checking it",
			entities: map[string]*logical.Entity{"orphan": orphan},
			entityID: "orphan", value: string(RequireParent), refused: false,
		},
		{
			name:     "live_parent refuses a parent that has been deleted",
			entities: map[string]*logical.Entity{"orphan": orphan},
			entityID: "orphan", value: string(RequireLiveParent), refused: true,
		},
		{
			name: "live_parent refuses a parent that is disabled",
			entities: map[string]*logical.Entity{
				"child": child, "service": {ID: "service", Disabled: true},
			},
			entityID: "child", value: string(RequireLiveParent), refused: true,
		},
		{
			name: "live_parent accepts a present enabled parent",
			entities: map[string]*logical.Entity{
				"child": child, "service": {ID: "service"},
			},
			entityID: "child", value: string(RequireLiveParent), refused: false,
		},
		{
			name: "live_parent refuses a unit that named itself",
			entities: map[string]*logical.Entity{
				"self": aliasWithCustom("self", map[string]string{MetaParentEntityID: "self"}),
			},
			entityID: "self", value: string(RequireLiveParent), refused: true,
		},
		{
			name:     "an unreadable requirement fails closed",
			entities: map[string]*logical.Entity{"child": child, "service": {ID: "service"}},
			entityID: "child", value: "whatever-a-newer-binary-wrote", refused: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := &mapSystemView{entities: tc.entities}
			resp := Enforce(&logical.Request{EntityID: tc.entityID}, view, tc.value)
			if tc.refused != (resp != nil) {
				t.Fatalf("Enforce refused=%v, want %v (resp %v)", resp != nil, tc.refused, resp)
			}
		})
	}
}

func TestParseRequirementTreatsEmptyAsNone(t *testing.T) {
	got, err := ParseRequirement("")
	if err != nil || got != RequireNone {
		t.Errorf("ParseRequirement(\"\") = %q, %v; want %q, nil — a role persisted before this "+
			"field existed must still load", got, err, RequireNone)
	}
}
```

- [x] **Step 2: Run it to verify it fails**

Run: `go test github.com/nicois/openbao-cloud-creds/pkg/lineage/... -run 'Enforce|ParseRequirement'`
Expected: FAIL — `undefined: RequireNone`, `undefined: Enforce`.

- [x] **Step 3: Implement**

In `pkg/lineage/lineage.go`, delete the two `var _ =` placeholder lines from Task 1 and append:

```go
// FieldRequireCallerLineage is the ROLE field demanding that this mount can say whose unit the caller
// is. Spelled once here so ten plugins agree on it.
const FieldRequireCallerLineage = "require_caller_lineage"

// Requirement is how much of a caller's lineage a role insists on.
//
// Separate from pkg/requester's require_caller_identity rather than a fourth value on it, because the
// two are ORTHOGONAL, not a ladder: a batch-token caller has no accessor and may still have a
// perfectly good parent, while a service token with an accessor may have none. Folding them into one
// field would force an operator to choose between two unrelated demands.
type Requirement string

const (
	// RequireNone issues to anyone, recording lineage when it resolves. The default, because every
	// role written before this field existed must keep issuing what it issued.
	RequireNone Requirement = "none"
	// RequireParent refuses a caller this mount can establish no parent for. It costs one
	// EntityInfo — the one Resolve already makes — and says nothing about whether that parent
	// still exists.
	RequireParent Requirement = "parent"
	// RequireLiveParent additionally re-reads the parent's own entity and refuses when it is
	// absent or disabled. This is the containment value: disabling one service's entity stops
	// every unit beneath it from obtaining new credentials on every cloud at once, with no sweep
	// and no worker. It costs one additional EntityInfo per issuance, which is a MemDB read in
	// the core process, not an upstream call.
	RequireLiveParent Requirement = "live_parent"
)

// Requirements is the accepted vocabulary, for a field description and for validation.
func Requirements() []Requirement {
	return []Requirement{RequireNone, RequireParent, RequireLiveParent}
}

// ParseRequirement validates a stored or submitted value. An empty string is RequireNone, so a role
// persisted before this field existed parses rather than failing closed on every read.
func ParseRequirement(value string) (Requirement, error) {
	if value == "" {
		return RequireNone, nil
	}
	for _, known := range Requirements() {
		if Requirement(value) == known {
			return known, nil
		}
	}
	return RequireNone, fmt.Errorf("%s must be one of %s, %s or %s, not %q",
		FieldRequireCallerLineage, RequireNone, RequireParent, RequireLiveParent, value)
}

// Enforce returns the refusal a role's stored requirement demands, or nil to proceed.
//
// Shaped exactly like requester.Enforce — it takes the raw stored string, parses it here so an
// unrecognised value fails closed at one site, and returns the RESPONSE so ten plugins cannot drift
// into ten wordings. Called BEFORE a minter is selected, so a refused request costs the upstream
// nothing.
func Enforce(req *logical.Request, view logical.SystemView, value string) *logical.Response {
	requirement, err := ParseRequirement(value)
	if err != nil {
		// Fail CLOSED on a value this binary does not understand: treating it as RequireNone would
		// turn a role written by a newer binary into one that issues to anybody.
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error())
	}
	if requirement == RequireNone {
		return nil
	}

	found := Resolve(req, view)
	if found.ParentEntityID == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and no parent is recorded against this caller's identity "+
				"(expected %s in an entity alias's custom_metadata or metadata, or on the entity); "+
				"the unit's provisioner records it",
			FieldRequireCallerLineage, requirement, MetaParentEntityID)
	}
	if requirement == RequireParent {
		return nil
	}

	if found.ParentEntityID == req.EntityID {
		// A unit that named itself is its own parent, which is a lineage of one and no lineage at
		// all. Refused here rather than in Resolve so `parent` stays the cheap "is anything
		// recorded" check and the cycle rule lives with the liveness rule it belongs to.
		return credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and the caller names ITSELF as its parent",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	parent, err := view.EntityInfo(found.ParentEntityID)
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrEntityUnavailable,
			"this role requires %s=%s and the caller's parent entity could not be read",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	if parent == nil {
		return credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and the caller's parent entity no longer exists",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	if parent.Disabled {
		return credenvelope.ErrorResponse(credenvelope.ErrCallerUnparented,
			"this role requires %s=%s and the caller's parent entity is disabled",
			FieldRequireCallerLineage, RequireLiveParent)
	}
	return nil
}

// RoleFieldDescription is the help text for the role field, so an operator reads the same explanation
// on every cloud.
func RoleFieldDescription() string {
	return "Whose unit this role will issue to: " + string(RequireNone) +
		" (anyone; lineage is still recorded when it resolves), " + string(RequireParent) +
		" (refuse a caller no parent is recorded for), or " + string(RequireLiveParent) +
		" (additionally refuse when that parent's entity is absent or disabled, which is what " +
		"makes disabling a service stop its units from obtaining new credentials). Lineage is " +
		"read from " + MetaParentEntityID + " on the caller's entity alias (custom_metadata, " +
		"then metadata) or the entity itself, and there is no request parameter for it. " +
		"Defaults to " + string(RequireNone)
}
```

Check `ErrEntityUnavailable` exists before using it:

```bash
grep -n "ErrEntityUnavailable" pkg/credenvelope/errors.go
```

If it does not, use `credenvelope.ErrInternal` instead and drop that branch's distinct wording.

- [x] **Step 4: Run the tests to verify they pass**

Run: `go test -race github.com/nicois/openbao-cloud-creds/pkg/lineage/...`
Expected: PASS (all cases, including the eight `Enforce` subtests).

- [x] **Step 5: Commit**

```bash
git add pkg/lineage
git commit -m "feat(lineage): refuse a caller whose parent is missing, deleted or disabled"
```

---

### Task 4: stamp the record and publish it on `issued/`

**Files:**
- Modify: `pkg/lineage/lineage.go` (add `Stamp`), `pkg/issuedlist/issuedlist.go:78-83`, `pkg/issuedlist/go.mod`
- Test: `pkg/lineage/lineage_test.go`, `pkg/issuedlist/issuedlist_test.go`

- [x] **Step 1: Write the failing tests**

Append to `pkg/lineage/lineage_test.go`:

```go
func TestStampAddsOnlyWhatResolved(t *testing.T) {
	view := &mapSystemView{entities: map[string]*logical.Entity{
		"child": aliasWithCustom("child", map[string]string{
			MetaParentEntityID: "service", MetaUnitID: "unit-7",
		}),
	}}

	record := map[string]any{"role": "reader"}
	Stamp(record, &logical.Request{EntityID: "child"}, view)

	for key, want := range map[string]any{
		"role": "reader", FieldParentEntityID: "service", FieldUnitID: "unit-7",
		FieldSource: string(SourceAliasCustomMetadata),
	} {
		if record[key] != want {
			t.Errorf("record[%q] = %v, want %v", key, record[key], want)
		}
	}
}

func TestStampAddsNothingWhenNothingResolved(t *testing.T) {
	record := map[string]any{"role": "reader"}
	Stamp(record, &logical.Request{}, &mapSystemView{})

	if len(record) != 1 {
		t.Errorf("record = %v, want only its original key: an absent parent must not be "+
			"recorded as an empty one, which a report would read as a unit with no service",
			record)
	}
}
```

Append to `pkg/issuedlist/issuedlist_test.go`:

```go
func TestFieldsPublishesLineage(t *testing.T) {
	for _, field := range []string{
		lineage.FieldParentEntityID, lineage.FieldUnitID, lineage.FieldSource,
	} {
		if !slices.Contains(Fields(), field) {
			t.Errorf("Fields() omits %q, so issued/ cannot answer whose unit holds a credential",
				field)
		}
	}
}
```

Add the imports that file needs (`slices`, and
`github.com/nicois/openbao-cloud-creds/pkg/lineage`).

- [x] **Step 2: Run them to verify they fail**

Run: `go test github.com/nicois/openbao-cloud-creds/pkg/lineage/... github.com/nicois/openbao-cloud-creds/pkg/issuedlist/...`
Expected: FAIL — `undefined: Stamp`; and the issuedlist module cannot resolve `pkg/lineage`.

- [x] **Step 3: Implement**

Append to `pkg/lineage/lineage.go`:

```go
// Stamp copies the resolvable lineage fields into an existing tracking record.
//
// Takes the record rather than returning a new map, for the reason requester.Stamp does: a plugin
// must not be able to build its record from lineage alone and lose its own fields. Writes nothing
// when nothing resolved — an empty parent recorded as a field would read, in a report, as a unit
// whose service is the empty string rather than as a unit nobody has claimed.
func Stamp(record map[string]any, req *logical.Request, view logical.SystemView) map[string]any {
	found := Resolve(req, view)
	if found.ParentEntityID == "" {
		return record
	}
	record[FieldParentEntityID] = found.ParentEntityID
	record[FieldSource] = string(found.Source)
	if found.UnitID != "" {
		record[FieldUnitID] = found.UnitID
	}
	return record
}
```

In `pkg/issuedlist/go.mod`, add the require and replace:

```
	github.com/nicois/openbao-cloud-creds/pkg/lineage v0.5.0
```
```
replace github.com/nicois/openbao-cloud-creds/pkg/lineage => ../lineage
```

In `pkg/issuedlist/issuedlist.go`, import `"github.com/nicois/openbao-cloud-creds/pkg/lineage"` and
extend `Fields()` so the returned slice reads:

```go
	return []string{
		"role", "minter", "minter_set", "created", "expires_at", "app_object_id",
		requester.FieldTokenAccessor, requester.FieldEntityID,
		lineage.FieldParentEntityID, lineage.FieldUnitID, lineage.FieldSource,
	}
```

- [x] **Step 4: Run to verify they pass**

Run: `go test -race github.com/nicois/openbao-cloud-creds/pkg/lineage/... github.com/nicois/openbao-cloud-creds/pkg/issuedlist/...`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add pkg/lineage pkg/issuedlist
git commit -m "feat(issued): publish the caller's lineage on the inventory"
```

---

### Task 5: wire the reference plugin (`credential-do`) end to end

**Files:**
- Modify: `plugins/credential-do/consts.go`, `plugins/credential-do/path_roles.go:43,153,285`, `plugins/credential-do/path_creds.go:67,181`, `plugins/credential-do/go.mod`
- Test: `plugins/credential-do/path_creds_test.go`

Do DO alone first and completely: it is the reference implementation, and the conformance category in
Task 7 needs one subject that already passes before nine more are touched.

- [x] **Step 1: Write the failing test**

Append to `plugins/credential-do/spaces_roles_test.go`, which already has the two helpers this needs —
`spacesRoleSetup(t)` (a backend with the `default` minter set written) and
`writeRole(t, b, storage, name, data)` (returns the response without failing, for cases expecting a
refusal). The package is `credentialdo_test`.

No system-view override is needed for this test: `logical.TestBackendConfig()` uses
`logical.StaticSystemView`, whose `EntityInfo` returns a nil entity for every id — which is exactly
"this caller has no lineage", the case under test. The positive path (a parent that resolves) is
covered by the conformance category in Task 7, which controls the identity.

```go
func TestIssuanceRefusesAnUnparentedCallerWhenTheRoleDemandsLineage(t *testing.T) {
	b, storage := spacesRoleSetup(t)
	if resp := writeRole(t, b, storage, "reader", map[string]any{
		"credential_type":                 "spaces_key",
		"region":                          "syd1",
		"grants":                          "read:example-bucket",
		lineage.FieldRequireCallerLineage: string(lineage.RequireLiveParent),
	}); resp != nil && resp.IsError() {
		t.Fatalf("writing a role with %s was refused: %v",
			lineage.FieldRequireCallerLineage, resp.Error())
	}

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/reader", Storage: storage,
		ClientTokenAccessor: "an-accessor", EntityID: "child-with-no-parent",
	})
	if err != nil {
		t.Fatalf("request returned a hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("issuance succeeded for an unparented caller; want a refusal: %v", resp)
	}
	if code := resp.Data["error_code"]; code != string(credenvelope.ErrCallerUnparented) {
		t.Errorf("error_code = %v, want %q", code, credenvelope.ErrCallerUnparented)
	}
}
```

Copy the `credential_type`/`region`/`grants` values from a neighbouring test in that file rather than
trusting these — they must be a role shape the plugin already accepts, or the test fails for the wrong
reason.

- [x] **Step 2: Run it to verify it fails**

Run: `go test github.com/nicois/openbao-cloud-creds/plugins/credential-do/... -run Unparented`
Expected: FAIL — the role field is unknown, so the write is rejected or ignored and issuance succeeds.

- [x] **Step 3: Add the role field**

In `plugins/credential-do/consts.go`, beside the existing `fieldRequireCallerIdentity` const, add:

```go
	// fieldRequireCallerLineage is lineage.FieldRequireCallerLineage, named locally for the same
	// reason every other field is: one spelling per plugin, checked by lint.
	fieldRequireCallerLineage = lineage.FieldRequireCallerLineage
```

In `path_roles.go`, mirror the three places `require_caller_identity` appears:
1. the role struct — add `RequireCallerLineage string \`json:"require_caller_lineage"\`` beside
   `RequireCallerIdentity`, with a comment noting an empty value is `lineage.RequireNone` so a role
   persisted before the field loads;
2. the field schema map (near `:153`) —
   ```go
   		fieldRequireCallerLineage: {
   			Type:        framework.TypeString,
   			Description: lineage.RoleFieldDescription(),
   		},
   ```
3. the write path (near `:285`) — validate and persist:
   ```go
   	requireCallerLineage := data.Get(fieldRequireCallerLineage).(string)
   	if _, err := lineage.ParseRequirement(requireCallerLineage); err != nil {
   		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
   	}
   ```
   and set it on the stored role; also add it to the role READ response beside
   `require_caller_identity` — a field the read path omits is erased by the next partial write
   (the `PrefillRoleWrite` hazard named in `docs/decisions.md`).

- [x] **Step 4: Enforce and stamp**

In `path_creds.go`, immediately after the existing `requester.Enforce` block at `:67`:

```go
	// Checked here, beside the identity requirement and before a minter is selected, so a refused
	// request costs the upstream nothing.
	if resp := lineage.Enforce(req, b.System(), role.RequireCallerLineage); resp != nil {
		return resp, nil
	}
```

And at the tracking-record assembly at `:181`, wrap the existing `requester.Stamp(...)` call so both
stamps apply to the same map:

```go
		lineage.Stamp(requester.Stamp(map[string]any{
			// ... existing record fields unchanged ...
		}, req), req, b.System()),
```

Add `"github.com/nicois/openbao-cloud-creds/pkg/lineage"` to both files' imports, and to
`plugins/credential-do/go.mod` add the require and `replace ... => ../../pkg/lineage`.

- [x] **Step 5: Run to verify it passes**

Run: `go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-do/...`
Expected: PASS, including the new test and every existing one.

- [x] **Step 6: Commit**

```bash
git add plugins/credential-do
git commit -m "feat(do): record and enforce the caller's lineage"
```

---

### Task 6: a conformance-harness hook for a controlled identity

**Files:**
- Modify: `pkg/plugintest/harness.go:302` area (add the field), `:325-365` (the three constructors)
- Test: exercised by Task 7; no separate test (it is test infrastructure, and an unused hook would be dead code — Task 7 lands in the same PR)

- [x] **Step 1: Add the hook**

In `pkg/plugintest/harness.go`, add to the `Harness` struct immediately before `Skips`:

```go
	// SystemView, when set, replaces the default logical.TestBackendConfig() system view for
	// every backend this harness builds. The lineage category needs it: the SDK's
	// StaticSystemView answers EntityInfo with one entity for EVERY id, which cannot express
	// "the caller's parent is a different entity" — the whole relationship under test.
	SystemView logical.SystemView
```

- [x] **Step 2: Honour it in all three constructors**

In `newBackendWithStorage`, `newBackend` and `Reload`, immediately after each
`cfg := logical.TestBackendConfig()`:

```go
	if h.SystemView != nil {
		cfg.System = h.SystemView
	}
```

All three, deliberately: `Reload` builds a fresh backend from persisted storage, and a reload that
lost the test's identity would fail the category for a reason that is not about the plugin.

- [x] **Step 3: Verify nothing broke**

Run: `make test-conformance`
Expected: PASS, unchanged — no harness sets the field yet.

- [x] **Step 4: Commit**

```bash
git add pkg/plugintest/harness.go
git commit -m "test(plugintest): let a harness supply the system view"
```

---

### Task 7: the `lineage` conformance category

**Files:**
- Create: `pkg/plugintest/lineage.go`
- Modify: `pkg/plugintest/harness.go` (category const), `pkg/plugintest/conformance.go` (register), all twelve `conformance/harness_*_test.go`
- Test: `make test-conformance`

- [x] **Step 1: Declare the category**

In `pkg/plugintest/harness.go`, after `CategoryInventory`:

```go
	// CategoryLineage covers WHOSE unit obtained a credential: a role can demand the caller's
	// parent, the refusal is a stable code, the recorded parent comes only from fields a client
	// cannot write, and a parent that is disabled or deleted stops issuance at once.
	CategoryLineage Category = "lineage"
```

Add `CategoryLineage` to whatever list `conformance.go` iterates (find it with
`grep -n "CategoryInventory" pkg/plugintest/conformance.go`).

- [x] **Step 2: Write the identity double**

Create `pkg/plugintest/lineage.go`. Note what it does NOT need: no harness file changes. Each case
copies the `Harness` (a struct, so a copy is free) and sets its own `SystemView`, which is why the
category's `requires` is nil and no subject can opt out by forgetting to wire something.

```go
package plugintest

import (
	"sync/atomic"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/lineage"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The lineage the suite presents, beside provenance's suiteEntityID/suiteTokenAccessor.
const (
	suiteParentEntityID = "conformance-parent-entity-id"
	suiteUnitID         = "conformance-unit-7"
	// suiteUnparentedEntityID is a caller core resolved an entity for, against which no parent
	// is recorded — a unit nobody has claimed, which is the shape a role refuses.
	suiteUnparentedEntityID = "conformance-unparented-entity-id"
)

// lineageView is the identity a lineage case builds its subject over: the suite's caller carries a
// parent in its alias custom_metadata, and that parent is a SECOND entity the case can disable.
//
// It exists because logical.StaticSystemView answers EntityInfo with one entity for every id, which
// cannot express "the caller's parent is a different entity" — the whole relationship under test.
type lineageView struct {
	logical.StaticSystemView
	parentDisabled atomic.Bool
}

// EntityInfo answers for the caller and its parent, and nil for every other id — an unknown id must
// read as "no such entity", which is what a DELETED parent looks like from inside a plugin.
func (v *lineageView) EntityInfo(entityID string) (*logical.Entity, error) {
	switch entityID {
	case suiteEntityID:
		return &logical.Entity{ID: suiteEntityID, Aliases: []*logical.Alias{{
			Name: suiteEntityID,
			CustomMetadata: map[string]string{
				lineage.MetaParentEntityID: suiteParentEntityID,
				lineage.MetaUnitID:         suiteUnitID,
			},
		}}}, nil
	case suiteParentEntityID:
		return &logical.Entity{ID: suiteParentEntityID, Disabled: v.parentDisabled.Load()}, nil
	case suiteUnparentedEntityID:
		return &logical.Entity{ID: suiteUnparentedEntityID, Aliases: []*logical.Alias{{
			Name: suiteUnparentedEntityID,
		}}}, nil
	}
	return nil, nil
}

// withLineageIdentity copies the harness onto a fresh identity, so one case disabling a parent
// cannot leak into another case or another category.
func withLineageIdentity(h Harness) (Harness, *lineageView) {
	view := &lineageView{}
	h.SystemView = view
	return h, view
}

// requireLineage sets the role's requirement through the role's own write path — which is also an
// assertion, for the reason requireCaller gives: a requirement an operator can only set by rewriting
// the whole role is not one they can add to a role that is already live.
func requireLineage(t *testing.T, b logical.Backend, storage logical.Storage,
	rolePath string, requirement lineage.Requirement,
) {
	t.Helper()
	resp := TryWrite(t, b, storage, rolePath, map[string]any{
		lineage.FieldRequireCallerLineage: string(requirement),
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("writing %s=%s to %s was refused: %v", lineage.FieldRequireCallerLineage,
			requirement, rolePath, resp.Error())
	}
}

// issueAsUnparented reads the issue path as a caller with an entity and an accessor but no recorded
// parent — so a refusal can only be about lineage, not about pkg/requester's requirement.
func issueAsUnparented(t *testing.T, b logical.Backend, storage logical.Storage,
	path string, data map[string]any,
) *logical.Response {
	t.Helper()
	return issueWith(t, b, storage, path, &logical.Request{
		ClientTokenAccessor: suiteTokenAccessor,
		EntityID:            suiteUnparentedEntityID,
		Data:                data,
	})
}
```

- [x] **Step 3: Write the five cases**

Append to `pkg/plugintest/lineage.go`:

```go
// RunLineageSuite covers WHOSE unit obtained a credential: that a role can demand the caller's
// parent, that the demand is checked before anything is minted, that a parent an operator has
// disabled stops issuance at once, that the caller cannot supply its own lineage, and that the
// record names it.
//
// Four of the five cases apply to every subject, because refusing to issue to an unclaimed unit is
// not a question about a cloud. Only the recording case needs a per-read tracking record, and it
// gates on the same helper the provenance suite uses so there is ONE way to say "this subject
// records nothing per read".
func RunLineageSuite(t *testing.T, h Harness) {
	for _, c := range []struct {
		name string
		run  func(*testing.T, Harness)
	}{
		{"ARoleCanRequireTheCallersParent", lineageRequireParent},
		{"ADisabledParentStopsIssuanceAtOnce", lineageDisabledParentStopsIssuance},
		{"LineageCannotBeForgedByTheCaller", lineageCannotBeForged},
		{"RefusingAnUnparentedCallerCostsTheUpstreamNothing", lineageRefusalMintsNothing},
		{"AnIssuedCredentialRecordsWhoseUnitObtainedIt", lineageRecordsTheParent},
	} {
		t.Run(c.name, func(t *testing.T) { c.run(t, h) })
	}
}

// lineageRequireParent: live_parent refuses an unclaimed unit and issues to a claimed one.
func lineageRequireParent(t *testing.T, h Harness) {
	h, _ = withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)
	requireLineage(t, b, storage, h.RolePath, lineage.RequireLiveParent)

	resp := issueAsUnparented(t, b, storage, h.IssuePath, nil)
	assertCode(t, resp, credenvelope.ErrCallerUnparented,
		"issuing to a caller no parent is recorded for, from a role requiring one")

	if resp := issueAsCaller(t, b, storage, h.IssuePath, nil); resp == nil || resp.IsError() {
		t.Fatalf("a role requiring %s refused a caller whose parent is present and enabled: %v",
			lineage.RequireLiveParent, resp)
	}
}

// lineageDisabledParentStopsIssuance: disabling the PARENT's entity stops the child at once.
//
// This case is why the requirement has a live_parent value at all. Nothing else changes between the
// two reads — no role write, no config write, no worker tick, no revocation — so what it pins is
// that one operator action against one identity stops issuance to every unit beneath it, on every
// cloud, without this mount being told.
func lineageDisabledParentStopsIssuance(t *testing.T, h Harness) {
	h, view := withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)
	requireLineage(t, b, storage, h.RolePath, lineage.RequireLiveParent)

	if resp := issueAsCaller(t, b, storage, h.IssuePath, nil); resp == nil || resp.IsError() {
		t.Fatalf("the first read failed, so this case would prove nothing: %v", resp)
	}

	view.parentDisabled.Store(true)

	resp := issueAsCaller(t, b, storage, h.IssuePath, nil)
	assertCode(t, resp, credenvelope.ErrCallerUnparented,
		"issuing to a caller whose parent entity has been disabled")
}

// lineageCannotBeForged: a caller supplying its own lineage does not satisfy the requirement.
//
// The same reasoning as the provenance suite's forgery case, and the reason pkg/lineage has no
// request parameter: a forgeable parent would let any unit claim a live service and be served,
// which is worse than being refused — the credential would then be recorded against a service that
// never asked for it.
func lineageCannotBeForged(t *testing.T, h Harness) {
	h, _ = withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)
	requireLineage(t, b, storage, h.RolePath, lineage.RequireLiveParent)

	forged := map[string]any{
		lineage.FieldParentEntityID:       suiteParentEntityID,
		lineage.MetaParentEntityID:        suiteParentEntityID,
		lineage.FieldRequireCallerLineage: string(lineage.RequireNone),
	}
	resp := issueAsUnparented(t, b, storage, h.IssuePath, forged)
	assertCode(t, resp, credenvelope.ErrCallerUnparented,
		"issuing to an unparented caller that supplied a parent of its own in the request")
}

// lineageRefusalMintsNothing: the check happens before a minter is selected.
//
// Placement is the whole assertion, exactly as it is for provenance: a requirement checked after the
// mint leaves a credential upstream that no lease, no tracking record and no reconciler pass knows
// about — an orphan created by a security control.
func lineageRefusalMintsNothing(t *testing.T, h Harness) {
	h, _ = withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)
	requireLineage(t, b, storage, h.RolePath, lineage.RequireLiveParent)

	before := h.ProvisionedCount()
	resp := issueAsUnparented(t, b, storage, h.IssuePath, nil)
	assertCode(t, resp, credenvelope.ErrCallerUnparented, "the refused read")

	if after := h.ProvisionedCount(); after != before {
		t.Errorf("a refused read moved the upstream credential count from %d to %d: the "+
			"requirement is being checked after the mint, so every refusal leaves an orphan",
			before, after)
	}
	if h.TrackingPrefix != "" {
		if n := trackingRecords(t, storage, h.TrackingPrefix); n != 0 {
			t.Errorf("a refused read left %d tracking record(s) under %s", n, h.TrackingPrefix)
		}
	}
}

// lineageRecordsTheParent: the record names the parent even when the role demands nothing.
//
// Deliberately run on a role with the DEFAULT requirement: recording is not conditional on
// enforcing. An operator who has not yet decided to refuse anyone still gets a report that answers
// whose unit holds each credential, which is the half of this feature that is useful on day one.
func lineageRecordsTheParent(t *testing.T, h Harness) {
	requireTrackingRecords(t, h)
	h, _ = withLineageIdentity(h)
	b, storage := newConfiguredBackend(t, h)

	if resp := issueAsCaller(t, b, storage, h.IssuePath, nil); resp == nil || resp.IsError() {
		t.Fatalf("the role could not issue, so this case would prove nothing: %v", resp)
	}

	record := soleTrackingRecord(t, storage, h.TrackingPrefix)
	assertRecordField(t, record, lineage.FieldParentEntityID, suiteParentEntityID)
	assertRecordField(t, record, lineage.FieldUnitID, suiteUnitID)
	assertRecordField(t, record, lineage.FieldSource, string(lineage.SourceAliasCustomMetadata))
}
```

Add the `pkg/lineage` require and `replace ... => ../lineage` to `pkg/plugintest/go.mod`.

- [x] **Step 4: Register the category**

In `pkg/plugintest/conformance.go`, add to the category table after the `CategoryInventory` entry:

```go
	{
		name: CategoryLineage,
		run:  RunLineageSuite,
		// Nothing cloud-specific and nothing to wire per subject: each case supplies its own
		// identity by copying the harness, so no cloud can opt out by omitting a field. The one
		// case needing a per-read tracking record gates itself and prints why.
		requires: func(_ Harness) []string { return nil },
	},
```

- [x] **Step 5: Run it — `do` passes, the other eleven fail**

Run: `make test-conformance`
Expected: `do` PASSES all five cases; the other eleven subjects FAIL on
`ARoleCanRequireTheCallersParent` because their role write path does not accept the field yet. That is
the failing test for Task 8.

- [x] **Step 6: Commit**

```bash
git add pkg/plugintest conformance
git commit -m "test(conformance): fence the lineage contract on every subject"
```

---

### Task 8: the remaining nine plugins

**Files (per plugin, nine times):**
- Modify: `plugins/credential-<name>/consts.go`, `path_roles.go`, `path_creds.go`, `go.mod`

The edit is byte-identical to Task 5 apart from the file paths, because the three seams are the same on
every cloud. Do them one at a time, committing each, so a failure names one cloud.

Plugins and their credential path, for the `Enforce` insertion point:

| Plugin | Enforce goes after the existing `requester.Enforce` in |
|---|---|
| `credential-aws` | `plugins/credential-aws/path_creds.go` |
| `credential-gcp` | `plugins/credential-gcp/path_creds.go` |
| `credential-azure` | `plugins/credential-azure/path_creds.go` |
| `credential-ovh` | `plugins/credential-ovh/path_creds.go` |
| `credential-upcloud` | `plugins/credential-upcloud/path_creds.go` |
| `credential-exoscale` | `plugins/credential-exoscale/path_creds.go` |
| `credential-vultr` | `plugins/credential-vultr/path_creds.go` |
| `credential-akamai` | `plugins/credential-akamai/path_creds.go` |
| `credential-oci` | `plugins/credential-oci/path_creds.go` |

- [x] **Step 1: For each plugin, add the const**

In `consts.go`, beside `fieldRequireCallerIdentity`:

```go
	fieldRequireCallerLineage = lineage.FieldRequireCallerLineage
```

- [x] **Step 2: For each plugin, add the role field**

In `path_roles.go`: the struct field
`RequireCallerLineage string \`json:"require_caller_lineage"\``; the schema entry

```go
		fieldRequireCallerLineage: {
			Type:        framework.TypeString,
			Description: lineage.RoleFieldDescription(),
		},
```

the write-path validation

```go
	requireCallerLineage := data.Get(fieldRequireCallerLineage).(string)
	if _, err := lineage.ParseRequirement(requireCallerLineage); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
```

persisting it onto the role, and the read-path response entry beside `require_caller_identity`.

- [x] **Step 3: For each plugin, enforce and stamp**

In `path_creds.go`, after the existing `requester.Enforce` block:

```go
	if resp := lineage.Enforce(req, b.System(), role.RequireCallerLineage); resp != nil {
		return resp, nil
	}
```

and at the tracking-record assembly, wrap the existing `requester.Stamp(...)`:

```go
		lineage.Stamp(requester.Stamp(map[string]any{
			// ... existing record fields unchanged ...
		}, req), req, b.System()),
```

OCI is the exception for the stamp only: it provisions slots outside a request, so pass the request
through where one exists and do not invent one where it does not — follow exactly what
`requester.Stamp` does there today (`grep -n "requester.Stamp" plugins/credential-oci/`), including
passing nil if that is what the rotation path does.

- [x] **Step 4: For each plugin, add the dependency**

In `go.mod`: `github.com/nicois/openbao-cloud-creds/pkg/lineage v0.5.0` and
`replace github.com/nicois/openbao-cloud-creds/pkg/lineage => ../../pkg/lineage`.

- [x] **Step 5: For each plugin, test and commit**

Run: `go test -race github.com/nicois/openbao-cloud-creds/plugins/credential-<name>/...`
Expected: PASS.

Then the subject's own conformance run, which is the real check:

```bash
go test github.com/nicois/openbao-cloud-creds/conformance/... -run 'TestConformance/<subject>/lineage' -v
```

Expected: five cases pass (four on subjects that record nothing per read, with the fifth printing its
skip reason). No harness file needs editing — the suite supplies its own identity.

```bash
git add plugins/credential-<name>
git commit -m "feat(<cloud>): record and enforce the caller's lineage"
```

- [x] **Step 6: Verify all ten are wired, not nine**

Run:

```bash
grep -rl "lineage.Enforce" plugins/*/path_creds.go | wc -l
```

Expected: `10`.

Run: `make test-conformance`
Expected: PASS, twelve subjects × thirteen categories, with the matrix printing the declared skips and
no others.

---

### Task 9: drive it over HTTP in `e2e/`

**Files:**
- Modify: `pkg/baotest/scenario.go`
- Test: `make test-e2e`

An assertion added here reaches every driven subject at once, which is why the scenario lives in
`pkg/baotest` rather than in `e2e/`.

- [x] **Step 1: Extend the scenario**

In `pkg/baotest/scenario.go`, find where the scenario LISTs `issued/` and asserts the entry names the
role and the caller. Add, in the same place, an assertion that when the case declares lineage the entry
carries `requested_by_parent_entity_id`. The scenario's own login is an AppRole in a live `bao`, so the
parent must be written for real: before issuing, write the alias's custom metadata over HTTP —

```
identity/entity-alias/id/<alias_id>   custom_metadata='{"cloud_creds_parent_entity_id":"<parent entity id>"}'
```

creating a second entity to be the parent (`identity/entity` write, name `baotest-parent`). This is the
one layer that proves the whole substrate contract rather than a stub of it: it shows a real OpenBao
returns that custom metadata through `EntityInfo` to an out-of-process plugin.

- [x] **Step 2: Run the e2e suite**

Run: `make test-e2e`
Expected: PASS for all nine driven subjects. If `EntityInfo` returns no custom metadata across the
plugin RPC boundary, STOP and record it in `docs/decisions.md`: the contract would then have to move
to alias `metadata` (written by the auth method) and the plan's substrate table is wrong. Verify
against `helper/identity/identity.go`'s `ToSDKAlias` before concluding — it does copy
`CustomMetadata`, so a failure here is more likely a missing entity/alias write in the scenario.

- [x] **Step 3: Commit**

```bash
git add pkg/baotest e2e
git commit -m "test(e2e): prove lineage crosses the plugin RPC boundary"
```

---

### Task 10: documentation and release

**Files:**
- Modify: `docs/ttl-semantics.md` (no change — verify), `docs/design.md`, `docs/techrfc.md`, `docs/decisions.md`, `docs/openbao-integration-gaps.md`, `CLAUDE.md`, every `go.mod` (version bump)

- [x] **Step 1: Write the rationale note**

In `docs/decisions.md`, under the 2026-09-21 lineage section already present, add a subsection "Why
lineage is read from the identity store and enforced at issuance" covering: why the identity store is
the only substrate (barrier-isolated mount storage), why there is no request parameter, why
`require_caller_lineage` is a separate field from `require_caller_identity` (orthogonal, not a ladder),
why `live_parent` costs a second `EntityInfo` and is worth it (it is a MemDB read, and it is what makes
disabling a service a cross-cloud containment lever), and why conflicting aliases resolve to nothing.

- [x] **Step 2: Update the contract docs**

- `docs/design.md`: the worked example for a credential read gains the three `requested_by_*` lineage
  fields; the error table row was added in Task 2 — check it is still accurate.
- `CLAUDE.md`: add lineage to the newest-work paragraph and to the conformance category list (now
  thirteen); state that `api_version` is **unchanged** — a tracking-record field and a role field are
  not envelope changes, and no new `metadata.*` key was added.
- `docs/openbao-integration-gaps.md`: record what the e2e layer now proves (custom metadata reaches an
  external plugin) and what remains unproven (no real fleet has run it).

- [x] **Step 3: Verify every layer**

```bash
go build github.com/nicois/openbao-cloud-creds/...
go test -race github.com/nicois/openbao-cloud-creds/...
make lint
make test-conformance
make test-e2e
make build-standalone
make smoke-test
```

Expected: all green. `make lint` must report 0 issues including the tagged pass.

- [ ] **Step 4: Release** — NOT DONE, deliberately. Tagging is irreversible (the module proxy
caches a version's content permanently) and releasing is the human's decision, so this step was
left for the maintainer. `TestEveryModuleAgreesOnOneVersion` passes as-is: `pkg/lineage` and every
new require name `v0.5.0`, the version the rest of the set already names. What the release owes:
**33** module paths, not 32 — `pkg/lineage` is new.

`pkg/lineage` is a **new module**, so the module count goes from 32 to 33 and the new path must be
tagged with the rest. Follow the existing release process and let its guards check the result:

```bash
go test github.com/nicois/openbao-cloud-creds/conformance/... -run TestEveryModuleAgreesOnOneVersion
```

Bump every internal `require` to the new version (including the nine plugins' new
`pkg/lineage` requires and `pkg/issuedlist`'s), then tag all 33 module paths at one commit. The
unreleased rotation fix noted in `CLAUDE.md` ships in the same bump.

- [x] **Step 5: Commit**

```bash
git add -A
git commit -m "docs: describe the caller-lineage contract"
```

---

## Follow-up plan (separate): the reference substrate

Not part of this plan, and deliberately so — it is separable software with its own release surface, and
everything above is useful without it (an operator writes two metadata keys per unit and gets the whole
contract today).

**Its aim:** give each unit its own identity, so `entity_id` names an instance rather than a role, and
make the parent unforgeable at the source rather than merely unwritable by the client.

**Its shape**, from what this repo has already verified:

- an **auth** plugin (`plugins/auth-fleet`, mount `auth/fleet/`), because only an auth method chooses
  `Alias.Name` — that is the single decision that un-collapses one-entity-per-role into
  one-entity-per-unit, and no secrets engine can make it;
- `spawn`: one action that mints a unit's login material **and** records the parent from
  `req.EntityID`, so the unadopted state cannot exist and no grace period is needed to cover a
  provisioner crash between two calls;
- `login`: returns `Alias.Name = <unit id>` and `Alias.Metadata` carrying
  `cloud_creds_parent_entity_id` — the keys this plan reads;
- a **registry** in its own storage, with a paged LIST shaped like `issued/` and published by
  allowlist;
- a **sweep** over its own records only (the reconciler's owner-tag rule one layer up), disabling at T
  and deleting at T+N, failing open when a parent cannot be read (`identity/entity/merge` makes a
  parent id vanish legitimately), refusing cycles, and exempting root types;
- **containment without identity writes**: a dead unit's next login is refused immediately, and its
  token renewal is refused — verified to mean the token lives out its *current* TTL and then expires
  (`vault/expiration.go`: `RenewToken` returns the backend's error and does not revoke), taking its
  leases and therefore its cloud credentials with it. Instant cut-off still needs
  `entity.Disabled`, which is an operator action — or, with this plan in place,
  `require_caller_lineage=live_parent`, which turns that same operator action into an immediate
  cross-cloud stop on new issuance.
