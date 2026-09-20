package requester

import (
	"slices"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestACallerCannotNameItself is the property this package exists for. Affinity lets a caller pick
// its own shard key; provenance must not let it pick its own identity, because a record naming the
// wrong unit sends an incident responder after the wrong service while the compromised one keeps its
// access. There is deliberately no parameter through which a caller could supply one.
func TestACallerCannotNameItself(t *testing.T) {
	req := &logical.Request{
		ClientTokenAccessor: "real-accessor",
		EntityID:            "real-entity",
		// A caller putting these in its request body must have no effect: Identity reads the request
		// fields core populates from the presented token, and never the data.
		Data: map[string]interface{}{
			FieldTokenAccessor: "forged-accessor",
			FieldEntityID:      "forged-entity",
			"shard_key":        "forged-shard",
		},
	}
	got := Identity(req)
	if got[FieldTokenAccessor] != "real-accessor" {
		t.Errorf("%s is %v, want the accessor core populated", FieldTokenAccessor,
			got[FieldTokenAccessor])
	}
	if got[FieldEntityID] != "real-entity" {
		t.Errorf("%s is %v, want the entity core resolved", FieldEntityID, got[FieldEntityID])
	}
}

// TestAbsentFieldsAreOmittedRatherThanEmpty keeps a record honest. A root token has no entity and an
// internal call may present no token, so an empty string stamped under a provenance key would read as
// "issued by an identity whose name is blank" rather than "no resolvable caller".
func TestAbsentFieldsAreOmittedRatherThanEmpty(t *testing.T) {
	for name, req := range map[string]*logical.Request{
		"no entity":   {ClientTokenAccessor: "acc"},
		"no token":    {EntityID: "ent"},
		"neither":     {},
		"nil request": nil,
	} {
		t.Run(name, func(t *testing.T) {
			for key, value := range Identity(req) {
				if value == "" {
					t.Errorf("%s was stamped as an empty string; omit it instead", key)
				}
			}
		})
	}
}

// TestStampPreservesTheRecord guards the shape of the call at every site: a plugin's own fields must
// survive, because a record rebuilt from provenance alone would lose the role and minter that make it
// useful.
func TestStampPreservesTheRecord(t *testing.T) {
	record := map[string]interface{}{"role": "executor", "minter": "do_v1"}
	Stamp(record, &logical.Request{ClientTokenAccessor: "acc"})

	if record["role"] != "executor" || record["minter"] != "do_v1" {
		t.Errorf("Stamp lost the plugin's own fields: %v", record)
	}
	if record[FieldTokenAccessor] != "acc" {
		t.Errorf("Stamp did not add the accessor: %v", record)
	}
}

// TestStampOnARequestWithNoIdentityLeavesTheRecordAlone: issuance must not fail or gain empty keys
// just because nothing identified the caller.
func TestStampOnARequestWithNoIdentityLeavesTheRecordAlone(t *testing.T) {
	record := map[string]interface{}{"role": "executor"}
	Stamp(record, &logical.Request{})
	if len(record) != 1 {
		t.Errorf("record gained provenance keys with nothing to put in them: %v", record)
	}
}

// TestAnUnknownRequirementFailsClosed is the case no plugin's role path can reach, which is exactly
// why it is asserted here: a role written by a NEWER binary can name a requirement this one does not
// know. Treating it as RequireNone would turn "only issue to callers I can name" into "issue to
// anybody" on the older node of a mixed-version cluster — the same fail-open class as A29/A30.
func TestAnUnknownRequirementFailsClosed(t *testing.T) {
	resp := Enforce(&logical.Request{ClientTokenAccessor: "acc", EntityID: "ent"}, "some_future_rule")
	if resp == nil {
		t.Fatal("a requirement this binary does not understand was treated as no requirement")
	}
	if !resp.IsError() {
		t.Fatalf("expected an error response, got %v", resp)
	}
}

// TestWhatEachRequirementAccepts pins the two absences apart. They are different callers: a batch
// token has no accessor and does have an entity (shared with the service token that created it),
// while a root token has an accessor and no entity. A requirement that could not tell them apart
// would make `token_accessor` either useless or a ban on root.
func TestWhatEachRequirementAccepts(t *testing.T) {
	callers := map[string]*logical.Request{
		"service token": {ClientTokenAccessor: "acc", EntityID: "ent"},
		"batch token":   {EntityID: "ent"},
		"root token":    {ClientTokenAccessor: "acc"},
		"no token":      {},
	}
	refused := map[Requirement][]string{
		RequireNone:          {},
		RequireAny:           {"no token"},
		RequireTokenAccessor: {"batch token", "no token"},
	}
	for requirement, wantRefused := range refused {
		for name, req := range callers {
			got := Enforce(req, string(requirement)) != nil
			want := slices.Contains(wantRefused, name)
			if got != want {
				t.Errorf("%s with requirement %s: refused=%v, want %v", name, requirement, got, want)
			}
		}
	}
}
