package requester

import (
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
