package credentialdo_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The identity the cases below present. A claimed unit, so there IS something to record: an
// assertion that nothing was recorded proves nothing if nothing was resolvable in the first place.
const (
	sharedCallerEntityID  = "do-shared-caller-entity"
	sharedCallerAccessor  = "do-shared-caller-accessor"
	sharedParentEntityID  = "do-shared-parent-entity"
	sharedCallerUnitID    = "do-shared-unit-7"
	metaParentEntityIDKey = "cloud_creds_parent_entity_id"
	metaUnitIDKey         = "cloud_creds_unit_id"
)

// withClaimedCaller gives the backend an identity view that resolves a parent for the caller.
//
// logical.StaticSystemView answers EntityInfo with the same entity for every id, which is enough
// here: what these cases need is a view that WOULD produce a lineage, so that a record carrying none
// is a statement about the plugin rather than about the fixture.
//
// The metadata keys are spelled here rather than imported from pkg/lineage, as the e2e scenario
// spells them: what is being asserted is that a provisioner's claim does not reach this record, and
// importing the constants would let the contract rename itself and stay green.
func withClaimedCaller() backendOption {
	return func(config *logical.BackendConfig) {
		config.System = &logical.StaticSystemView{
			EntityVal: &logical.Entity{
				ID: sharedCallerEntityID,
				Aliases: []*logical.Alias{{
					Name: sharedCallerEntityID,
					CustomMetadata: map[string]string{
						metaParentEntityIDKey: sharedParentEntityID,
						metaUnitIDKey:         sharedCallerUnitID,
					},
				}},
			},
		}
	}
}

// readAsClaimedCaller reads a credential as a caller core resolved an accessor, an entity and
// (through the view above) a parent for. The three request fields are set by hand because only
// OpenBao core populates them for real.
func readAsClaimedCaller(t *testing.T, b logical.Backend, storage logical.Storage,
	role string,
) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation:           logical.ReadOperation,
		Path:                "creds/" + role,
		Storage:             storage,
		ClientTokenAccessor: sharedCallerAccessor,
		EntityID:            sharedCallerEntityID,
	})
	if err != nil {
		t.Fatalf("creds read on %q returned a hard error: %v", role, err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("creds read on %q failed: %v", role, resp)
	}
	return resp
}

// TestSharedSpacesKey_RecordsNobodyAsHavingObtainedIt is a negative assertion, and the only guard on
// it.
//
// trackSpacesKey funnels BOTH Spaces credential types: the per-lease path hands it the request that
// read the lease, and the rotation hands it nothing, because a key served to every reader of the role
// was obtained by no one reader. Only the argument at that one call site enforces the difference —
// and the do-spaces-rotated conformance subject skips the recording cases precisely because the
// credential is shared, so an edit that started passing the request through would attribute a
// role-owned, fleet-shared key to whichever client happened to trigger a due rotation, with every
// layer green.
//
// It covers provenance and lineage together because the hazard is one hazard: both stamps are applied
// at that single site, and neither has any other test asserting what a shared key's record contains.
func TestSharedSpacesKey_RecordsNobodyAsHavingObtainedIt(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv, withClaimedCaller())

	// The first read mints the role's key, and the second, after forcing the rotation due, mints its
	// replacement. Both go through trackSpacesKey's rotation caller, so both records are asserted.
	readAsClaimedCaller(t, b, storage, rotatedRoleName)
	if err := credentialdo.ForceRotationDue(t.Context(), b, storage, rotatedRoleName); err != nil {
		t.Fatalf("forcing the rotation due failed: %v", err)
	}
	readAsClaimedCaller(t, b, storage, rotatedRoleName)

	keys, err := storage.List(t.Context(), "active-spaces-keys/")
	if err != nil {
		t.Fatalf("listing the tracking prefix failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected the retiring and the current key both tracked, got %v", keys)
	}
	for _, key := range keys {
		entry, err := storage.Get(t.Context(), "active-spaces-keys/"+key)
		if err != nil || entry == nil {
			t.Fatalf("reading tracking record %s: err=%v entry=%v", key, err, entry)
		}
		record := map[string]any{}
		if err := json.Unmarshal(entry.Value, &record); err != nil {
			t.Fatalf("tracking record %s is not a JSON object: %v", key, err)
		}
		for field, value := range record {
			if strings.HasPrefix(field, "requested_by_") {
				t.Errorf("the record for the shared key %s says %s=%v: this credential belongs to "+
					"the ROLE and is served to every reader, so naming the caller that happened to "+
					"trigger the rotation attributes a fleet's credential to one unit — which is "+
					"the misattribution both stamps exist to prevent", key, field, value)
			}
		}
	}
}

// TestSharedSpacesKey_APerLeaseKeyStillRecordsItsCaller is the positive half, and it is what makes
// the negative one above meaningful: the same funnel, the same identity, the same fake — and a record
// that DOES name the caller, because a per-lease key really was obtained by the read that got it.
// Without this, an accidental change that stopped stamping either type would leave the negative case
// passing and nothing failing.
func TestSharedSpacesKey_APerLeaseKeyStillRecordsItsCaller(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupSpacesBackend(t, srv, withClaimedCaller())

	readAsClaimedCaller(t, b, storage, "spaces")

	keys, err := storage.List(t.Context(), "active-spaces-keys/")
	if err != nil {
		t.Fatalf("listing the tracking prefix failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected exactly one tracking record after one read, got %v", keys)
	}
	entry, err := storage.Get(t.Context(), "active-spaces-keys/"+keys[0])
	if err != nil || entry == nil {
		t.Fatalf("reading tracking record %s: err=%v entry=%v", keys[0], err, entry)
	}
	record := map[string]any{}
	if err := json.Unmarshal(entry.Value, &record); err != nil {
		t.Fatalf("tracking record %s is not a JSON object: %v", keys[0], err)
	}
	for field, want := range map[string]string{
		"requested_by_token_accessor":   sharedCallerAccessor,
		"requested_by_entity_id":        sharedCallerEntityID,
		"requested_by_parent_entity_id": sharedParentEntityID,
		"requested_by_unit_id":          sharedCallerUnitID,
		"requested_by_lineage_source":   "alias_custom_metadata",
	} {
		if got := record[field]; got != want {
			t.Errorf("the per-lease key's record says %s=%v, want %q — so the negative assertion on "+
				"the SHARED key is about the rotation, not about a stamp that never runs",
				field, got, want)
		}
	}
}
