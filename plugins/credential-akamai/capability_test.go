package credentialakamai

import (
	"fmt"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Local literals for the capability tests. capForbiddenAPIID is an apiId the
// fake can be told the signing credential may not delegate, which is how
// "authenticates but cannot mint" is expressed on Akamai.
const (
	capRolePath       = "roles/purge-probe"
	capRoleName       = "purge-probe"
	capForbiddenAPIID = 9901
	capRoleTTL        = 900
	capRoleMaxTTL     = 3600
	capGroupID        = 4711
)

// capRoleAPIAccess is the role's api_access grant, naming the api the fake can be
// told is ungrantable.
var capRoleAPIAccess = fmt.Sprintf(`{"apis":[{"apiId":%d,"accessLevel":"READ-WRITE"}]}`, capForbiddenAPIID)

// capWriteRole writes a role bound to the default set and returns the response
// (nil on success, an error response when the capability probe rejected it).
func capWriteRole(t *testing.T, b *backend, storage logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: capRolePath, Storage: storage,
		Data: map[string]any{
			fieldDefaultTTL: capRoleTTL, fieldMaxTTL: capRoleMaxTTL,
			fieldGroupID: capGroupID, fieldAPIAccess: capRoleAPIAccess,
			fieldMinterSet: defaultSetName,
		},
	})
	if err != nil {
		t.Fatalf("role write errored: %v", err)
	}
	return resp
}

// A minter that authenticates (GET self succeeds) but may not delegate the api a
// role asks for must not have a role bound to it. Akamai will not let an api
// client grant access it does not itself hold, so this is the common
// misconfiguration: a minter provisioned with Identity-Management rights alone.
func TestCapability_RoleWriteRejectedWhenMinterCannotGrantRoleAPI(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", minter1Token),
	})
	srv.SetUngrantableAPIID(capForbiddenAPIID)

	resp := capWriteRole(t, bk, storage)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the role write to be rejected, got %v", resp)
	}
	read, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: capRolePath, Storage: storage,
	})
	if err != nil {
		t.Fatalf("role read errored: %v", err)
	}
	if read != nil {
		t.Fatalf("rejected role write persisted the role: %v", read.Data)
	}
}

// The probe is a real create, so it must also be a real delete: a successful
// role write leaves no api client behind.
func TestCapability_ProbeLeavesNoAPIClient(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", minter1Token),
	})

	before := srv.ProvisionedCount()
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	if after := srv.ProvisionedCount(); after != before {
		t.Fatalf("probe leaked %d api client(s): %d -> %d", after-before, before, after)
	}
}

// A rotation successor that passes its health check can still be unable to mint:
// its grants are copied from the incumbent's, which may not cover an api a bound
// role asks for. The probe run before the commit must reject the rotation, leave
// the set untouched, and delete the successor's upstream api client.
func TestCapability_RotationRejectedWhenSuccessorCannotMint(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", minter1Token),
		neverExpiresMinter("minter-2", minter2Token),
	})
	// The role binds while the api is still grantable, so the role-write probe
	// passes; the grant is revoked afterwards, which is what rotation must catch.
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	srv.SetUngrantableAPIID(capForbiddenAPIID)
	before := srv.ProvisionedCount()

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]any{fieldMinterID: "minter-1"},
	})
	if err != nil {
		t.Fatalf("rotate errored: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the rotation to be rejected, got %v", resp)
	}

	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 2 {
		t.Fatalf("rejected rotation changed the set: %d minters, want 2", len(set.Minters))
	}
	for i := range set.Minters {
		if set.Minters[i].Retired {
			t.Fatalf("rejected rotation retired minter %q", set.Minters[i].ID)
		}
	}
	if after := srv.ProvisionedCount(); after != before {
		t.Fatalf("rejected rotation leaked %d api client(s)", after-before)
	}
}

// verify_minter_capability=false skips the probe entirely: the role binds even
// though its api cannot be granted, and no probe client is ever created.
func TestCapability_DisabledSkipsProbe(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", minter1Token),
	})
	if resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]any{
			fieldHost: testHost, fieldAPIURL: srv.URL, fieldVerifyCapability: false,
		},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}
	srv.SetUngrantableAPIID(capForbiddenAPIID)

	before := srv.ProvisionedCount()
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("probe ran despite verify_minter_capability=false: %v", resp.Error())
	}
	if after := srv.ProvisionedCount(); after != before {
		t.Fatalf("expected no probe api client, saw %d", after-before)
	}
}
