package credentialexoscale

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	capRolePath = "roles/compute-probe"
	capRoleID   = "22222222-2222-2222-2222-222222222222"
	// capMintedPrefix is the prefix the fake gives the keys it mints, so forbidding
	// it targets rotation successors without touching operator-provided minters.
	capMintedPrefix = "EXOsecret_fake_"
)

// capWriteRole writes a role bound to the default set and returns the response.
func capWriteRole(t *testing.T, b *backend, storage logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: capRolePath, Storage: storage,
		Data: map[string]interface{}{
			fieldDefaultTTL: 3600, fieldMaxTTL: 86400,
			fieldRoleID: capRoleID, fieldMinterSet: defaultSetName,
		},
	})
	if err != nil {
		t.Fatalf("role write errored: %v", err)
	}
	return resp
}

// A role may not be bound to a set whose minter cannot create api-keys. The
// health check cannot see it: GET /v2/zone succeeds for any live key.
func TestCapability_RoleWriteRejectedWhenMinterCannotMint(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresRotatableMinter(minter1ID, minter1Key),
	})
	srv.SetForbidCreateForKeyPrefix("EXO_key_")

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

// A successful probe leaves nothing upstream: it creates a key and deletes it.
func TestCapability_ProbeLeavesNoKeyBehind(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresRotatableMinter(minter1ID, minter1Key),
	})
	before := srv.ProvisionedCount()
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	if after := srv.ProvisionedCount(); after != before {
		t.Fatalf("capability probe left %d key(s) upstream", after-before)
	}
}

// A rotation successor that is live but whose granted IAM role cannot create
// api-keys must not be committed: only a probe distinguishes it from a good one.
func TestCapability_RotationRejectedWhenSuccessorCannotMint(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresRotatableMinter(minter1ID, minter1Key),
		neverExpiresRotatableMinter(minter2ID, minter2Key),
	})
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}

	before := srv.ProvisionedCount()
	srv.SetForbidCreateForKeyPrefix(capMintedPrefix)

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: minter1ID},
	})
	if err != nil {
		t.Fatalf("rotate errored: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected rotation to be rejected, got %v", resp)
	}

	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 2 {
		t.Fatalf("rejected rotation changed the set: %+v", set.Minters)
	}
	for i := range set.Minters {
		if set.Minters[i].Retired {
			t.Fatalf("rejected rotation retired minter %q", set.Minters[i].ID)
		}
	}
	if after := srv.ProvisionedCount(); after != before {
		t.Fatalf("rejected rotation leaked a key: %d before, %d after", before, after)
	}
}

// Replacing a set's minters re-probes every role already bound to it.
func TestCapability_SetRewriteRejectedWhenReplacementCannotMint(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresRotatableMinter(minter1ID, minter1Key),
	})
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}

	srv.SetForbidCreateForKeyPrefix("EXO_key_")
	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathMinterSetWrite, Storage: storage,
		Data: map[string]interface{}{fieldMintersKey: []interface{}{
			neverExpiresRotatableMinter("minter-replacement", "EXO_key_9"),
		}},
	})
	if err != nil {
		t.Fatalf("set write errored: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the set rewrite to be rejected, got %v", resp)
	}
	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 1 || set.Minters[0].ID != minter1ID {
		t.Fatalf("rejected rewrite replaced the live set: %+v", set.Minters)
	}
}

// The probe is skippable for operators who cannot accept a probe mint.
func TestCapability_DisabledSkipsProbe(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresRotatableMinter(minter1ID, minter1Key),
	})
	if resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]interface{}{fieldAPIURL: srv.URL, fieldVerifyCapability: false},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	srv.SetForbidCreateForKeyPrefix("EXO_key_")
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("probe ran despite verify_minter_capability=false: %v", resp.Error())
	}
}
