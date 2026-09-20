package credentialazure

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	capRolePath = "roles/graph-rw"
	capOtherApp = "other-app-object-id"
)

// capWriteRole writes a role bound to the default set, naming the given app
// registration, and returns the response for the caller to assert on.
func capWriteRole(t *testing.T, b *backend, storage logical.Storage, appObjectID string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: capRolePath, Storage: storage,
		Data: map[string]any{
			fieldDefaultTTL: 3600, fieldMaxTTL: 86400,
			fieldAppObjectID: appObjectID, fieldClientID: "client-id-456",
			fieldMinterSet: defaultSetName,
		},
	})
	if err != nil {
		t.Fatalf("role write errored: %v", err)
	}
	return resp
}

// A role may not be bound to a set whose minter cannot add passwords to the
// app registration the role names. Authenticating — and even reading that
// application — is not the same right.
func TestCapability_RoleWriteRejectedWhenMinterCannotMintForItsApp(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", "cid1:secret1"),
	})
	srv.SetAddPasswordForbidden(capOtherApp, true)

	resp := capWriteRole(t, bk, storage, capOtherApp)
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

// A successful probe leaves nothing upstream: it adds a password and removes it.
func TestCapability_ProbeLeavesNoPasswordBehind(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", "cid1:secret1"),
	})
	if resp := capWriteRole(t, bk, storage, testAppObjectID); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	if n := srv.PasswordCount(); n != 0 {
		t.Fatalf("capability probe left %d password(s) upstream, want 0", n)
	}
}

// The Azure rotation gap: the successor secret is minted on ONE app
// registration (the one in rotation_params), but the set's roles may name
// others. A successor that is live, and passes CheckHealth, can still be unable
// to mint for a bound role — so rotation must probe it against every bound role
// and refuse to commit if it cannot serve them.
func TestCapability_RotationRejectedWhenSuccessorCannotMintForABoundRole(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", "cid1:secret1"),
		neverExpiresMinter("minter-2", "cid2:secret2"),
	})
	if resp := capWriteRole(t, bk, storage, capOtherApp); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}

	before := srv.PasswordCount()
	srv.SetAddPasswordForbidden(capOtherApp, true)

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]any{fieldMinterID: "minter-1"},
	})
	if err != nil {
		t.Fatalf("rotate errored: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected rotation to be rejected, got %v", resp)
	}

	// No state change: the original is still active, no successor was added, and
	// the successor's just-minted secret was cleaned up.
	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 2 {
		t.Fatalf("rejected rotation changed the set: %+v", set.Minters)
	}
	for i := range set.Minters {
		if set.Minters[i].Retired {
			t.Fatalf("rejected rotation retired minter %q", set.Minters[i].ID)
		}
	}
	if after := srv.PasswordCount(); after != before {
		t.Fatalf("rejected rotation leaked a secret: %d passwords before, %d after", before, after)
	}
}

// Rotation still commits when the successor can mint for every bound role.
func TestCapability_RotationCommitsWhenSuccessorIsCapable(t *testing.T) {
	bk, _, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", "cid1:secret1"),
		neverExpiresMinter("minter-2", "cid2:secret2"),
	})
	if resp := capWriteRole(t, bk, storage, testAppObjectID); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]any{fieldMinterID: "minter-1"},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotation failed: err=%v resp=%v", err, resp)
	}
	if set := loadSetFromStorage(t, storage); len(set.Minters) != 3 {
		t.Fatalf("expected 2 active + 1 retired minter, got %+v", set.Minters)
	}
}

// Replacing a set's minters re-probes every role already bound to it.
func TestCapability_SetRewriteRejectedWhenReplacementCannotMint(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", "cid1:secret1"),
	})
	if resp := capWriteRole(t, bk, storage, capOtherApp); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}

	srv.SetAddPasswordForbidden(capOtherApp, true)
	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathMinterSetWrite, Storage: storage,
		Data: map[string]any{fieldMintersKey: []any{
			neverExpiresMinter("minter-replacement", "cid9:secret9"),
		}},
	})
	if err != nil {
		t.Fatalf("set write errored: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the set rewrite to be rejected, got %v", resp)
	}
	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 1 || set.Minters[0].ID != "minter-1" {
		t.Fatalf("rejected rewrite replaced the live set: %+v", set.Minters)
	}
}

// The probe is skippable for operators who cannot accept a probe mint.
func TestCapability_DisabledSkipsProbe(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", "cid1:secret1"),
	})
	if resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]any{
			fieldTenantID: "test-tenant", fieldGraphEndpoint: srv.URL, fieldLoginEndpoint: srv.URL,
			fieldVerifyCapability: false,
		},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	srv.SetAddPasswordForbidden(capOtherApp, true)
	if resp := capWriteRole(t, bk, storage, capOtherApp); resp != nil && resp.IsError() {
		t.Fatalf("probe ran despite verify_minter_capability=false: %v", resp.Error())
	}
}
