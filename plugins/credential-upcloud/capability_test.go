package credentialupcloud

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	capRolePath = "roles/probe-role"
	// capMintedPrefix is the prefix the fake gives tokens it mints, so forbidding
	// it targets rotation successors without touching operator-provided minters.
	capMintedPrefix = "ucat_fake_"
)

// capWriteRole writes a role bound to the default set and returns the response.
func capWriteRole(t *testing.T, b *backend, storage logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: capRolePath, Storage: storage,
		Data: map[string]any{
			fieldDefaultTTL: 3600, fieldMaxTTL: 86400,
			fieldMinterSet: defaultSetName,
		},
	})
	if err != nil {
		t.Fatalf("role write errored: %v", err)
	}
	return resp
}

// A role may not be bound to a set whose minter cannot create tokens. On UpCloud
// that is invisible to the health check: a token without can_create_tokens reads
// /1.3/account happily and only fails when asked to mint.
func TestCapability_RoleWriteRejectedWhenMinterCannotMint(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", "ucat_v1_one"),
	})
	srv.SetForbidMintForTokenPrefix("ucat_v1_")

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

// A successful probe leaves nothing upstream: it creates a token and deletes it.
func TestCapability_ProbeLeavesNoTokenBehind(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", "ucat_v1_one"),
	})
	before := srv.ProvisionedCount()
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	if after := srv.ProvisionedCount(); after != before {
		t.Fatalf("capability probe left %d token(s) upstream", after-before)
	}
}

// A rotation successor that is live but cannot mint (no can_create_tokens) must
// not be committed: the health check passes, so only a probe catches it.
func TestCapability_RotationRejectedWhenSuccessorCannotMint(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", "ucat_v1_one"),
		neverExpiresMinter("minter-2", "ucat_v1_two"),
	})
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}

	before := srv.ProvisionedCount()
	srv.SetForbidMintForTokenPrefix(capMintedPrefix)

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
		t.Fatalf("rejected rotation leaked a token: %d before, %d after", before, after)
	}
}

// The probe is skippable for operators who cannot accept a probe mint.
func TestCapability_DisabledSkipsProbe(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []any{
		neverExpiresMinter("minter-1", "ucat_v1_one"),
	})
	if resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]any{
			fieldUsername: "testuser", fieldAPIURL: srv.URL, fieldVerifyCapability: false,
		},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	srv.SetForbidMintForTokenPrefix("ucat_v1_")
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("probe ran despite verify_minter_capability=false: %v", resp.Error())
	}
}
