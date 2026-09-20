package credentialvultr

import (
	"encoding/json"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	capRolePath    = "roles/manage-probe"
	capACLs        = "manage_users,subscriptions"
	capUngrantable = "manage_users"
	capSetName     = "default"
	capMinter1ID   = "minter-1"
	capMinter1Key  = "VULTR_key_1"
)

// newCapabilityBackend builds a Vultr backend wired to a fake API with the given
// minters written through the API, and returns it with the fake and storage.
func newCapabilityBackend(t *testing.T, minters []any) (*backend, *fakes.VultrServer, logical.Storage) {
	t.Helper()
	srv := fakes.NewVultrServer()
	t.Cleanup(srv.Close)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	storage := config.StorageView

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]any{fieldAPIURL: srv.URL},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}
	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathMinterSetWrite, Storage: storage,
		Data: map[string]any{fieldMintersKey: minters},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write: err=%v resp=%v", err, resp)
	}
	return b.(*backend), srv, storage
}

// capMinter builds a never-expiring minter map for the API's minters field.
func capMinter(id, token string) map[string]any {
	return map[string]any{"id": id, "token": token, "never_expires": true}
}

// capWriteRole writes a role bound to the default set and returns the response.
func capWriteRole(t *testing.T, b *backend, storage logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: capRolePath, Storage: storage,
		Data: map[string]any{
			fieldDefaultTTL: 3600, fieldMaxTTL: 86400,
			fieldACLs: capACLs, fieldMinterSet: capSetName,
		},
	})
	if err != nil {
		t.Fatalf("role write errored: %v", err)
	}
	return resp
}

// capLoadSet reads the persisted default minter set straight from storage.
func capLoadSet(t *testing.T, storage logical.Storage) cloudconfig.MinterSet {
	t.Helper()
	entry, err := storage.Get(t.Context(), "minter-sets/"+capSetName)
	if err != nil || entry == nil {
		t.Fatalf("get set: err=%v entry=%v", err, entry)
	}
	var set cloudconfig.MinterSet
	if err := json.Unmarshal(entry.Value, &set); err != nil {
		t.Fatalf("unmarshal set: %v", err)
	}
	return set
}

// A role may not be bound to a set whose minter cannot grant the role's ACLs.
// Vultr refuses to delegate an ACL the creating key does not hold, and the
// account health check cannot see that.
func TestCapability_RoleWriteRejectedWhenMinterCannotGrantACLs(t *testing.T) {
	bk, srv, storage := newCapabilityBackend(t, []any{capMinter(capMinter1ID, capMinter1Key)})
	srv.SetUngrantableACL(capUngrantable)

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

// A successful probe leaves nothing upstream: it creates a sub-user and deletes it.
func TestCapability_ProbeLeavesNoSubUserBehind(t *testing.T) {
	bk, srv, storage := newCapabilityBackend(t, []any{capMinter(capMinter1ID, capMinter1Key)})
	before := srv.ProvisionedCount()
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	if after := srv.ProvisionedCount(); after != before {
		t.Fatalf("capability probe left %d sub-user(s) upstream", after-before)
	}
}

// Replacing a set's minters re-probes every role already bound to it, so a
// hand-pasted replacement key with narrower ACLs is rejected at the set write.
func TestCapability_SetRewriteRejectedWhenReplacementCannotGrantACLs(t *testing.T) {
	bk, srv, storage := newCapabilityBackend(t, []any{capMinter(capMinter1ID, capMinter1Key)})
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}

	srv.SetUngrantableACL(capUngrantable)
	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathMinterSetWrite, Storage: storage,
		Data: map[string]any{fieldMintersKey: []any{
			capMinter("minter-replacement", "VULTR_key_9"),
		}},
	})
	if err != nil {
		t.Fatalf("set write errored: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the set rewrite to be rejected, got %v", resp)
	}
	if set := capLoadSet(t, storage); len(set.Minters) != 1 || set.Minters[0].ID != capMinter1ID {
		t.Fatalf("rejected rewrite replaced the live set: %+v", set.Minters)
	}
}

// The probe is skippable for operators who cannot accept a probe mint.
func TestCapability_DisabledSkipsProbe(t *testing.T) {
	bk, srv, storage := newCapabilityBackend(t, []any{capMinter(capMinter1ID, capMinter1Key)})
	if resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]any{fieldAPIURL: srv.URL, fieldVerifyCapability: false},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	srv.SetUngrantableACL(capUngrantable)
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("probe ran despite verify_minter_capability=false: %v", resp.Error())
	}
}
