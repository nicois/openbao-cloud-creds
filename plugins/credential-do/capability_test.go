package credentialdo_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// capBackend returns a backend wired to a fake DO API whose failure knob the
// test controls, so the capability probe can be made to fail on demand.
func capBackend(t *testing.T, verify bool) (logical.Backend, logical.Storage, *fakes.DOServer) {
	t.Helper()
	srv := fakes.NewDOServer()
	t.Cleanup(srv.Close)

	cfg := logical.TestBackendConfig()
	cfg.StorageView = &logical.InmemStorage{}
	b, err := credentialdo.Factory(context.Background(), cfg)
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	capWrite(t, b, cfg.StorageView, "config", map[string]interface{}{
		"do_api_url": srv.URL, "verify_minter_capability": verify,
	})
	return b, cfg.StorageView, srv
}

func capWrite(t *testing.T, b logical.Backend, storage logical.Storage, path string, data map[string]interface{}) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("%s write failed: err=%v resp=%v", path, err, resp)
	}
}

func capTryWrite(t *testing.T, b logical.Backend, storage logical.Storage, path string, data map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
	})
	if err != nil {
		t.Fatalf("%s write errored: %v", path, err)
	}
	return resp
}

const (
	capSetPath   = "minter-sets/default"
	capRolePath  = "roles/probe-role"
	capRoleData  = "read,write"
	capVerifyMsg = "capability verification failed"
)

func capDefaultSet(id, token string) map[string]interface{} {
	return map[string]interface{}{
		"minters": []interface{}{
			map[string]interface{}{"id": id, "token": token, "never_expires": true},
		},
	}
}

func capRoleFields() map[string]interface{} {
	return map[string]interface{}{
		"default_ttl": 900, "max_ttl": 3600, "scopes": capRoleData, "minter_set": "default",
	}
}

// A role may not be bound to a minter set whose minter cannot mint for it. This
// is the check that stops an operator defining a role the minting key is
// unsuitable for; before it existed the misconfiguration surfaced only at the
// first credential read, as an upstream 403.
func TestCapability_RoleWriteRejectedWhenMinterCannotMint(t *testing.T) {
	b, storage, srv := capBackend(t, true)
	capWrite(t, b, storage, capSetPath, capDefaultSet("minter-1", "dop_v1_test"))

	srv.SetNextStatus(http.StatusForbidden)
	resp := capTryWrite(t, b, storage, capRolePath, capRoleFields())
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected role write to be rejected, got %v", resp)
	}
	if !strings.Contains(resp.Error().Error(), capVerifyMsg) {
		t.Fatalf("expected a capability failure, got %v", resp.Error())
	}

	// The role must not have been persisted: a rejected write leaves no role
	// behind for a later read to succeed against.
	read, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: capRolePath, Storage: storage,
	})
	if err != nil {
		t.Fatalf("role read errored: %v", err)
	}
	if read != nil {
		t.Fatalf("rejected role write persisted the role: %v", read.Data)
	}
}

// A successful probe must leave nothing upstream: it mints and deletes.
func TestCapability_ProbeLeavesNoCredentialBehind(t *testing.T) {
	b, storage, srv := capBackend(t, true)
	capWrite(t, b, storage, capSetPath, capDefaultSet("minter-1", "dop_v1_test"))
	capWrite(t, b, storage, capRolePath, capRoleFields())

	if n := srv.ProvisionedCount(); n != 0 {
		t.Fatalf("capability probe left %d credential(s) upstream, want 0", n)
	}
}

// Replacing a set's minters re-probes every role already bound to the set — the
// DigitalOcean case that matters, since DO minters are replaced by hand and
// nothing else in the plugin would notice a under-scoped replacement PAT.
func TestCapability_SetRewriteRejectedWhenReplacementCannotMint(t *testing.T) {
	b, storage, srv := capBackend(t, true)
	capWrite(t, b, storage, capSetPath, capDefaultSet("minter-1", "dop_v1_test"))
	capWrite(t, b, storage, capRolePath, capRoleFields())

	srv.SetNextStatus(http.StatusForbidden)
	resp := capTryWrite(t, b, storage, capSetPath, capDefaultSet("minter-2", "dop_v1_replacement"))
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected minter-set rewrite to be rejected, got %v", resp)
	}

	// The previous, working set must survive a rejected replacement.
	read, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: capSetPath, Storage: storage,
	})
	if err != nil || read == nil {
		t.Fatalf("minter-set read failed: err=%v resp=%v", err, read)
	}
	ids, _ := read.Data["minter_ids"].([]string)
	if len(ids) != 1 || ids[0] != "minter-1" {
		t.Fatalf("rejected rewrite replaced the live set: %v", ids)
	}
}

// Probing is skippable: an operator who cannot accept a probe mint sets
// verify_minter_capability=false and gets the old behaviour.
func TestCapability_DisabledSkipsProbe(t *testing.T) {
	b, storage, srv := capBackend(t, false)
	capWrite(t, b, storage, capSetPath, capDefaultSet("minter-1", "dop_v1_test"))

	srv.SetNextStatus(http.StatusForbidden)
	capWrite(t, b, storage, capRolePath, capRoleFields())
}

// A disabled role cannot issue, so it must not be able to block a minter-set
// write either.
func TestCapability_DisabledRoleNotProbedOnSetWrite(t *testing.T) {
	b, storage, srv := capBackend(t, true)
	capWrite(t, b, storage, capSetPath, capDefaultSet("minter-1", "dop_v1_test"))

	// There is no disable endpoint; Disabled is set out of band, so plant the
	// role directly.
	entry, err := logical.StorageEntryJSON(capRolePath, map[string]interface{}{
		"name": "probe-role", "scopes": capRoleData, "minter_set": "default", "disabled": true,
	})
	if err != nil {
		t.Fatalf("entry build failed: %v", err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatalf("planting disabled role failed: %v", err)
	}

	srv.SetNextStatus(http.StatusForbidden)
	// The injected 403 is never consumed by a probe, so the set write succeeds.
	capWrite(t, b, storage, capSetPath, capDefaultSet("minter-1", "dop_v1_test"))
}
