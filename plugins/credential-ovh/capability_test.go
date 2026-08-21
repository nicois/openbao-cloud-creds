package credentialovh_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	credentialovh "github.com/nicois/openbao-cloud-creds/plugins/credential-ovh"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	capRolePath = "roles/probe-role"
	capSetPath  = "minter-sets/default"
)

// capBackend builds a configured OVH backend whose token client mints only while
// canMint is true, and reports how many mint calls were made. verify controls
// verify_minter_capability.
func capBackend(t *testing.T, canMint *atomic.Bool, mints *atomic.Int64, verify bool) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)

	credentialovh.SetTokenClientFactory(b, func(_, _, _ string) credentialovh.TokenClient {
		return credentialovh.NewFakeTokenClient(func(_ context.Context) (string, int, error) {
			mints.Add(1)
			if !canMint.Load() {
				return "", 0, fmt.Errorf("OVH OAuth2 error (HTTP 403): insufficient_scope: this service account may not mint tokens")
			}
			return "ovh-probe-token", 3600, nil
		}, nil)
	})

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{"region": "eu", "verify_minter_capability": verify},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}
	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: capSetPath, Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{map[string]interface{}{
			"id": "minter-1", "client_id": "cid", "client_secret": "secret", "never_expires": true,
		}}},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}
	return b, storage
}

// capWriteRole writes a role bound to the default set and returns the response.
func capWriteRole(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: capRolePath, Storage: storage,
		Data: map[string]interface{}{"default_ttl": 3600, "max_ttl": 3600, "minter_set": "default"},
	})
	if err != nil {
		t.Fatalf("role write errored: %v", err)
	}
	return resp
}

// A role may not be bound to a set whose minters cannot mint. On OVH minting is
// the only upstream operation, so this is the whole of capability.
func TestCapability_RoleWriteRejectedWhenMinterCannotMint(t *testing.T) {
	var canMint atomic.Bool
	var mints atomic.Int64
	b, storage := capBackend(t, &canMint, &mints, true)

	resp := capWriteRole(t, b, storage)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the role write to be rejected, got %v", resp)
	}
	if mints.Load() == 0 {
		t.Fatal("the role write did not attempt a probe mint")
	}
	read, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: capRolePath, Storage: storage,
	})
	if err != nil {
		t.Fatalf("role read errored: %v", err)
	}
	if read != nil {
		t.Fatalf("rejected role write persisted the role: %v", read.Data)
	}
}

// A capable minter lets the role write through, and the probe really ran.
func TestCapability_RoleWriteProbesAndSucceeds(t *testing.T) {
	var canMint atomic.Bool
	canMint.Store(true)
	var mints atomic.Int64
	b, storage := capBackend(t, &canMint, &mints, true)

	before := mints.Load()
	if resp := capWriteRole(t, b, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	if mints.Load() <= before {
		t.Fatal("the role write did not attempt a probe mint")
	}
}

// The probe is skippable: on OVH tokens cannot be revoked, so each probe leaves a
// 1h token nobody holds, and some operators will not accept that.
func TestCapability_DisabledSkipsProbe(t *testing.T) {
	var canMint atomic.Bool
	var mints atomic.Int64
	b, storage := capBackend(t, &canMint, &mints, false)

	before := mints.Load()
	if resp := capWriteRole(t, b, storage); resp != nil && resp.IsError() {
		t.Fatalf("probe ran despite verify_minter_capability=false: %v", resp.Error())
	}
	if mints.Load() != before {
		t.Fatalf("expected no probe mint, saw %d", mints.Load()-before)
	}
}
