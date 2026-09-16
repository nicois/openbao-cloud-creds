package credentialdo_test

import (
	"testing"

	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// purgeRotatedRole runs roles/<name>/revoke-upstream to completion in one call. The rotated
// type holds at most two keys per role, so the default per-pass bound never bites and the
// worker has nothing left to continue.
func purgeRotatedRole(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + rotatedRoleName + "/revoke-upstream",
		Storage:   storage,
		Data:      map[string]interface{}{"mode": "normal"},
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("revoke-upstream failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["complete"] != true {
		t.Fatalf("the purge did not finish in one pass: %v", resp.Data)
	}
	return resp
}

// A purge deletes the shared key, and the record saying which key the role serves is separate
// from the tracking record the purge walks. If it survives, the role keeps handing out the
// access key of a credential DigitalOcean no longer has — and does so silently for the rest of
// the rotation period, which is the failure mode a purge is called to end.
func TestRotatedSpacesPurge_StopsTheRoleServingTheDeletedKey(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	purged := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))
	purgeRotatedRole(t, b, storage)

	if srv.HasSpacesKey(purged) {
		t.Fatalf("the purge left the shared key %s live upstream", purged)
	}
	if n := srv.ProvisionedSpacesKeyCount(); n != 0 {
		t.Fatalf("the purge left %d keys upstream", n)
	}

	fresh := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))
	if fresh == purged {
		t.Fatal("the role served the access key of the credential the purge deleted: a client " +
			"cannot tell it is dead except by being refused by Spaces")
	}
	if !srv.HasSpacesKey(fresh) {
		t.Errorf("the role served %s, which does not exist upstream", fresh)
	}
	if n := srv.ProvisionedSpacesKeyCount(); n != 1 {
		t.Errorf("expected the read after a purge to mint exactly one replacement, got %d keys", n)
	}
}

// Mid-overlap there are two keys, and a purge is a containment action: the overlap is a
// courtesy to clients, not a hold on an operator ending an incident.
func TestRotatedSpacesPurge_TakesTheRetiringKeyToo(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	retiring := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))
	if err := credentialdo.ForceRotationDue(t.Context(), b, storage, rotatedRoleName); err != nil {
		t.Fatalf("forcing the rotation due failed: %v", err)
	}
	current := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))
	if n := srv.ProvisionedSpacesKeyCount(); n != 2 {
		t.Fatalf("expected two keys during the overlap, got %d", n)
	}

	resp := purgeRotatedRole(t, b, storage)
	if got := resp.Data["deleted"]; got != 2 {
		t.Errorf("the purge reported deleted=%v, want 2: the retiring key is as usable as the "+
			"current one to whoever holds it", got)
	}
	for _, key := range []string{retiring, current} {
		if srv.HasSpacesKey(key) {
			t.Errorf("the purge left %s live upstream", key)
		}
	}
	if records, err := storage.List(t.Context(), "active-spaces-keys/"); err != nil {
		t.Fatalf("listing the tracking prefix failed: %v", err)
	} else if len(records) != 0 {
		t.Errorf("%v tracking records survived the purge", records)
	}

	// Nothing is left for the sweeper to delete, and it must not report the role's retiring
	// key as a failure it should retry: the key is gone and the state should not name it.
	if err := credentialdo.SweepSharedSpacesKeys(t.Context(), b, storage); err != nil {
		t.Errorf("the sweep after a purge failed: %v", err)
	}
	if n := srv.ProvisionedSpacesKeyCount(); n != 0 {
		t.Errorf("the sweep minted %d keys for a role whose credentials were just purged", n)
	}
}
