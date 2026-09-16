package credentialdo_test

import (
	"slices"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// rotateKeys is the report an operator gets back, spelled out here rather than read from the
// implementation: a schema assertion that takes its expectations from the code it checks
// asserts nothing. Note what is absent — the secret key. This is an operator lever, not a
// credential read, and the secret belongs only to the clients reading creds/<role>.
var rotateKeys = []string{
	"role", "access_key", "replaced_access_key", "replaced_deleted_at", "rotate_at",
}

func rotateRoleNow(t *testing.T, b logical.Backend, storage logical.Storage, roleName string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + roleName + "/rotate",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("rotate failed: %v", err)
	}
	if resp == nil {
		t.Fatal("rotate returned no response")
	}
	return resp
}

// rotateCode is the stable error_code of a refusal, which travels in the message prefix
// rather than in a field of its own.
func rotateCode(t *testing.T, resp *logical.Response) credenvelope.ErrorCode {
	t.Helper()
	if !resp.IsError() {
		t.Fatalf("expected a refusal, got %v", resp.Data)
	}
	code, known := credenvelope.CodeOf(resp.Error().Error())
	if !known {
		t.Fatalf("the refusal carries no recognised error_code: %v", resp.Error())
	}
	return code
}

func rotateField(t *testing.T, resp *logical.Response, key string) string {
	t.Helper()
	value, ok := resp.Data[key].(string)
	if !ok {
		t.Fatalf("expected %s in the rotate report, got %v", key, resp.Data)
	}
	return value
}

// The lever an operator pulls when a key must be replaced before its period is up — a
// suspected but unconfirmed leak, or a compliance date. Clients are not cut off: that is
// revoke-upstream, and conflating the two would mean an operator rotating on schedule broke
// every holder.
func TestRotatedSpacesRotate_ReplacesTheKeyAndKeepsTheOldOneForTheOverlap(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	old := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))

	resp := rotateRoleNow(t, b, storage, rotatedRoleName)
	if resp.IsError() {
		t.Fatalf("rotate was refused: %v", resp)
	}
	keys := make([]string, 0, len(resp.Data))
	for key := range resp.Data {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	want := slices.Clone(rotateKeys)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Errorf("the rotate report has keys %v, want %v", keys, want)
	}

	fresh := rotateField(t, resp, "access_key")
	if fresh == old {
		t.Fatal("rotate reported the same key it was asked to replace")
	}
	if got := rotateField(t, resp, "replaced_access_key"); got != old {
		t.Errorf("the report names %s as replaced, but the role was serving %s", got, old)
	}
	if rotateField(t, resp, "replaced_deleted_at") == "" {
		t.Error("the report does not say when the replaced key stops working, which is the one " +
			"date an operator has to give the clients still holding it")
	}
	if !srv.HasSpacesKey(old) {
		t.Error("rotate deleted the old key immediately, breaking every client holding it; " +
			"revoke-upstream is the lever for that")
	}
	if got := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil)); got != fresh {
		t.Errorf("after rotate the role serves %s, not the key rotate minted (%s)", got, fresh)
	}
	if n := srv.ProvisionedSpacesKeyCount(); n != 2 {
		t.Errorf("expected the replaced and the fresh key both live during the overlap, got %d", n)
	}
}

// Rotating a role no client has read yet provisions its first key. The worker deliberately
// does not — spending an account's key allowance on a credential nobody asked for — but an
// operator asking in as many words has asked for it, and it lets a key be in place before the
// clients that will use it arrive.
func TestRotatedSpacesRotate_ProvisionsARoleNobodyHasRead(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	resp := rotateRoleNow(t, b, storage, rotatedRoleName)
	if resp.IsError() {
		t.Fatalf("rotate was refused for an unread role: %v", resp)
	}
	minted := rotateField(t, resp, "access_key")
	if got := rotateField(t, resp, "replaced_access_key"); got != "" {
		t.Errorf("the report names %s as replaced, but the role had no key", got)
	}
	if got := rotateField(t, resp, "replaced_deleted_at"); got != "" {
		t.Errorf("the report gives a deletion date (%s) for a key that never existed", got)
	}
	if n := srv.ProvisionedSpacesKeyCount(); n != 1 {
		t.Fatalf("expected one key after provisioning an unread role, got %d", n)
	}
	if got := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil)); got != minted {
		t.Errorf("the first read served %s rather than the key rotate had already minted (%s), so "+
			"an operator preparing a role ahead of its clients costs the account two keys", got, minted)
	}
}

// The endpoint exists for one lifecycle. On the other two the credential is the lease's: a
// per-lease key is replaced by reading again, and a token by letting the lease end.
func TestRotatedSpacesRotate_RefusesTheOtherCredentialTypes(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	for _, roleName := range []string{"spaces", "test-role"} {
		t.Run(roleName, func(t *testing.T) {
			resp := rotateRoleNow(t, b, storage, roleName)
			if !resp.IsError() {
				t.Fatalf("rotate was accepted for role %q: %v", roleName, resp)
			}
			if got := rotateCode(t, resp); got != credenvelope.ErrUnsupported {
				t.Errorf("rotate on role %q answered error_code=%q, want %q", roleName, got,
					credenvelope.ErrUnsupported)
			}
			if n := srv.ProvisionedSpacesKeyCount(); n != 0 {
				t.Errorf("a refused rotate minted %d keys", n)
			}
		})
	}
}

// A disabled role is the incident lever: nothing the plugin does on its behalf may reach the
// cloud, and rotating is minting.
func TestRotatedSpacesRotate_RefusesADisabledRole(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/" + rotatedRoleName, Storage: storage,
		Data: map[string]interface{}{"disabled": true},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("disabling the role failed: err=%v resp=%v", err, resp)
	}

	rotated := rotateRoleNow(t, b, storage, rotatedRoleName)
	if !rotated.IsError() {
		t.Fatalf("rotate minted for a disabled role: %v", rotated)
	}
	if got := rotateCode(t, rotated); got != credenvelope.ErrRoleDisabled {
		t.Errorf("rotate on a disabled role answered error_code=%q, want %q", got,
			credenvelope.ErrRoleDisabled)
	}
	if n := srv.ProvisionedSpacesKeyCount(); n != 0 {
		t.Errorf("rotate minted %d keys for a disabled role", n)
	}
}

// A role that does not exist must not be reported as rotated.
func TestRotatedSpacesRotate_RefusesAMissingRole(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	resp := rotateRoleNow(t, b, storage, "no-such-role")
	if !resp.IsError() {
		t.Fatalf("rotate was accepted for a role that does not exist: %v", resp)
	}
	if got := rotateCode(t, resp); got != credenvelope.ErrRoleNotFound {
		t.Errorf("rotate on a missing role answered error_code=%q, want %q", got,
			credenvelope.ErrRoleNotFound)
	}
}
