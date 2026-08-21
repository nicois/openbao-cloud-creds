package capability

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func okCheck(key, minter, role string, ran *[]string) Check {
	return Check{
		Key: key, Minter: minter, Roles: []string{role},
		Run: func(context.Context) error {
			*ran = append(*ran, key)
			return nil
		},
	}
}

func TestVerify_RunsEachDistinctCheckOnce(t *testing.T) {
	var ran []string
	checks := []Check{
		okCheck("a", "m1", "role-a", &ran),
		okCheck("a", "m1", "role-b", &ran),
		okCheck("b", "m1", "role-c", &ran),
	}
	result, err := Verify(t.Context(), checks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ran) != 2 {
		t.Fatalf("expected 2 probes for 2 distinct keys, ran %v", ran)
	}
	if result.Ran != 2 || result.Skipped != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

// A failure must name the minter and every role that shares the failing shape,
// so the operator knows what is broken and for whom.
func TestVerify_FailureNamesMinterAndAllSharingRoles(t *testing.T) {
	fail := func(context.Context) error { return errors.New("403 forbidden") }
	checks := []Check{
		{Key: "a", Minter: "minter-1", Roles: []string{"role-a"}, Run: fail},
		{Key: "a", Minter: "minter-1", Roles: []string{"role-b"}, Run: fail},
	}
	_, err := Verify(t.Context(), checks)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, want := range []string{"minter-1", "role-a", "role-b", "403 forbidden"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not mention %q", msg, want)
		}
	}
}

func TestVerify_UnsupportedIsSkippedNotFailed(t *testing.T) {
	checks := []Check{{
		Key: "a", Minter: "m1", Roles: []string{"role-a"},
		Run: func(context.Context) error { return ErrUnsupported },
	}}
	result, err := Verify(t.Context(), checks)
	if err != nil {
		t.Fatalf("ErrUnsupported must not fail verification: %v", err)
	}
	if result.Skipped != 1 || result.Ran != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestDedupe_IsDeterministicallyOrdered(t *testing.T) {
	var ran []string
	got := Dedupe([]Check{
		okCheck("c", "m", "r", &ran),
		okCheck("a", "m", "r", &ran),
		okCheck("b", "m", "r", &ran),
	})
	keys := make([]string, 0, len(got))
	for _, c := range got {
		keys = append(keys, c.Key)
	}
	if strings.Join(keys, ",") != "a,b,c" {
		t.Fatalf("expected key-sorted order, got %v", keys)
	}
}

func putRole(t *testing.T, storage logical.Storage, name string, role map[string]interface{}) {
	t.Helper()
	entry, err := logical.StorageEntryJSON("roles/"+name, role)
	if err != nil {
		t.Fatalf("entry build failed: %v", err)
	}
	if err := storage.Put(t.Context(), entry); err != nil {
		t.Fatalf("put failed: %v", err)
	}
}

func TestRolesBoundTo_FiltersBySetAndSkipsDisabled(t *testing.T) {
	storage := &logical.InmemStorage{}
	putRole(t, storage, "in-set", map[string]interface{}{"name": "in-set", "minter_set": "alpha"})
	putRole(t, storage, "other-set", map[string]interface{}{"name": "other-set", "minter_set": "beta"})
	putRole(t, storage, "off", map[string]interface{}{"name": "off", "minter_set": "alpha", "disabled": true})

	bound, err := RolesBoundTo(t.Context(), storage, "alpha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bound) != 1 || bound[0].Name != "in-set" {
		t.Fatalf("unexpected bound roles: %+v", bound)
	}
	if len(bound[0].Raw) == 0 {
		t.Fatal("bound role carried no raw JSON for the caller to decode")
	}
}

// Probe credentials must carry the owner prefix: if the probe's own delete
// fails, the owner-tag reconciler is what reclaims them.
func TestProbeName_IsOwnerTaggedAndUnique(t *testing.T) {
	first, second := ProbeName("my-role"), ProbeName("my-role")
	for _, name := range []string{first, second} {
		if !strings.HasPrefix(name, "cloud-creds-my-role-") {
			t.Fatalf("probe name %q lacks the owner prefix", name)
		}
	}
	if first == second {
		t.Fatalf("probe names collided: %q", first)
	}
}
