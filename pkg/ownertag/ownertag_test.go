package ownertag

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestTwoMountsDoNotOwnEachOthersCredentials is the property A19 is about. Two mounts
// against one cloud account each saw the other's LIVE credentials as orphans, because
// the owner tag identified the product rather than the instance, and deleted up to ten
// per pass — silently. decisions.md recommended multiple mounts as an isolation
// strategy with no warning.
func TestTwoMountsDoNotOwnEachOthersCredentials(t *testing.T) {
	ctx := t.Context()
	mountA, mountB := &logical.InmemStorage{}, &logical.InmemStorage{}

	idA, err := InstanceID(ctx, mountA)
	if err != nil {
		t.Fatalf("InstanceID(A): %v", err)
	}
	idB, err := InstanceID(ctx, mountB)
	if err != nil {
		t.Fatalf("InstanceID(B): %v", err)
	}
	if idA == idB {
		t.Fatal("two mounts minted the same instance id, so they cannot tell their credentials apart")
	}

	nameA := CredentialName(idA, "backup-reader", "req-1")
	nameB := CredentialName(idB, "backup-reader", "req-2")

	if !Owns(idA, nameA) || !Owns(idB, nameB) {
		t.Fatal("a mount does not recognise its own credential")
	}
	if Owns(idA, nameB) {
		t.Errorf("mount A claims %q, which mount B created — A's reconciler would delete a live "+
			"credential belonging to B (A19)", nameB)
	}
	if Owns(idB, nameA) {
		t.Errorf("mount B claims %q, which mount A created", nameA)
	}
}

// The id must survive a reload: it lives in storage precisely because a timer-driven
// worker has no request to read a mount point from, and an id regenerated per process
// would orphan every credential the previous process issued.
func TestInstanceIDIsStable(t *testing.T) {
	ctx := t.Context()
	storage := &logical.InmemStorage{}
	first, err := InstanceID(ctx, storage)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := InstanceID(ctx, storage)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first != second {
		t.Errorf("instance id changed between calls (%q -> %q): every previously issued credential "+
			"would become unrecognised", first, second)
	}
}

// A credential named under the OLD scheme must not match — it becomes unmanaged rather
// than deleted, which is the safe direction for a migration.
func TestOldSchemeNamesAreNotClaimed(t *testing.T) {
	if Owns("abcdef0123456789", Base+"backup-reader-req-1") {
		t.Error("a pre-migration credential is claimed by the new filter; the migration must leave " +
			"old credentials alone rather than risk deleting something it cannot attribute")
	}
}
