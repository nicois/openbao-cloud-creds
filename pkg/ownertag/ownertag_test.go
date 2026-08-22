package ownertag

import (
	"strings"
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

// TestFitNameKeepsThePartsThatMatter is the regression guard for AWS's session
// names. The bug was a tail truncation, so every assertion here is about which end
// gives way.
func TestFitNameKeepsThePartsThatMatter(t *testing.T) {
	const instance = "abcdef0123456789"
	prefix := Prefix(instance)
	const requestID = "0f1e2d3c-4b5a"

	t.Run("UnboundedAndFittingNamesAreUntouched", func(t *testing.T) {
		want := prefix + "role" + "-" + requestID
		if got := FitName(prefix, "role", requestID, 0); got != want {
			t.Errorf("maxLen 0 must mean unbounded: got %q want %q", got, want)
		}
		if got := FitName(prefix, "role", requestID, len(want)); got != want {
			t.Errorf("a name that already fits must be returned whole: got %q want %q", got, want)
		}
	})

	t.Run("ShortensTheRoleNotTheRequestID", func(t *testing.T) {
		const maxLen = 64
		got := FitName(prefix, "a-role-name-far-too-long-to-fit-in-a-session-name", requestID, maxLen)
		if len(got) > maxLen {
			t.Fatalf("fitted name is %d chars, over the %d cap: %q", len(got), maxLen, got)
		}
		if !Owns(instance, got) {
			t.Errorf("the owner prefix did not survive fitting, so this mount's own reconciler "+
				"would no longer recognise %q as ours", got)
		}
		if !strings.HasSuffix(got, requestID) {
			t.Errorf("the request id did not survive fitting: %q. Truncating the tail is the bug — "+
				"every lease of a long-named role then shares one upstream name, and the cloud's "+
				"audit log can no longer attribute a session to a request", got)
		}
	})

	t.Run("DropsTheRoleEntirelyBeforeTouchingEitherEnd", func(t *testing.T) {
		// A cap with no room for the role: prefix + suffix must still both survive.
		got := FitName(prefix, "role", requestID, len(prefix)+len(requestID))
		if got != prefix+requestID {
			t.Errorf("got %q, want the prefix and suffix with the middle dropped", got)
		}
	})

	t.Run("PrefixSurvivesEvenAnImpossibleCap", func(t *testing.T) {
		got := FitName(prefix, "role", requestID, len(prefix)+2)
		if !Owns(instance, got) {
			t.Errorf("%q lost the owner prefix; ownership is the one part that must never be cut "+
				"while any alternative remains", got)
		}
	})
}
