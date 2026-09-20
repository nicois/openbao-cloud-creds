package cloudconfig_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

func TestValidateMinterSet_ExcludesRetired(t *testing.T) {
	// A set valid ONLY because of a retired never_expires minter must FAIL:
	// validation considers active minters only.
	minters := []cloudconfig.Minter{
		{ID: "old", NeverExpires: true, Retired: true, RetiredAt: time.Now()},
		{ID: "new", ExpiresAt: time.Now().Add(48 * time.Hour)},
	}
	// active = just "new" (one expiring minter) -> invalid (needs >=2 or a never_expires)
	if err := cloudconfig.ValidateMinterSet(minters); err == nil {
		t.Fatal("expected validation to fail when only active minter is a single expiring one")
	}
}

func TestValidateMinterSet_ActiveNeverExpiresPasses(t *testing.T) {
	minters := []cloudconfig.Minter{
		{ID: "old", NeverExpires: true, Retired: true, RetiredAt: time.Now()},
		{ID: "new", NeverExpires: true},
	}
	if err := cloudconfig.ValidateMinterSet(minters); err != nil {
		t.Fatalf("active never_expires minter should satisfy the rule: %v", err)
	}
}

func TestActiveMinters_FiltersRetired(t *testing.T) {
	minters := []cloudconfig.Minter{
		{ID: "a"},
		{ID: "b", Retired: true},
	}
	active := cloudconfig.ActiveMinters(minters)
	if len(active) != 1 || active[0].ID != "a" {
		t.Fatalf("ActiveMinters = %v, want [a]", active)
	}
}

// A minter arrives as an untyped object, so every plugin read the keys it knew and
// ignored the rest: `rotation_params` was accepted in silence on the four clouds
// that cannot rotate a minter at all, and any mistyped key was accepted as though it
// had been understood (A28).
func TestValidateMinterKeys(t *testing.T) {
	rotatable := []string{"id", "expires_at", "never_expires", "token", cloudconfig.MinterKeyRotationParams}
	fixed := []string{"id", "expires_at", "never_expires", "token"}

	t.Run("accepts a known shape", func(t *testing.T) {
		raw := map[string]any{"id": "m1", "token": "t", "never_expires": true}
		if err := cloudconfig.ValidateMinterKeys("m1", raw, fixed...); err != nil {
			t.Fatalf("a valid minter was rejected: %v", err)
		}
	})

	t.Run("rotation_params is refused where nothing can rotate, and says why", func(t *testing.T) {
		raw := map[string]any{"id": "m1", "token": "t", cloudconfig.MinterKeyRotationParams: map[string]any{}}
		err := cloudconfig.ValidateMinterKeys("m1", raw, fixed...)
		if err == nil {
			t.Fatal("rotation_params was accepted on a cloud that cannot rotate a minter, so the " +
				"operator's setting is silently discarded")
		}
		if !strings.Contains(err.Error(), "cannot self-rotate") {
			t.Errorf("the rejection should explain that nothing would read it, got: %v", err)
		}
	})

	t.Run("rotation_params is accepted where rotation exists", func(t *testing.T) {
		raw := map[string]any{"id": "m1", "token": "t", cloudconfig.MinterKeyRotationParams: map[string]any{}}
		if err := cloudconfig.ValidateMinterKeys("m1", raw, rotatable...); err != nil {
			t.Fatalf("rotation_params was refused on a cloud that rotates: %v", err)
		}
	})

	t.Run("a mistyped key is refused rather than ignored", func(t *testing.T) {
		// The dangerous one: never_expire (singular) silently means "this minter
		// expires", and RSK-005 exists because a set that has quietly become
		// single-minter is the failure nobody notices until the minter dies.
		raw := map[string]any{"id": "m1", "token": "t", "never_expire": true}
		err := cloudconfig.ValidateMinterKeys("m1", raw, fixed...)
		if err == nil {
			t.Fatal("a mistyped key was accepted as though it had been understood")
		}
		if !strings.Contains(err.Error(), "never_expire") || !strings.Contains(err.Error(), "accepted:") {
			t.Errorf("the rejection should name the bad key and list what is accepted, got: %v", err)
		}
	})
}
