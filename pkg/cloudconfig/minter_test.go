package cloudconfig_test

import (
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
