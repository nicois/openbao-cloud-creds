package cloudconfig_test

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

func TestMinterSetValid_SingleNeverExpires(t *testing.T) {
	set := []cloudconfig.Minter{
		{ID: "m1", NeverExpires: true},
	}
	if err := cloudconfig.ValidateMinterSet(set); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestMinterSetValid_NeverExpiresPlusExpiring(t *testing.T) {
	set := []cloudconfig.Minter{
		{ID: "m1", NeverExpires: true},
		{ID: "m2", ExpiresAt: time.Now().Add(30 * 24 * time.Hour)},
	}
	if err := cloudconfig.ValidateMinterSet(set); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestMinterSetValid_TwoExpiringWith7dGap(t *testing.T) {
	now := time.Now()
	set := []cloudconfig.Minter{
		{ID: "m1", ExpiresAt: now.Add(14 * 24 * time.Hour)},
		{ID: "m2", ExpiresAt: now.Add(30 * 24 * time.Hour)},
	}
	if err := cloudconfig.ValidateMinterSet(set); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestMinterSetInvalid_SingleExpiring(t *testing.T) {
	set := []cloudconfig.Minter{
		{ID: "m1", ExpiresAt: time.Now().Add(30 * 24 * time.Hour)},
	}
	if err := cloudconfig.ValidateMinterSet(set); err == nil {
		t.Fatal("expected error for single expiring minter")
	}
}

func TestMinterSetInvalid_TwoExpiringTooClose(t *testing.T) {
	now := time.Now()
	set := []cloudconfig.Minter{
		{ID: "m1", ExpiresAt: now.Add(10 * 24 * time.Hour)},
		{ID: "m2", ExpiresAt: now.Add(12 * 24 * time.Hour)},
	}
	if err := cloudconfig.ValidateMinterSet(set); err == nil {
		t.Fatal("expected error for minters with <7d gap")
	}
}

func TestMinterSetInvalid_Empty(t *testing.T) {
	if err := cloudconfig.ValidateMinterSet(nil); err == nil {
		t.Fatal("expected error for empty minter set")
	}
}
