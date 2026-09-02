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

func TestDefaultConfig_MinterExpiryWarnDefaultsToMinMinterGap(t *testing.T) {
	cfg := cloudconfig.DefaultConfig("do")
	if cfg.MinterExpiryWarn != cloudconfig.MinMinterGap {
		t.Fatalf("MinterExpiryWarn = %v, want MinMinterGap (%v)", cfg.MinterExpiryWarn, cloudconfig.MinMinterGap)
	}
}

func TestDefaultConfig_MinterRetireGraceDefaultsToMinMinterGap(t *testing.T) {
	if got := cloudconfig.DefaultConfig("do").MinterRetireGrace; got != cloudconfig.MinMinterGap {
		t.Fatalf("MinterRetireGrace = %v, want MinMinterGap", got)
	}
}

// TestCredentialLimitPerMinterDefaultsToUnenforced: most clouds' caps are undocumented, so an unset
// field must not become a guessed limit that refuses issuance the cloud would have allowed.
func TestCredentialLimitPerMinterDefaultsToUnenforced(t *testing.T) {
	limit := 8
	negative := -1
	cases := map[string]struct {
		cfg  *cloudconfig.PluginConfig
		want int
	}{
		"nil config":  {nil, 0},
		"unset field": {&cloudconfig.PluginConfig{}, 0},
		"set":         {&cloudconfig.PluginConfig{MinterCredentialLimit: &limit}, 8},
		"negative":    {&cloudconfig.PluginConfig{MinterCredentialLimit: &negative}, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.cfg.CredentialLimitPerMinter(); got != tc.want {
				t.Errorf("CredentialLimitPerMinter() = %d, want %d", got, tc.want)
			}
		})
	}
}
