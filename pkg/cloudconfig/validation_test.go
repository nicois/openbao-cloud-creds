package cloudconfig_test

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

func TestValidateSetName(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "simple", input: "default", wantErr: false},
		{name: "with-dash", input: "set-1", wantErr: false},
		{name: "with-underscore", input: "a_b", wantErr: false},
		{name: "mixed-alnum", input: "ABC123", wantErr: false},
		{name: "empty", input: "", wantErr: true},
		{name: "path-traversal", input: "../evil", wantErr: true},
		{name: "slash", input: "a/b", wantErr: true},
		{name: "space", input: "a b", wantErr: true},
		{name: "dot", input: "a.b", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cloudconfig.ValidateSetName(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateSetName(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestValidateRole(t *testing.T) {
	cases := []struct {
		name    string
		role    cloudconfig.Role
		wantErr bool
	}{
		{
			name:    "valid",
			role:    cloudconfig.Role{Name: "reader", DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour},
			wantErr: false,
		},
		{
			name:    "valid-equal-ttls",
			role:    cloudconfig.Role{Name: "reader", DefaultTTL: time.Hour, MaxTTL: time.Hour},
			wantErr: false,
		},
		{
			name:    "empty-name",
			role:    cloudconfig.Role{Name: "", DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour},
			wantErr: true,
		},
		{
			name:    "zero-default-ttl",
			role:    cloudconfig.Role{Name: "reader", DefaultTTL: 0, MaxTTL: 2 * time.Hour},
			wantErr: true,
		},
		{
			name:    "negative-default-ttl",
			role:    cloudconfig.Role{Name: "reader", DefaultTTL: -time.Hour, MaxTTL: 2 * time.Hour},
			wantErr: true,
		},
		{
			name:    "zero-max-ttl",
			role:    cloudconfig.Role{Name: "reader", DefaultTTL: time.Hour, MaxTTL: 0},
			wantErr: true,
		},
		{
			name:    "negative-max-ttl",
			role:    cloudconfig.Role{Name: "reader", DefaultTTL: time.Hour, MaxTTL: -time.Hour},
			wantErr: true,
		},
		{
			name:    "default-gt-max",
			role:    cloudconfig.Role{Name: "reader", DefaultTTL: 3 * time.Hour, MaxTTL: time.Hour},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.role
			err := cloudconfig.ValidateRole(&r)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateRole(%+v) error = %v, wantErr = %v", tc.role, err, tc.wantErr)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := cloudconfig.DefaultConfig("do")

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.Cloud != "do" {
		t.Errorf("Cloud = %q, want %q", cfg.Cloud, "do")
	}
	if cfg.ReconcileCadence != 6*time.Hour {
		t.Errorf("ReconcileCadence = %v, want %v", cfg.ReconcileCadence, 6*time.Hour)
	}
	if cfg.BootstrapDelay != 24*time.Hour {
		t.Errorf("BootstrapDelay = %v, want %v", cfg.BootstrapDelay, 24*time.Hour)
	}
	if cfg.MaxDeletesPerPass != 10 {
		t.Errorf("MaxDeletesPerPass = %d, want %d", cfg.MaxDeletesPerPass, 10)
	}
	if len(cfg.Minters) != 0 {
		t.Errorf("Minters = %v, want empty", cfg.Minters)
	}
}
