package cloudconfig

import "time"

const (
	defaultReconcileCadence  = 6 * time.Hour
	defaultBootstrapDelay    = 24 * time.Hour
	defaultMaxDeletesPerPass = 10
)

type PluginConfig struct {
	Versioned
	Cloud             string        `json:"cloud"`
	Minters           []Minter      `json:"minters"`
	ReconcileCadence  time.Duration `json:"reconcile_cadence"`
	BootstrapDelay    time.Duration `json:"bootstrap_delay"`
	MaxDeletesPerPass int           `json:"max_deletes_per_pass"`
	MinterExpiryWarn  time.Duration `json:"minter_expiry_warn"`
	MinterRetireGrace time.Duration `json:"minter_retire_grace"`

	// VerifyMinterCapability gates the capability probe (pkg/capability): a
	// throwaway mint-and-delete run at minter-set write, role write, and before a
	// rotation commits, proving a minter can mint and not merely authenticate.
	// A nil pointer means "not configured", which CapabilityVerificationEnabled
	// reads as enabled — the fail-closed default, so a config written before this
	// field existed does not silently lose the check.
	VerifyMinterCapability *bool `json:"verify_minter_capability,omitempty"`

	// CapabilityCacheTTL is how long a successful capability probe stands in for a
	// fresh one, so a repeated configuration write does not re-mint the whole
	// (minters x roles) fan-out. A nil pointer means "not configured", which reads
	// as capability.DefaultCacheTTL; an explicit 0 disables the cache and re-probes
	// every write.
	CapabilityCacheTTL *time.Duration `json:"capability_cache_ttl,omitempty"`
}

// DefaultCapabilityCacheTTL is the default for CapabilityCacheTTL. It is declared
// here rather than imported from pkg/capability because cloudconfig must not depend
// on a package that depends on it; the two constants are asserted equal by
// pkg/capability's tests.
const DefaultCapabilityCacheTTL = time.Hour

// CapabilityVerificationEnabled reports whether capability probes should run.
// Enabled unless an operator has explicitly set verify_minter_capability=false,
// including when there is no stored config at all.
func (c *PluginConfig) CapabilityVerificationEnabled() bool {
	return c == nil || c.VerifyMinterCapability == nil || *c.VerifyMinterCapability
}

// CapabilityCacheDuration reports how long a probe verdict stands. An operator's
// explicit 0 is honoured (the cache off), which is why the field is a pointer.
func (c *PluginConfig) CapabilityCacheDuration() time.Duration {
	if c == nil || c.CapabilityCacheTTL == nil {
		return DefaultCapabilityCacheTTL
	}
	if *c.CapabilityCacheTTL < 0 {
		return 0
	}
	return *c.CapabilityCacheTTL
}

func DefaultConfig(cloud string) *PluginConfig {
	return &PluginConfig{
		Versioned:         Versioned{Schema: SchemaVersion},
		Cloud:             cloud,
		ReconcileCadence:  defaultReconcileCadence,
		BootstrapDelay:    defaultBootstrapDelay,
		MaxDeletesPerPass: defaultMaxDeletesPerPass,
		MinterExpiryWarn:  MinMinterGap,
		MinterRetireGrace: MinMinterGap,
	}
}
