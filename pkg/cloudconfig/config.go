package cloudconfig

import "time"

const (
	defaultFlushInterval     = 15 * time.Minute
	defaultReconcileCadence  = 6 * time.Hour
	defaultBootstrapDelay    = 24 * time.Hour
	defaultMaxDeletesPerPass = 10
)

type PluginConfig struct {
	Cloud             string        `json:"cloud"`
	Minters           []Minter      `json:"minters"`
	FlushInterval     time.Duration `json:"flush_interval"`
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
}

// CapabilityVerificationEnabled reports whether capability probes should run.
// Enabled unless an operator has explicitly set verify_minter_capability=false,
// including when there is no stored config at all.
func (c *PluginConfig) CapabilityVerificationEnabled() bool {
	return c == nil || c.VerifyMinterCapability == nil || *c.VerifyMinterCapability
}

func DefaultConfig(cloud string) *PluginConfig {
	return &PluginConfig{
		Cloud:             cloud,
		FlushInterval:     defaultFlushInterval,
		ReconcileCadence:  defaultReconcileCadence,
		BootstrapDelay:    defaultBootstrapDelay,
		MaxDeletesPerPass: defaultMaxDeletesPerPass,
		MinterExpiryWarn:  MinMinterGap,
		MinterRetireGrace: MinMinterGap,
	}
}
