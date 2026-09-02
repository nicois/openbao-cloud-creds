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

	// MinterCredentialLimit is how many live credentials ONE minter may have
	// outstanding, where the cloud caps that per account. Selection passes over a
	// minter at its limit and uses the next in preference order, so a set scales the
	// ceiling to (limit x minters) — which is a second reason to add minters, next to
	// redundancy and rate-limit sharding.
	//
	// Nil or zero means UNENFORCED, and that has to be the default: most clouds'
	// caps are undocumented, and a guessed limit would refuse issuance that the
	// cloud would have allowed. Setting it is how an operator opts into the
	// protection, and into the warning that precedes the ceiling.
	//
	// It bounds what this MOUNT knows it holds. Credentials created in the same
	// account by anything else, and orphans whose tracking record was lost, are
	// invisible to it — so the cloud's own refusal still has to be handled, and this
	// is about avoiding wasted calls and warning in time, not about being
	// authoritative. See pkg/mintercapacity.
	MinterCredentialLimit *int `json:"minter_credential_limit,omitempty"`
}

// DefaultCapabilityCacheTTL is the default for CapabilityCacheTTL. It is declared
// here rather than imported from pkg/capability because cloudconfig must not depend
// on a package that depends on it; the two constants are asserted equal by
// pkg/capability's tests.
const DefaultCapabilityCacheTTL = time.Hour

// CredentialLimitPerMinter reports the configured per-minter cap, or 0 when unset —
// which pkg/mintercapacity treats as unenforced.
func (c *PluginConfig) CredentialLimitPerMinter() int {
	if c == nil || c.MinterCredentialLimit == nil || *c.MinterCredentialLimit < 0 {
		return 0
	}
	return *c.MinterCredentialLimit
}

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
