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
}

func DefaultConfig(cloud string) *PluginConfig {
	return &PluginConfig{
		Cloud:             cloud,
		FlushInterval:     defaultFlushInterval,
		ReconcileCadence:  defaultReconcileCadence,
		BootstrapDelay:    defaultBootstrapDelay,
		MaxDeletesPerPass: defaultMaxDeletesPerPass,
		MinterExpiryWarn:  MinMinterGap,
	}
}
