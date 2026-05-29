package cloudconfig

import "time"

type PluginConfig struct {
	Cloud             string        `json:"cloud"`
	Minters           []Minter      `json:"minters"`
	FlushInterval     time.Duration `json:"flush_interval"`
	ReconcileCadence  time.Duration `json:"reconcile_cadence"`
	BootstrapDelay    time.Duration `json:"bootstrap_delay"`
	MaxDeletesPerPass int           `json:"max_deletes_per_pass"`
}

func DefaultConfig(cloud string) *PluginConfig {
	return &PluginConfig{
		Cloud:             cloud,
		FlushInterval:     15 * time.Minute,
		ReconcileCadence:  6 * time.Hour,
		BootstrapDelay:    24 * time.Hour,
		MaxDeletesPerPass: 10,
	}
}
