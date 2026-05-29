package cloudconfig

import (
	"fmt"
	"time"
)

type Role struct {
	Name              string                 `json:"name"`
	Cloud             string                 `json:"cloud"`
	DefaultTTL        time.Duration          `json:"default_ttl"`
	MaxTTL            time.Duration          `json:"max_ttl"`
	DisableAutoDelete bool                   `json:"disable_auto_delete,omitempty"`
	CloudConfig       map[string]interface{} `json:"cloud_config,omitempty"`
}

func ValidateRole(r *Role) error {
	if r.Name == "" {
		return fmt.Errorf("role name is required")
	}
	if r.DefaultTTL <= 0 {
		return fmt.Errorf("default_ttl must be positive")
	}
	if r.MaxTTL <= 0 {
		return fmt.Errorf("max_ttl must be positive")
	}
	if r.DefaultTTL > r.MaxTTL {
		return fmt.Errorf("default_ttl (%v) must be <= max_ttl (%v)", r.DefaultTTL, r.MaxTTL)
	}
	return nil
}
