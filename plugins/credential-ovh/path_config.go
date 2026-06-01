package credentialovh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// Schema defaults are expressed in seconds (framework.TypeDurationSecond).
	defaultFlushIntervalSeconds    = 900   // 15m
	defaultReconcileCadenceSeconds = 21600 // 6h

	// reconcilerBootstrapDelay holds off the first reconcile pass after a
	// (re)start so leases issued just before restart aren't seen as orphans.
	reconcilerBootstrapDelay = 24 * time.Hour

	// maxDeletesPerPass caps how many orphaned tracking entries one reconcile pass deletes.
	maxDeletesPerPass = 10

	// healthCheckInterval is how often the health-check worker probes minters,
	// and the recovery state machine's re-probe cadence.
	healthCheckInterval = 5 * time.Minute

	// authFailThreshold is how long upstream auth must keep failing before the
	// recovery state machine declares a minter hard-failed.
	authFailThreshold = 30 * time.Second
)

// regionEndpoints maps OVH region codes to their OAuth2 token endpoints.
var regionEndpoints = map[string]string{
	"eu": "https://www.ovh.com/auth/oauth2/token",
	"ca": "https://ca.ovh.com/auth/oauth2/token",
	"us": "https://us.ovhcloud.com/auth/oauth2/token",
}

func (b *backend) configPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				fieldRegion: {
					Type:        framework.TypeString,
					Default:     "eu",
					Description: "OVH region: eu, ca, or us (determines token endpoint URL)",
				},
				"token_endpoint": {
					Type:        framework.TypeString,
					Default:     "",
					Description: "Override token endpoint URL (for testing)",
				},
				"flush_interval": {
					Type:        framework.TypeDurationSecond,
					Default:     defaultFlushIntervalSeconds,
					Description: "Metrics flush interval in seconds",
				},
				"reconcile_cadence": {
					Type:        framework.TypeDurationSecond,
					Default:     defaultReconcileCadenceSeconds,
					Description: "Reconciliation cadence in seconds",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			},
		},
	}
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	region := d.Get(fieldRegion).(string)
	if _, valid := regionEndpoints[region]; !valid {
		return logical.ErrorResponse("invalid region %q: must be eu, ca, or us", region), nil
	}

	flushInterval := time.Duration(d.Get("flush_interval").(int)) * time.Second
	reconcileCadence := time.Duration(d.Get("reconcile_cadence").(int)) * time.Second

	cfg := &cloudconfig.PluginConfig{
		Cloud:             cloudName,
		FlushInterval:     flushInterval,
		ReconcileCadence:  reconcileCadence,
		BootstrapDelay:    reconcilerBootstrapDelay,
		MaxDeletesPerPass: maxDeletesPerPass,
	}

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Determine token endpoint
	tokenEndpoint := d.Get("token_endpoint").(string)
	if tokenEndpoint == "" {
		tokenEndpoint = regionEndpoints[region]
	}

	// Persist region + token endpoint separately so a reloaded backend
	// (failover/restart) can rehydrate them before any config write. KI-001.
	metaEntry, err := logical.StorageEntryJSON("config_meta", map[string]string{
		"region":         region,
		"token_endpoint": tokenEndpoint,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, metaEntry); err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.config = cfg
	b.region = region
	b.tokenEndpoint = tokenEndpoint
	b.mu.Unlock()

	go b.startWorkers(b.baseCtx, req.Storage)

	return nil, nil
}

// loadConfig rehydrates operational config from storage into the backend, so a
// reloaded backend (failover/restart) matches one that just had config written. KI-001.
func (b *backend) loadConfig(ctx context.Context, storage logical.Storage) error {
	entry, err := storage.Get(ctx, "config")
	if err != nil || entry == nil {
		return err
	}
	var cfg cloudconfig.PluginConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return err
	}
	b.mu.Lock()
	b.config = &cfg
	b.mu.Unlock()

	metaEntry, err := storage.Get(ctx, "config_meta")
	if err != nil || metaEntry == nil {
		return err
	}
	var meta map[string]string
	if err := json.Unmarshal(metaEntry.Value, &meta); err != nil {
		return err
	}
	b.mu.Lock()
	if meta["region"] != "" {
		b.region = meta["region"]
	}
	if meta["token_endpoint"] != "" {
		b.tokenEndpoint = meta["token_endpoint"]
	}
	b.mu.Unlock()
	return nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var cfg cloudconfig.PluginConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			fieldCloud:          cfg.Cloud,
			fieldRegion:         b.getRegion(),
			"flush_interval":    int(cfg.FlushInterval.Seconds()),
			"reconcile_cadence": int(cfg.ReconcileCadence.Seconds()),
		},
	}, nil
}

func (b *backend) getRegion() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.region
}

// parseMinterToken splits the stored colon-separated client_id:client_secret.
func parseMinterToken(token string) (clientID, clientSecret string, err error) {
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid minter token format: expected client_id:client_secret")
	}
	return parts[0], parts[1], nil
}
