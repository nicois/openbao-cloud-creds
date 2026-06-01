package credentialakamai

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) configPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				fieldHost: {
					Type:        framework.TypeString,
					Description: "Akamai API host (e.g., akab-xxxx.luna.akamaiapis.net)",
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
				"minter_expiry_warn": {
					Type:        framework.TypeDurationSecond,
					Default:     defaultMinterExpiryWarnSeconds,
					Description: "Warn in logs when an expiring minter is within this many seconds of expiry",
				},
				"akamai_api_url": {
					Type:        framework.TypeString,
					Default:     "",
					Description: "Override Akamai API base URL (for testing)",
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
	host := d.Get(fieldHost).(string)
	if host == "" {
		return logical.ErrorResponse("host is required"), nil
	}

	flushInterval := time.Duration(d.Get("flush_interval").(int)) * time.Second
	reconcileCadence := time.Duration(d.Get("reconcile_cadence").(int)) * time.Second
	minterExpiryWarn := time.Duration(d.Get("minter_expiry_warn").(int)) * time.Second

	cfg := &cloudconfig.PluginConfig{
		Cloud:             cloudName,
		FlushInterval:     flushInterval,
		ReconcileCadence:  reconcileCadence,
		BootstrapDelay:    reconcilerBootstrapDelay,
		MaxDeletesPerPass: maxDeletesPerPass,
		MinterExpiryWarn:  minterExpiryWarn,
	}

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	apiURL := d.Get("akamai_api_url").(string)

	// Store host and api url separately so a reloaded backend (failover/restart)
	// can rehydrate them before any config write happens. KI-001.
	hostEntry, err := logical.StorageEntryJSON("config/host", map[string]string{
		fieldHost: host,
		"api_url": apiURL,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, hostEntry); err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.config = cfg
	b.host = host
	if apiURL != "" {
		b.apiURL = apiURL
	}
	b.mu.Unlock()

	go b.startWorkers(b.baseCtx, req.Storage)

	return nil, nil
}

// loadConfig restores the operational config (host, api url, plugin config)
// from storage so the EdgeGrid signer and HTTP client have them after a
// process restart / failover, before any config write happens. KI-001.
func (b *backend) loadConfig(ctx context.Context, storage logical.Storage) error {
	if entry, err := storage.Get(ctx, "config"); err == nil && entry != nil {
		var cfg cloudconfig.PluginConfig
		if err := json.Unmarshal(entry.Value, &cfg); err != nil {
			return err
		}
		b.mu.Lock()
		b.config = &cfg
		b.mu.Unlock()
	} else if err != nil {
		return err
	}

	entry, err := storage.Get(ctx, "config/host")
	if err != nil || entry == nil {
		return err
	}
	var h map[string]string
	if err := json.Unmarshal(entry.Value, &h); err != nil {
		return err
	}
	b.mu.Lock()
	if h[fieldHost] != "" {
		b.host = h[fieldHost]
	}
	if h["api_url"] != "" {
		b.apiURL = h["api_url"]
	}
	b.mu.Unlock()
	return nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
			fieldCloud:           cfg.Cloud,
			"flush_interval":     int(cfg.FlushInterval.Seconds()),
			"reconcile_cadence":  int(cfg.ReconcileCadence.Seconds()),
			"minter_expiry_warn": int(cfg.MinterExpiryWarn.Seconds()),
		},
	}, nil
}
