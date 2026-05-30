package credentialexoscale

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
				"flush_interval": {
					Type:        framework.TypeDurationSecond,
					Default:     900,
					Description: "Metrics flush interval in seconds",
				},
				"reconcile_cadence": {
					Type:        framework.TypeDurationSecond,
					Default:     21600,
					Description: "Reconciliation cadence in seconds",
				},
				"exoscale_api_url": {
					Type:        framework.TypeString,
					Default:     "https://api-ch-gva-2.exoscale.com",
					Description: "Exoscale API base URL (for testing)",
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
	flushInterval := time.Duration(d.Get("flush_interval").(int)) * time.Second
	reconcileCadence := time.Duration(d.Get("reconcile_cadence").(int)) * time.Second

	cfg := &cloudconfig.PluginConfig{
		Cloud:             "exoscale",
		FlushInterval:     flushInterval,
		ReconcileCadence:  reconcileCadence,
		BootstrapDelay:    24 * time.Hour,
		MaxDeletesPerPass: 10,
	}

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	apiURL := d.Get("exoscale_api_url").(string)

	// Persist operational config separately so a reloaded backend (failover/
	// restart) can rehydrate it before any config write happens. KI-001.
	metaEntry, err := logical.StorageEntryJSON("config_meta", map[string]string{"api_url": apiURL})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, metaEntry); err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.config = cfg
	if apiURL != "" {
		b.apiURL = apiURL
	}
	b.mu.Unlock()

	go b.startWorkers(context.Background(), req.Storage)

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
	if meta["api_url"] != "" {
		b.apiURL = meta["api_url"]
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
			"cloud":             cfg.Cloud,
			"flush_interval":    int(cfg.FlushInterval.Seconds()),
			"reconcile_cadence": int(cfg.ReconcileCadence.Seconds()),
		},
	}, nil
}
