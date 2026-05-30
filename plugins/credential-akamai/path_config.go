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
				"host": {
					Type:        framework.TypeString,
					Description: "Akamai API host (e.g., akab-xxxx.luna.akamaiapis.net)",
				},
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
	host := d.Get("host").(string)
	if host == "" {
		return logical.ErrorResponse("host is required"), nil
	}

	flushInterval := time.Duration(d.Get("flush_interval").(int)) * time.Second
	reconcileCadence := time.Duration(d.Get("reconcile_cadence").(int)) * time.Second

	cfg := &cloudconfig.PluginConfig{
		Cloud:             "akamai",
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

	// Store host separately
	hostEntry, err := logical.StorageEntryJSON("config/host", map[string]string{"host": host})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, hostEntry); err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.config = cfg
	b.host = host
	if url, ok := d.GetOk("akamai_api_url"); ok {
		b.apiURL = url.(string)
	}
	b.mu.Unlock()

	go b.startWorkers(context.Background(), req.Storage)

	return nil, nil
}

// loadHost restores the configured Akamai host from storage so the EdgeGrid
// signer has it after a process restart, before any config write happens.
func (b *backend) loadHost(ctx context.Context, storage logical.Storage) error {
	entry, err := storage.Get(ctx, "config/host")
	if err != nil {
		return err
	}
	if entry == nil {
		return nil
	}
	var h map[string]string
	if err := json.Unmarshal(entry.Value, &h); err != nil {
		return err
	}
	b.mu.Lock()
	b.host = h["host"]
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
