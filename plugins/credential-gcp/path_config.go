package credentialgcp

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
			Pattern: pathConfig,
			Fields: map[string]*framework.FieldSchema{
				"project": {
					Type:        framework.TypeString,
					Default:     "",
					Description: "GCP project ID (for context/documentation)",
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
				fieldMinterRetireGrace: {
					Type:        framework.TypeDurationSecond,
					Default:     defaultMinterRetireGraceSeconds,
					Description: "Seconds after a minter is retired (by rotation) before its upstream SA key is deleted by the retired-sweep",
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
	minterExpiryWarn := time.Duration(d.Get("minter_expiry_warn").(int)) * time.Second
	minterRetireGrace := time.Duration(d.Get(fieldMinterRetireGrace).(int)) * time.Second

	cfg := &cloudconfig.PluginConfig{
		Cloud:             cloudName,
		FlushInterval:     flushInterval,
		ReconcileCadence:  reconcileCadence,
		BootstrapDelay:    reconcilerBootstrapDelay,
		MaxDeletesPerPass: maxDeletesPerPass,
		MinterExpiryWarn:  minterExpiryWarn,
		MinterRetireGrace: minterRetireGrace,
	}

	entry, err := logical.StorageEntryJSON(pathConfig, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.config = cfg
	if project, ok := d.GetOk("project"); ok {
		b.project = project.(string)
	}
	b.mu.Unlock()

	go b.startWorkers(b.baseCtx, req.Storage)

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, pathConfig)
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
			fieldCloud:             cfg.Cloud,
			"project":              b.getProject(),
			"flush_interval":       int(cfg.FlushInterval.Seconds()),
			"reconcile_cadence":    int(cfg.ReconcileCadence.Seconds()),
			"minter_expiry_warn":   int(cfg.MinterExpiryWarn.Seconds()),
			fieldMinterRetireGrace: int(cfg.MinterRetireGrace.Seconds()),
		},
	}, nil
}

func (b *backend) getProject() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.project
}
