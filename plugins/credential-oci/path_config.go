package credentialoci

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// Schema defaults are expressed in seconds (framework.TypeDurationSecond).
	defaultFlushIntervalSeconds         = 900   // 15m
	defaultReconcileCadenceSeconds      = 21600 // 6h
	defaultRotationCheckIntervalSeconds = 3600  // 1h

	// defaultMinterExpiryWarnSeconds is the default near-expiry warn threshold (7d),
	// matching cloudconfig.MinMinterGap.
	defaultMinterExpiryWarnSeconds = 604800 // 7d

	// defaultMinterRetireGraceSeconds is the default retirement grace (7d, =
	// cloudconfig.MinMinterGap). OCI uses phased slot rotation and never marks a
	// minter retired, so the sweep that would consume this never runs; the field
	// exists only to keep the config surface uniform across all clouds.
	defaultMinterRetireGraceSeconds = 604800 // 7d

	// reconcilerBootstrapDelay holds off the first reconcile pass after a
	// (re)start so leases issued just before restart aren't seen as orphans.
	reconcilerBootstrapDelay = 24 * time.Hour

	// maxDeletesPerPass caps how many orphaned tokens one reconcile pass deletes.
	maxDeletesPerPass = 10
)

func (b *backend) configPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				"region": {
					Type:        framework.TypeString,
					Default:     "us-ashburn-1",
					Description: "OCI region (e.g., us-ashburn-1)",
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
					Description: "Seconds after a minter is retired before its upstream credential is deleted by the retired-sweep (unused on OCI: phased rotation, no minter self-rotation)",
				},
				fieldVerifyCapability: {
					Type:        framework.TypeBool,
					Default:     true,
					Description: "Prove a minter can mint (throwaway mint-and-delete probe) at minter-set write and role write; set false only where a probe mint is unacceptable",
				},
				"rotation_check_interval": {
					Type:        framework.TypeDurationSecond,
					Default:     defaultRotationCheckIntervalSeconds,
					Description: "How often the rotation worker checks for slots needing rotation (seconds)",
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
	verifyCapability := d.Get(fieldVerifyCapability).(bool)

	cfg := &cloudconfig.PluginConfig{
		Cloud:             cloudName,
		FlushInterval:     flushInterval,
		ReconcileCadence:  reconcileCadence,
		BootstrapDelay:    reconcilerBootstrapDelay,
		MaxDeletesPerPass: maxDeletesPerPass,
		MinterExpiryWarn:  minterExpiryWarn,
		MinterRetireGrace: minterRetireGrace,

		VerifyMinterCapability: &verifyCapability,
	}

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Store rotation_check_interval separately
	rotationCheckInterval := time.Duration(d.Get("rotation_check_interval").(int)) * time.Second
	rEntry, err := logical.StorageEntryJSON("config/rotation_check_interval", rotationCheckInterval)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, rEntry); err != nil {
		return nil, err
	}

	// Store region
	region := d.Get("region").(string)
	regionEntry, err := logical.StorageEntryJSON("config/region", region)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, regionEntry); err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.config = cfg
	b.region = region
	b.mu.Unlock()

	go b.startWorkers(b.baseCtx, req.Storage)

	return nil, nil
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

	// Load region
	regionEntry, err := req.Storage.Get(ctx, "config/region")
	if err != nil {
		return nil, err
	}
	region := "us-ashburn-1"
	if regionEntry != nil {
		_ = json.Unmarshal(regionEntry.Value, &region)
	}

	// Load rotation check interval
	rEntry, err := req.Storage.Get(ctx, "config/rotation_check_interval")
	if err != nil {
		return nil, err
	}
	rotationCheckInterval := defaultRotationCheckIntervalSeconds
	if rEntry != nil {
		var d time.Duration
		if err := json.Unmarshal(rEntry.Value, &d); err == nil {
			rotationCheckInterval = int(d.Seconds())
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			fieldCloud:                cfg.Cloud,
			"region":                  region,
			"flush_interval":          int(cfg.FlushInterval.Seconds()),
			"reconcile_cadence":       int(cfg.ReconcileCadence.Seconds()),
			"minter_expiry_warn":      int(cfg.MinterExpiryWarn.Seconds()),
			fieldMinterRetireGrace:    int(cfg.MinterRetireGrace.Seconds()),
			fieldVerifyCapability:     cfg.CapabilityVerificationEnabled(),
			"rotation_check_interval": rotationCheckInterval,
		},
	}, nil
}
