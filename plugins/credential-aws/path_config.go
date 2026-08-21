package credentialaws

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
	defaultFlushIntervalSeconds    = 900   // 15m
	defaultReconcileCadenceSeconds = 21600 // 6h

	// defaultMinterExpiryWarnSeconds is the default near-expiry warn threshold (7d),
	// matching cloudconfig.MinMinterGap.
	defaultMinterExpiryWarnSeconds = 604800 // 7d

	// defaultMinterRetireGraceSeconds is the default grace (7d, = cloudconfig.MinMinterGap)
	// between marking a minter retired and the retired-sweep deleting its upstream
	// access key. The grace must exceed the worst-case interval before every raft
	// node has reloaded the set, so no node's in-memory snapshot still selects a
	// minter whose upstream access key has been deleted.
	defaultMinterRetireGraceSeconds = 604800 // 7d

	// reconcilerBootstrapDelay holds off the first reconcile pass after a
	// (re)start so leases issued just before restart aren't seen as orphans.
	reconcilerBootstrapDelay = 24 * time.Hour

	// maxDeletesPerPass caps how many orphaned tokens one reconcile pass deletes.
	maxDeletesPerPass = 10

	// healthCheckInterval is how often the health-check worker probes minters,
	// and the recovery state machine's re-probe cadence.
	healthCheckInterval = 5 * time.Minute

	// authFailThreshold is how long upstream auth must keep failing before the
	// recovery state machine declares a minter hard-failed.
	authFailThreshold = 30 * time.Second
)

func (b *backend) configPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: pathConfig,
			Fields: map[string]*framework.FieldSchema{
				"region": {
					Type:        framework.TypeString,
					Default:     defaultRegion,
					Description: "AWS region for STS calls",
				},
				"sts_endpoint": {
					Type:        framework.TypeString,
					Default:     "",
					Description: "Override STS endpoint (for testing)",
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
					Description: "Seconds after a minter is retired (by rotation) before its upstream access key is deleted by the retired-sweep",
				},
				fieldVerifyCapability: {
					Type:        framework.TypeBool,
					Default:     true,
					Description: "Prove a minter can mint (throwaway mint-and-delete probe) at minter-set write and role write; set false only where a probe mint is unacceptable",
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

	entry, err := logical.StorageEntryJSON(pathConfig, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.config = cfg
	if region, ok := d.GetOk("region"); ok {
		b.region = region.(string)
	}
	if endpoint, ok := d.GetOk("sts_endpoint"); ok {
		b.stsEndpoint = endpoint.(string)
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
			"region":               b.getRegion(),
			"flush_interval":       int(cfg.FlushInterval.Seconds()),
			"reconcile_cadence":    int(cfg.ReconcileCadence.Seconds()),
			"minter_expiry_warn":   int(cfg.MinterExpiryWarn.Seconds()),
			fieldMinterRetireGrace: int(cfg.MinterRetireGrace.Seconds()),
			fieldVerifyCapability:  cfg.CapabilityVerificationEnabled(),
		},
	}, nil
}

func (b *backend) getRegion() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.region != "" {
		return b.region
	}
	return defaultRegion
}
