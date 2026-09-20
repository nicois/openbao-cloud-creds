package credentialaws

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
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

	// defaultCapabilityCacheTTLSeconds is how long a successful capability probe
	// stands in for a fresh one (1h). See capability.DefaultCacheTTL for the trade:
	// without a cache, every configuration write re-mints the whole probe fan-out.
	defaultCapabilityCacheTTLSeconds = 3600

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
				fieldRegion: {
					Type:        framework.TypeString,
					Default:     defaultRegion,
					Description: "AWS region for STS calls",
				},
				fieldSTSEndpoint: {
					Type:        framework.TypeString,
					Default:     "",
					Description: "Override STS endpoint (for testing)",
				},
				fieldReconcileCadence: {
					Type:        framework.TypeDurationSecond,
					Default:     defaultReconcileCadenceSeconds,
					Description: "Reconciliation cadence in seconds",
				},
				fieldMinterExpiryWarn: {
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
				fieldCapabilityCacheTTL: {
					Type:        framework.TypeDurationSecond,
					Default:     defaultCapabilityCacheTTLSeconds,
					Description: "How long a successful capability probe stands in for a fresh one, so a repeated configuration write does not re-mint the whole (minters x roles) fan-out; 0 re-probes every write",
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

	// Refuse an endpoint that could carry the minter credential off-box. TLS for
	// anything not loopback (A3); the fakes and e2e use http on 127.0.0.1.
	if err := cloudconfig.ValidateEndpoint(fieldSTSEndpoint, d.Get(fieldSTSEndpoint).(string)); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
	reconcileCadence := time.Duration(d.Get(fieldReconcileCadence).(int)) * time.Second
	minterExpiryWarn := time.Duration(d.Get(fieldMinterExpiryWarn).(int)) * time.Second
	minterRetireGrace := time.Duration(d.Get(fieldMinterRetireGrace).(int)) * time.Second

	// Reject a non-positive interval here, where the operator finds out. A zero
	// interval used to panic the plugin process and crash-loop every mount in the
	// binary (A2); worker.Register now clamps too, but silently.
	if err := cloudconfig.ValidateIntervals(map[string]time.Duration{
		fieldReconcileCadence:  reconcileCadence,
		fieldMinterExpiryWarn:  minterExpiryWarn,
		fieldMinterRetireGrace: minterRetireGrace,
	}); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
	verifyCapability := d.Get(fieldVerifyCapability).(bool)
	capabilityCacheTTL := time.Duration(d.Get(fieldCapabilityCacheTTL).(int)) * time.Second

	cfg := &cloudconfig.PluginConfig{
		Schema:            cloudconfig.SchemaVersion,
		Cloud:             cloudName,
		ReconcileCadence:  reconcileCadence,
		BootstrapDelay:    reconcilerBootstrapDelay,
		MaxDeletesPerPass: maxDeletesPerPass,
		MinterExpiryWarn:  minterExpiryWarn,
		MinterRetireGrace: minterRetireGrace,

		VerifyMinterCapability: &verifyCapability,
		CapabilityCacheTTL:     &capabilityCacheTTL,
	}

	entry, err := logical.StorageEntryJSON(pathConfig, cfg)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "encoding an entry for storage", err), nil
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "writing to storage", err), nil
	}

	region := d.Get(fieldRegion).(string)
	stsEndpoint := d.Get(fieldSTSEndpoint).(string)

	// Persist the cloud-specific settings separately: cloudconfig.PluginConfig
	// has no field for them, and without this a reloaded backend (failover /
	// plugin reload) silently reverts to the default region and loses the STS
	// endpoint override. KI-001.
	metaEntry, err := logical.StorageEntryJSON(configMetaKey, map[string]string{
		fieldRegion:      region,
		fieldSTSEndpoint: stsEndpoint,
	})
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "encoding an entry for storage", err), nil
	}
	if err := req.Storage.Put(ctx, metaEntry); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "writing to storage", err), nil
	}

	b.mu.Lock()
	b.config = cfg
	if region != "" {
		b.region = region
	}
	if stsEndpoint != "" {
		b.stsEndpoint = stsEndpoint
	}
	b.mu.Unlock()

	go b.startWorkers(b.baseCtx, req.Storage)

	return nil, nil
}

// loadConfig rehydrates operational and cloud-specific config from storage into
// the backend, so a reloaded backend (failover/restart) matches one that just had
// config written. KI-001.
func (b *backend) loadConfig(ctx context.Context, storage logical.Storage) error {
	entry, err := storage.Get(ctx, pathConfig)
	if err != nil || entry == nil {
		return err
	}
	var cfg cloudconfig.PluginConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return err
	}
	// Refuse an entry a NEWER binary wrote: every mutation here rewrites the whole
	// struct, so loading it would erase the fields this binary does not know (A30).
	if err := cfg.CheckSchema("the stored config"); err != nil {
		return err
	}
	b.mu.Lock()
	b.config = &cfg
	b.mu.Unlock()

	metaEntry, err := storage.Get(ctx, configMetaKey)
	if err != nil || metaEntry == nil {
		return err
	}
	var meta map[string]string
	if err := json.Unmarshal(metaEntry.Value, &meta); err != nil {
		return err
	}
	b.mu.Lock()
	if meta[fieldRegion] != "" {
		b.region = meta[fieldRegion]
	}
	if meta[fieldSTSEndpoint] != "" {
		b.stsEndpoint = meta[fieldSTSEndpoint]
	}
	b.mu.Unlock()
	return nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, pathConfig)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	if entry == nil {
		return nil, nil
	}

	var cfg cloudconfig.PluginConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "parsing a stored entry", err), nil
	}

	return &logical.Response{
		Data: map[string]any{
			fieldCloud:              cfg.Cloud,
			fieldRegion:             b.getRegion(),
			fieldReconcileCadence:   int(cfg.ReconcileCadence.Seconds()),
			fieldMinterExpiryWarn:   int(cfg.MinterExpiryWarn.Seconds()),
			fieldMinterRetireGrace:  int(cfg.MinterRetireGrace.Seconds()),
			fieldVerifyCapability:   cfg.CapabilityVerificationEnabled(),
			fieldCapabilityCacheTTL: int(cfg.CapabilityCacheDuration().Seconds()),
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
