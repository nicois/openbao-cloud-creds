package credentialoci

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Storage keys for the cloud-specific settings kept outside
// cloudconfig.PluginConfig, and the default region used when none is stored.
// loadConfig rehydrates both, so a reloaded backend matches one that just had
// config written (KI-001).
const (
	configRegionKey        = "config/region"
	configRotationCheckKey = "config/rotation_check_interval"
	defaultRegion          = "us-ashburn-1"
)

const (
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

	// defaultCapabilityCacheTTLSeconds is how long a successful capability probe
	// stands in for a fresh one (1h). See capability.DefaultCacheTTL for the trade:
	// without a cache, every configuration write re-mints the whole probe fan-out.
	defaultCapabilityCacheTTLSeconds = 3600

	// reconcilerBootstrapDelay holds off the first reconcile pass after a
	// (re)start so leases issued just before restart aren't seen as orphans.
	reconcilerBootstrapDelay = 24 * time.Hour

	// maxDeletesPerPass caps how many orphaned tokens one reconcile pass deletes.
	maxDeletesPerPass = 10
)

func (b *backend) configPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: pathConfig,
			Fields: map[string]*framework.FieldSchema{
				"region": {
					Type:        framework.TypeString,
					Default:     defaultRegion,
					Description: "OCI region (e.g., us-ashburn-1)",
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
					Description: "Seconds after a minter is retired before its upstream credential is deleted by the retired-sweep (unused on OCI: phased rotation, no minter self-rotation)",
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
				fieldRotationCheckInterval: {
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
	reconcileCadence := time.Duration(d.Get(fieldReconcileCadence).(int)) * time.Second
	minterExpiryWarn := time.Duration(d.Get(fieldMinterExpiryWarn).(int)) * time.Second
	// Nothing on this cloud is ever retired: minter self-rotation is infeasible here
	// and minter-sets/<name>/rotate rejects, so the retired-sweep has no work and this
	// value would never be read. Accepting it silently is how an operator comes to
	// believe a setting is in force (A28). GetOk distinguishes "set to the default"
	// from "not set", so a uniform config template that omits it still works.
	if _, provided := d.GetOk(fieldMinterRetireGrace); provided {
		return credenvelope.ErrorResponse(credenvelope.ErrUnsupported,
			"%s has no effect on this cloud: its minters cannot self-rotate, so no minter is ever "+
				"retired and the retired-sweep has nothing to sweep", fieldMinterRetireGrace), nil
	}
	minterRetireGrace := time.Duration(d.Get(fieldMinterRetireGrace).(int)) * time.Second
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

	// Store rotation_check_interval separately
	rotationCheckInterval := time.Duration(d.Get(fieldRotationCheckInterval).(int)) * time.Second

	// Reject a non-positive interval here, where the operator finds out. A zero
	// interval used to panic the plugin process and crash-loop every mount in the
	// binary (A2); worker.Register now clamps too, but silently.
	if err := cloudconfig.ValidateIntervals(map[string]time.Duration{
		fieldReconcileCadence:      reconcileCadence,
		fieldMinterExpiryWarn:      minterExpiryWarn,
		fieldMinterRetireGrace:     minterRetireGrace,
		fieldRotationCheckInterval: rotationCheckInterval,
	}); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
	rEntry, err := logical.StorageEntryJSON(configRotationCheckKey, rotationCheckInterval)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "encoding an entry for storage", err), nil
	}
	if err := req.Storage.Put(ctx, rEntry); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "writing to storage", err), nil
	}

	// Store region
	region := d.Get("region").(string)
	regionEntry, err := logical.StorageEntryJSON(configRegionKey, region)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "encoding an entry for storage", err), nil
	}
	if err := req.Storage.Put(ctx, regionEntry); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "writing to storage", err), nil
	}

	b.mu.Lock()
	b.config = cfg
	b.region = region
	b.mu.Unlock()

	go b.startWorkers(b.baseCtx, req.Storage)

	return nil, nil
}

// loadConfig rehydrates operational config and the region from storage into the
// backend, so a reloaded backend (failover/restart) matches one that just had
// config written. Without it the signing client falls back to the default region
// after every failover, whatever the operator configured. KI-001.
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

	regionEntry, err := storage.Get(ctx, configRegionKey)
	if err != nil || regionEntry == nil {
		return err
	}
	var region string
	if err := json.Unmarshal(regionEntry.Value, &region); err != nil {
		return err
	}
	b.mu.Lock()
	if region != "" {
		b.region = region
	}
	b.mu.Unlock()
	return nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	// Load region
	regionEntry, err := req.Storage.Get(ctx, configRegionKey)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	region := defaultRegion
	if regionEntry != nil {
		_ = json.Unmarshal(regionEntry.Value, &region)
	}

	// Load rotation check interval
	rEntry, err := req.Storage.Get(ctx, configRotationCheckKey)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	rotationCheckInterval := defaultRotationCheckIntervalSeconds
	if rEntry != nil {
		var d time.Duration
		if err := json.Unmarshal(rEntry.Value, &d); err == nil {
			rotationCheckInterval = int(d.Seconds())
		}
	}

	return &logical.Response{
		Data: map[string]any{
			fieldCloud:                 cfg.Cloud,
			"region":                   region,
			fieldReconcileCadence:      int(cfg.ReconcileCadence.Seconds()),
			fieldMinterExpiryWarn:      int(cfg.MinterExpiryWarn.Seconds()),
			fieldMinterRetireGrace:     int(cfg.MinterRetireGrace.Seconds()),
			fieldVerifyCapability:      cfg.CapabilityVerificationEnabled(),
			fieldCapabilityCacheTTL:    int(cfg.CapabilityCacheDuration().Seconds()),
			fieldRotationCheckInterval: rotationCheckInterval,
		},
	}, nil
}
