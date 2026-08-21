package credentialovh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
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

	// defaultMinterRetireGraceSeconds is the default retirement grace (7d, =
	// cloudconfig.MinMinterGap). OVH never marks a minter retired (no
	// self-rotation), so the sweep that would consume this never runs; the field
	// exists only to keep the config surface uniform across all clouds.
	defaultMinterRetireGraceSeconds = 604800 // 7d

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
				fieldFlushInterval: {
					Type:        framework.TypeDurationSecond,
					Default:     defaultFlushIntervalSeconds,
					Description: "Metrics flush interval in seconds",
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
					Description: "Seconds after a minter is retired before its upstream credential is deleted by the retired-sweep (unused on OVH: no self-rotation)",
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

	// Refuse an endpoint that could carry the minter credential off-box. TLS for
	// anything not loopback (A3); the fakes and e2e use http on 127.0.0.1.
	if err := cloudconfig.ValidateEndpoint("token_endpoint", d.Get("token_endpoint").(string)); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
	region := d.Get(fieldRegion).(string)
	if _, valid := regionEndpoints[region]; !valid {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "invalid region %q: must be eu, ca, or us", region), nil
	}

	flushInterval := time.Duration(d.Get(fieldFlushInterval).(int)) * time.Second
	reconcileCadence := time.Duration(d.Get(fieldReconcileCadence).(int)) * time.Second
	minterExpiryWarn := time.Duration(d.Get(fieldMinterExpiryWarn).(int)) * time.Second
	minterRetireGrace := time.Duration(d.Get(fieldMinterRetireGrace).(int)) * time.Second

	// Reject a non-positive interval here, where the operator finds out. A zero
	// flush_interval used to panic the plugin process and crash-loop every mount
	// in the binary (A2); worker.Register now clamps too, but silently.
	if err := cloudconfig.ValidateIntervals(map[string]time.Duration{
		fieldFlushInterval:     flushInterval,
		fieldReconcileCadence:  reconcileCadence,
		fieldMinterExpiryWarn:  minterExpiryWarn,
		fieldMinterRetireGrace: minterRetireGrace,
	}); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
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
			fieldCloud:             cfg.Cloud,
			fieldRegion:            b.getRegion(),
			fieldFlushInterval:     int(cfg.FlushInterval.Seconds()),
			fieldReconcileCadence:  int(cfg.ReconcileCadence.Seconds()),
			fieldMinterExpiryWarn:  int(cfg.MinterExpiryWarn.Seconds()),
			fieldMinterRetireGrace: int(cfg.MinterRetireGrace.Seconds()),
			fieldVerifyCapability:  cfg.CapabilityVerificationEnabled(),
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
