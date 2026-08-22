package credentialazure

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
	// credential. The grace must exceed the worst-case interval before every raft
	// node reloads the set, so no node's in-memory snapshot still selects a minter
	// whose upstream secret has been deleted.
	defaultMinterRetireGraceSeconds = 604800 // 7d

	// reconcilerBootstrapDelay holds off the first reconcile pass after a
	// (re)start so leases issued just before restart aren't seen as orphans.
	reconcilerBootstrapDelay = 24 * time.Hour

	// maxDeletesPerPass caps how many orphaned credentials one reconcile pass deletes.
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
				fieldTenantID: {
					Type:        framework.TypeString,
					Description: "Azure AD tenant ID",
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
					Description: "Seconds after a minter is retired (by rotation) before its upstream credential is deleted by the retired-sweep",
				},
				fieldVerifyCapability: {
					Type:        framework.TypeBool,
					Default:     true,
					Description: "Prove a minter can mint (throwaway mint-and-delete probe) at minter-set write and role write; set false only where a probe mint is unacceptable",
				},
				"graph_endpoint": {
					Type:        framework.TypeString,
					Default:     "https://graph.microsoft.com",
					Description: "Microsoft Graph API endpoint (for testing)",
				},
				"login_endpoint": {
					Type:        framework.TypeString,
					Default:     "https://login.microsoftonline.com",
					Description: "Azure AD login endpoint (for testing)",
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
	if err := cloudconfig.ValidateEndpoint("graph_endpoint", d.Get("graph_endpoint").(string)); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
	if err := cloudconfig.ValidateEndpoint("login_endpoint", d.Get("login_endpoint").(string)); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}
	tenantID, ok := d.GetOk(fieldTenantID)
	if !ok || tenantID.(string) == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "tenant_id is required"), nil
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

	cfg := &cloudconfig.PluginConfig{
		Cloud:             cloudName,
		ReconcileCadence:  reconcileCadence,
		BootstrapDelay:    reconcilerBootstrapDelay,
		MaxDeletesPerPass: maxDeletesPerPass,
		MinterExpiryWarn:  minterExpiryWarn,
		MinterRetireGrace: minterRetireGrace,

		VerifyMinterCapability: &verifyCapability,
	}

	entry, err := logical.StorageEntryJSON(pathConfig, cfg)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "encoding an entry for storage", err), nil
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "writing to storage", err), nil
	}

	// Store tenant_id and endpoints separately for easy retrieval
	configMeta := map[string]string{
		fieldTenantID:    tenantID.(string),
		"graph_endpoint": d.Get("graph_endpoint").(string),
		"login_endpoint": d.Get("login_endpoint").(string),
	}
	metaEntry, err := logical.StorageEntryJSON("config_meta", configMeta)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "encoding an entry for storage", err), nil
	}
	if err := req.Storage.Put(ctx, metaEntry); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "writing to storage", err), nil
	}

	b.mu.Lock()
	b.config = cfg
	b.tenantID = tenantID.(string)
	b.graphEndpoint = d.Get("graph_endpoint").(string)
	b.loginEndpoint = d.Get("login_endpoint").(string)
	b.mu.Unlock()

	go b.startWorkers(b.baseCtx, req.Storage)

	return nil, nil
}

// loadConfig rehydrates operational config from storage into the backend, so a
// reloaded backend (failover/restart) matches one that just had config written. KI-001.
func (b *backend) loadConfig(ctx context.Context, storage logical.Storage) error {
	entry, err := storage.Get(ctx, pathConfig)
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
	if meta[fieldTenantID] != "" {
		b.tenantID = meta[fieldTenantID]
	}
	if meta["graph_endpoint"] != "" {
		b.graphEndpoint = meta["graph_endpoint"]
	}
	if meta["login_endpoint"] != "" {
		b.loginEndpoint = meta["login_endpoint"]
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

	return &logical.Response{
		Data: map[string]interface{}{
			fieldCloud:             cfg.Cloud,
			fieldReconcileCadence:  int(cfg.ReconcileCadence.Seconds()),
			fieldMinterExpiryWarn:  int(cfg.MinterExpiryWarn.Seconds()),
			fieldMinterRetireGrace: int(cfg.MinterRetireGrace.Seconds()),
			fieldVerifyCapability:  cfg.CapabilityVerificationEnabled(),
		},
	}, nil
}
