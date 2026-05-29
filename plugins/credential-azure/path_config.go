package credentialazure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) configPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				"minters": {
					Type:        framework.TypeSlice,
					Description: "List of minter credentials. Each has id, token (client_id:client_secret), never_expires/expires_at",
				},
				"tenant_id": {
					Type:        framework.TypeString,
					Description: "Azure AD tenant ID",
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
	mintersRaw := d.Get("minters")
	if mintersRaw == nil {
		return logical.ErrorResponse("minters is required"), nil
	}

	mintersSlice, ok := mintersRaw.([]interface{})
	if !ok {
		return logical.ErrorResponse("minters must be an array"), nil
	}

	tenantID, ok := d.GetOk("tenant_id")
	if !ok || tenantID.(string) == "" {
		return logical.ErrorResponse("tenant_id is required"), nil
	}

	var minters []cloudconfig.Minter
	for _, m := range mintersSlice {
		mMap, ok := m.(map[string]interface{})
		if !ok {
			return logical.ErrorResponse("each minter must be an object"), nil
		}
		token := fmt.Sprintf("%v", mMap["token"])
		// Validate token format: client_id:client_secret
		if !strings.Contains(token, ":") {
			return logical.ErrorResponse("minter token must be in format client_id:client_secret"), nil
		}
		minter := cloudconfig.Minter{
			ID:        fmt.Sprintf("%v", mMap["id"]),
			Token:     token,
			CreatedAt: time.Now(),
		}
		if ne, ok := mMap["never_expires"].(bool); ok && ne {
			minter.NeverExpires = true
		}
		if exp, ok := mMap["expires_at"].(string); ok {
			t, err := time.Parse(time.RFC3339, exp)
			if err != nil {
				return logical.ErrorResponse("invalid expires_at for minter %s: %v", minter.ID, err), nil
			}
			minter.ExpiresAt = t
		}
		minters = append(minters, minter)
	}

	if err := cloudconfig.ValidateMinterSet(minters); err != nil {
		return logical.ErrorResponse("invalid minter set: %v", err), nil
	}

	flushInterval := time.Duration(d.Get("flush_interval").(int)) * time.Second
	reconcileCadence := time.Duration(d.Get("reconcile_cadence").(int)) * time.Second

	cfg := &cloudconfig.PluginConfig{
		Cloud:             "azure",
		Minters:           minters,
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

	// Store tenant_id and endpoints separately for easy retrieval
	configMeta := map[string]string{
		"tenant_id":      tenantID.(string),
		"graph_endpoint": d.Get("graph_endpoint").(string),
		"login_endpoint": d.Get("login_endpoint").(string),
	}
	metaEntry, err := logical.StorageEntryJSON("config_meta", configMeta)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, metaEntry); err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.config = cfg
	b.tenantID = tenantID.(string)
	b.graphEndpoint = d.Get("graph_endpoint").(string)
	b.loginEndpoint = d.Get("login_endpoint").(string)
	b.minters = make(map[string]*minterState)
	for _, m := range minters {
		b.minters[m.ID] = &minterState{
			minter: m,
			sm: recovery.NewStateMachine(recovery.Config{
				AuthFailThreshold:   30 * time.Second,
				HealthCheckInterval: 5 * time.Minute,
			}),
		}
	}
	b.mu.Unlock()

	go b.startWorkers(context.Background(), req.Storage)

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

	return &logical.Response{
		Data: map[string]interface{}{
			"cloud":             cfg.Cloud,
			"minter_count":      len(cfg.Minters),
			"flush_interval":    int(cfg.FlushInterval.Seconds()),
			"reconcile_cadence": int(cfg.ReconcileCadence.Seconds()),
		},
	}, nil
}
