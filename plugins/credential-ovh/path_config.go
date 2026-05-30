package credentialovh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
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
				"region": {
					Type:        framework.TypeString,
					Default:     "eu",
					Description: "OVH region: eu, ca, or us (determines token endpoint URL)",
				},
				"token_endpoint": {
					Type:        framework.TypeString,
					Default:     "",
					Description: "Override token endpoint URL (for testing)",
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
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			},
		},
	}
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	region := d.Get("region").(string)
	if _, valid := regionEndpoints[region]; !valid {
		return logical.ErrorResponse("invalid region %q: must be eu, ca, or us", region), nil
	}

	flushInterval := time.Duration(d.Get("flush_interval").(int)) * time.Second
	reconcileCadence := time.Duration(d.Get("reconcile_cadence").(int)) * time.Second

	cfg := &cloudconfig.PluginConfig{
		Cloud:             "ovh",
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

	// Determine token endpoint
	tokenEndpoint := d.Get("token_endpoint").(string)
	if tokenEndpoint == "" {
		tokenEndpoint = regionEndpoints[region]
	}

	b.mu.Lock()
	b.config = cfg
	b.region = region
	b.tokenEndpoint = tokenEndpoint
	b.mu.Unlock()

	go b.startWorkers(context.Background(), req.Storage)

	return nil, nil
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
			"cloud":             cfg.Cloud,
			"region":            b.getRegion(),
			"flush_interval":    int(cfg.FlushInterval.Seconds()),
			"reconcile_cadence": int(cfg.ReconcileCadence.Seconds()),
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
