package credentialoci

import (
	"context"
	"encoding/json"
	"fmt"
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
					Description: "List of minter credentials. Each entry: {id, token (tenancy_ocid:user_ocid:fingerprint:private_key_pem), never_expires/expires_at}",
				},
				"region": {
					Type:        framework.TypeString,
					Default:     "us-ashburn-1",
					Description: "OCI region (e.g., us-ashburn-1)",
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
				"rotation_check_interval": {
					Type:        framework.TypeDurationSecond,
					Default:     3600,
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
	mintersRaw := d.Get("minters")
	if mintersRaw == nil {
		return logical.ErrorResponse("minters is required"), nil
	}

	mintersSlice, ok := mintersRaw.([]interface{})
	if !ok {
		return logical.ErrorResponse("minters must be an array"), nil
	}

	var minters []cloudconfig.Minter
	for _, m := range mintersSlice {
		mMap, ok := m.(map[string]interface{})
		if !ok {
			return logical.ErrorResponse("each minter must be an object"), nil
		}
		minter := cloudconfig.Minter{
			ID:        fmt.Sprintf("%v", mMap["id"]),
			Token:     fmt.Sprintf("%v", mMap["token"]),
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
		Cloud:             "oci",
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
	rotationCheckInterval := 3600
	if rEntry != nil {
		var d time.Duration
		if err := json.Unmarshal(rEntry.Value, &d); err == nil {
			rotationCheckInterval = int(d.Seconds())
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"cloud":                   cfg.Cloud,
			"minter_count":            len(cfg.Minters),
			"region":                  region,
			"flush_interval":          int(cfg.FlushInterval.Seconds()),
			"reconcile_cadence":       int(cfg.ReconcileCadence.Seconds()),
			"rotation_check_interval": rotationCheckInterval,
		},
	}, nil
}
