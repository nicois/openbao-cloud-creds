package credentialvultr

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) reconcilePaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "reconcile",
			Fields: map[string]*framework.FieldSchema{
				"mode": {
					Type:        framework.TypeString,
					Default:     "normal",
					Description: "Run mode: normal or dry_run",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathReconcile},
			},
		},
	}
}

func (b *backend) pathReconcile(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	mode := d.Get("mode").(string)
	dryRun := mode == "dry_run"

	client, err := b.anyHealthyMinter()
	if err != nil {
		return logical.ErrorResponse("cannot reconcile: %v", err), nil
	}

	lister := &vultrCloudLister{client: client}
	registry := &leaseRegistry{storage: req.Storage, ctx: ctx}

	cfg := reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  0,
		DryRun:            dryRun,
	}

	b.mu.RLock()
	if b.config != nil {
		cfg.MaxDeletesPerPass = b.config.MaxDeletesPerPass
	}
	b.mu.RUnlock()

	result, err := reconciler.New(cfg, lister, registry).Run(ctx, time.Now())
	if err != nil {
		return logical.ErrorResponse("reconcile failed: %v", err), nil
	}

	emitOrphansFound(len(result.OrphansFound))

	return &logical.Response{
		Data: map[string]interface{}{
			"mode":          mode,
			"dry_run":       dryRun,
			"orphans_found": len(result.OrphansFound),
			"deleted":       result.Deleted,
			"hit_limit":     result.HitLimit,
		},
	}, nil
}
