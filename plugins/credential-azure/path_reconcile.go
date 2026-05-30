package credentialazure

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

	// Get all roles to know which app_object_ids to scan
	appObjectIDs, err := b.getAllAppObjectIDs(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("cannot list roles: %v", err), nil
	}

	lister := &azureCloudLister{client: client, appObjectIDs: appObjectIDs}
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

func (b *backend) getAllAppObjectIDs(ctx context.Context, storage logical.Storage) ([]string, error) {
	entries, err := storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var appObjectIDs []string
	for _, name := range entries {
		entry, err := storage.Get(ctx, "roles/"+name)
		if err != nil || entry == nil {
			continue
		}
		var role azureRole
		if err := entry.DecodeJSON(&role); err != nil {
			continue
		}
		if role.AppObjectID != "" && !seen[role.AppObjectID] {
			seen[role.AppObjectID] = true
			appObjectIDs = append(appObjectIDs, role.AppObjectID)
		}
	}
	return appObjectIDs, nil
}
