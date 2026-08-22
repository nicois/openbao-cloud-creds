package credentialaws

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/localexpiry"
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

// pathReconcile for AWS cleans up stale tracking entries. Unlike DO/Exoscale,
// there are no upstream entities to delete — STS credentials auto-expire.
func (b *backend) pathReconcile(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	mode := d.Get("mode").(string)
	// mode used to be compared for equality with no validation, so "dryrun",
	// "dry-run" and "DRY_RUN" all ran a LIVE destructive pass and the response then
	// reported dry_run=false after the fact (A29 in docs/audit-2026-08-22.md). An
	// unrecognised mode on a destructive endpoint must be refused, not guessed.
	switch mode {
	case modeNormal, modeDryRun:
	default:
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"mode must be %q or %q, got %q", modeNormal, modeDryRun, mode), nil
	}
	dryRun := mode == modeDryRun

	res, err := localexpiry.PruneExpired(ctx, req.Storage, localexpiry.Options{
		Prefix: "active-tokens/",
		Now:    time.Now(),
		DryRun: dryRun,
		Logger: b.Logger(),
	})
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.Classify(credenvelope.StatusNone, err), "reconcile failed: %v", err), nil
	}

	emitOrphansFound(len(res.Expired))

	return &logical.Response{
		Data: map[string]interface{}{
			"mode":             mode,
			"dry_run":          dryRun,
			"expired_found":    len(res.Expired),
			"deleted":          res.Deleted,
			"active_remaining": res.Scanned - res.Deleted,
		},
	}, nil
}
