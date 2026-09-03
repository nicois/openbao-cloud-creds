package credentialaws

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/localexpiry"
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

	return &logical.Response{Data: reconciler.ResponseData{
		Mode:      mode,
		DryRun:    dryRun,
		Target:    reconciler.TargetLocalExpired,
		Scanned:   res.Scanned,
		Found:     len(res.Expired),
		Deleted:   res.Deleted,
		Remaining: res.Scanned - res.Deleted,
		// Nothing upstream is touched, so there is no upstream delete to fail and no
		// per-pass delete cap to hit. Both are reported as zero/false because the pass
		// genuinely has none, not because the field does not apply.
		DeleteErrors: 0,
		HitLimit:     false,
		// Every entry this pass reclaims is one whose credential has already expired — that is the
		// only reason it is reclaimable — so the expired count is the whole of it. Reported rather
		// than left at zero so the field means the same thing on every cloud.
		Expired: res.Deleted,
		// No confirmation hold: these entries are pruned because the credential they
		// track has already EXPIRED, so there is no live credential a hold would protect.
		ConfirmationHold: 0,
	}.Map()}, nil
}
