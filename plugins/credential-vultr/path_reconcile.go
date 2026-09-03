package credentialvultr

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
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
				"confirmation_hold": {
					Type:        framework.TypeDurationSecond,
					Default:     int(time.Hour.Seconds()),
					Description: "Grace period (seconds) below which a recently-created orphan is not deleted. Operator requests are floored at the reconciler minimum (5m). Default: the worker hold (1h).",
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

	requestedHold := time.Duration(d.Get("confirmation_hold").(int)) * time.Second
	effectiveHold := requestedHold
	if effectiveHold < reconciler.MinConfirmationHold {
		b.Logger().Info("manual reconcile: raising requested confirmation_hold to the floor",
			"requested", requestedHold.String(), "floor", reconciler.MinConfirmationHold.String())
		effectiveHold = reconciler.MinConfirmationHold
	}

	client, err := b.anyHealthyMinter()
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "cannot reconcile: %v", err), nil
	}

	instanceID, err := b.ownerInstanceID(ctx, req.Storage)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "resolving the owner instance id", err), nil
	}
	lister := &vultrCloudLister{client: client, storage: req.Storage, instanceID: instanceID}
	registry := &leaseRegistry{storage: req.Storage}

	cfg := reconciler.Config{
		MaxDeletesPerPass: maxDeletesPerPass,
		ConfirmationHold:  effectiveHold,
		DryRun:            dryRun,
	}

	b.mu.RLock()
	if b.config != nil {
		cfg.MaxDeletesPerPass = b.config.MaxDeletesPerPass
	}
	b.mu.RUnlock()

	result, err := reconciler.New(cfg, lister, registry).WithLogger(cloudName, b.Logger()).Run(ctx, time.Now())
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.Classify(credenvelope.StatusNone, err), "reconcile failed: %v", err), nil
	}

	emitOrphansFound(len(result.OrphansFound))

	return &logical.Response{Data: reconciler.ResponseData{
		Mode:             mode,
		DryRun:           dryRun,
		Target:           reconciler.TargetUpstreamOrphans,
		Scanned:          result.Scanned,
		Found:            len(result.OrphansFound),
		Deleted:          result.Deleted,
		Remaining:        result.Scanned - result.Deleted,
		DeleteErrors:     len(result.Errors),
		Expired:          result.Expired,
		HitLimit:         result.HitLimit,
		ConfirmationHold: effectiveHold,
	}.Map()}, nil
}
