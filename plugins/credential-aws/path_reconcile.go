package credentialaws

import (
	"context"
	"time"

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
	dryRun := mode == "dry_run"

	entries, err := req.Storage.List(ctx, "active-tokens/")
	if err != nil {
		return logical.ErrorResponse("reconcile failed: %v", err), nil
	}

	now := time.Now()
	var expired []string
	for _, key := range entries {
		entry, err := req.Storage.Get(ctx, "active-tokens/"+key)
		if err != nil || entry == nil {
			continue
		}

		var data map[string]interface{}
		if err := entry.DecodeJSON(&data); err != nil {
			continue
		}

		if expiresStr, ok := data["expires_at"].(string); ok {
			expiresAt, err := time.Parse(time.RFC3339, expiresStr)
			if err == nil && now.After(expiresAt) {
				expired = append(expired, key)
			}
		}
	}

	deleted := 0
	if !dryRun {
		for _, key := range expired {
			if err := req.Storage.Delete(ctx, "active-tokens/"+key); err != nil {
				b.Logger().Warn("reconcile: failed to delete expired entry", "key", key, "error", err)
				continue
			}
			deleted++
		}
	}

	emitOrphansFound(len(expired))

	return &logical.Response{
		Data: map[string]interface{}{
			"mode":             mode,
			"dry_run":          dryRun,
			"expired_found":    len(expired),
			"deleted":          deleted,
			"active_remaining": len(entries) - deleted,
		},
	}, nil
}
