package credentialazure

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) metricsPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "metrics/entity/" + framework.MatchAllRegex("entity_id"),
			Fields: map[string]*framework.FieldSchema{
				"entity_id": {
					Type:        framework.TypeString,
					Description: "Cloud entity ID to query",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathMetricsEntity},
			},
		},
		{
			Pattern: "metrics/stale$",
			Fields: map[string]*framework.FieldSchema{
				"older_than": {
					Type:        framework.TypeDurationSecond,
					Default:     604800,
					Description: "Return entities not accessed within this duration",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathMetricsStale},
			},
		},
	}
}

func (b *backend) pathMetricsEntity(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entityID := d.Get("entity_id").(string)

	b.mu.RLock()
	tracker := b.accessTracker
	b.mu.RUnlock()

	if tracker == nil {
		return logical.ErrorResponse("metrics not initialized"), nil
	}

	now := time.Now()
	merged, err := tracker.MergeEntity(ctx, entityID, now)
	if err != nil {
		return logical.ErrorResponse("metrics query failed: %v", err), nil
	}

	if merged.AccessCount == 0 {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"last_access_at":    merged.LastAccessAt.UTC().Format(time.RFC3339),
			"access_count":      merged.AccessCount,
			"staleness_seconds": merged.StalenessSeconds,
			"source":            merged.Source,
		},
	}, nil
}

func (b *backend) pathMetricsStale(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	tracker := b.accessTracker
	b.mu.RUnlock()

	if tracker == nil {
		return logical.ErrorResponse("metrics not initialized"), nil
	}

	olderThanSec := d.Get("older_than").(int)
	olderThan := time.Duration(olderThanSec) * time.Second
	now := time.Now()

	stale, err := tracker.ListStaleEntities(ctx, olderThan, now)
	if err != nil {
		return logical.ErrorResponse("stale query failed: %v", err), nil
	}

	return logical.ListResponse(stale), nil
}
