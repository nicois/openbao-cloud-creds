// Package metricspath provides the shared per-node access-metrics query
// endpoints (metrics/entity, metrics/stale) used by every credential plugin.
// Backed by a metrics.AccessTracker supplied via an accessor closure so each
// plugin retains its own lock discipline.
package metricspath

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
)

// Paths returns the metrics/entity and metrics/stale framework paths backed by
// the AccessTracker the accessor returns (the accessor handles any locking).
// staleDefaultSeconds is the schema default for the stale "older_than" window.
func Paths(accessor func() *metrics.AccessTracker, staleDefaultSeconds int) []*framework.Path {
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
				logical.ReadOperation: &framework.PathOperation{Callback: entityHandler(accessor)},
			},
		},
		{
			Pattern: "metrics/stale$",
			Fields: map[string]*framework.FieldSchema{
				"older_than": {
					Type:        framework.TypeDurationSecond,
					Default:     staleDefaultSeconds,
					Description: "Return entities not accessed within this duration",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: staleHandler(accessor)},
			},
		},
	}
}

func entityHandler(accessor func() *metrics.AccessTracker) framework.OperationFunc {
	return func(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		tracker := accessor()
		if tracker == nil {
			return logical.ErrorResponse("metrics not initialized"), nil
		}
		entityID := d.Get("entity_id").(string)
		merged, err := tracker.MergeEntity(ctx, entityID, time.Now())
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
}

func staleHandler(accessor func() *metrics.AccessTracker) framework.OperationFunc {
	return func(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		tracker := accessor()
		if tracker == nil {
			return logical.ErrorResponse("metrics not initialized"), nil
		}
		olderThan := time.Duration(d.Get("older_than").(int)) * time.Second
		stale, err := tracker.ListStaleEntities(ctx, olderThan, time.Now())
		if err != nil {
			return logical.ErrorResponse("stale query failed: %v", err), nil
		}
		return logical.ListResponse(stale), nil
	}
}
