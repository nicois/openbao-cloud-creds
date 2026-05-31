package reconciler

import (
	"context"
	"time"
)

type UpstreamEntity struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

type CloudLister interface {
	ListTaggedEntities(ctx context.Context) ([]UpstreamEntity, error)
	DeleteEntity(ctx context.Context, id string) error
}

type Registry interface {
	IsKnown(id string) bool
}

type Config struct {
	MaxDeletesPerPass int
	ConfirmationHold  time.Duration
	DryRun            bool
}

type Result struct {
	OrphansFound []string
	Deleted      int
	HitLimit     bool
}

type reconciler struct {
	config   Config
	cloud    CloudLister
	registry Registry
}

func New(cfg Config, cloud CloudLister, registry Registry) *reconciler {
	return &reconciler{
		config:   cfg,
		cloud:    cloud,
		registry: registry,
	}
}

func (r *reconciler) Run(ctx context.Context, now time.Time) (*Result, error) {
	entities, err := r.cloud.ListTaggedEntities(ctx)
	if err != nil {
		return nil, err
	}

	result := &Result{}

	for _, entity := range entities {
		if r.registry.IsKnown(entity.ID) {
			continue
		}

		if r.config.ConfirmationHold > 0 && !entity.CreatedAt.IsZero() {
			if now.Sub(entity.CreatedAt) < r.config.ConfirmationHold {
				continue
			}
		}

		result.OrphansFound = append(result.OrphansFound, entity.ID)

		if r.config.DryRun {
			continue
		}

		if result.Deleted >= r.config.MaxDeletesPerPass {
			result.HitLimit = true
			break
		}

		if err := r.cloud.DeleteEntity(ctx, entity.ID); err != nil {
			return result, err
		}
		result.Deleted++
	}

	return result, nil
}
