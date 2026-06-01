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

// ParseCreatedAt converts an RFC3339 creation timestamp from a cloud list
// response into a time.Time. An empty or unparseable value yields the zero
// time, which the fail-closed Run guard treats as "age unconfirmable" (skip).
// Listers use this so a malformed upstream timestamp can never cause a live
// credential to be deleted.
func ParseCreatedAt(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts
	}
	return time.Time{}
}

type CloudLister interface {
	ListTaggedEntities(ctx context.Context) ([]UpstreamEntity, error)
	DeleteEntity(ctx context.Context, id string) error
}

// Registry enumerates the lease IDs this node knows about. Run calls KnownIDs
// once per pass and membership-checks in memory (O(N), not a List-per-entity
// O(N^2) scan). Returning an error aborts the pass WITHOUT deleting anything:
// an incomplete known-set could misclassify a live credential as an orphan, so
// the safe response to "cannot enumerate known leases" is to delete nothing.
type Registry interface {
	KnownIDs(ctx context.Context) (map[string]struct{}, error)
}

// MinConfirmationHold is the floor for an operator-requested confirmation hold
// on the manual reconcile path. A hold shorter than this (including zero) would
// re-expose the create-then-track window that the fail-closed guard protects
// against, so operator-facing callers clamp their requested hold up to this
// value. NOTE: this floor is applied by callers (the manual /reconcile
// handlers), NOT inside Run — Run's ConfirmationHold==0 still means "guard
// disabled" for internal/worker use and existing tests.
const MinConfirmationHold = 5 * time.Minute

type Config struct {
	MaxDeletesPerPass int
	ConfirmationHold  time.Duration
	DryRun            bool
}

type Result struct {
	OrphansFound []string
	Deleted      int
	HitLimit     bool
	// Errors holds the IDs of orphans whose delete failed. A per-entity delete
	// failure no longer aborts the whole pass (defense in depth alongside the
	// lister-level 404-is-success handling); the failing ID is recorded here and
	// the pass continues to the next entity.
	Errors []string
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

	known, kerr := r.registry.KnownIDs(ctx)
	if kerr != nil {
		// Fail closed: without a complete known-set we cannot safely decide
		// what is an orphan, so abort the pass rather than risk deleting a
		// live credential.
		return nil, kerr
	}

	for _, entity := range entities {
		if _, ok := known[entity.ID]; ok {
			continue
		}

		// Fail closed: when a confirmation hold is configured, only delete an
		// orphan whose age we can confirm is older than the hold. If CreatedAt
		// is unknown (zero), we cannot confirm the entity isn't a just-issued
		// credential still in its create-then-track window, so we skip it this
		// pass rather than risk deleting a live credential.
		if r.config.ConfirmationHold > 0 {
			if entity.CreatedAt.IsZero() || now.Sub(entity.CreatedAt) < r.config.ConfirmationHold {
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
			result.Errors = append(result.Errors, entity.ID)
			continue
		}
		result.Deleted++
	}

	return result, nil
}
