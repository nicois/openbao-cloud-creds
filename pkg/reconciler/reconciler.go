package reconciler

import (
	"context"
	"time"

	"github.com/hashicorp/go-hclog"
)

type UpstreamEntity struct {
	ID        string
	Name      string
	CreatedAt time.Time
	// ExpiresAt is when the cloud will discard this credential by itself. OPTIONAL: zero means
	// "unknown", which is the honest answer for the clouds whose listings do not report it and for
	// the credentials that genuinely never expire.
	//
	// It exists to order the work rather than to change what is deleted. An orphan that has already
	// expired is inert — it cannot be used — while a live one is an exposure, and the per-pass delete
	// budget should be spent on the second first. Without this field the reconciler processed the
	// listing in creation order, which puts the EXPIRED ones first (they are the oldest), so on a
	// cloud that lists expired credentials the budget went to the harmless ones.
	ExpiresAt time.Time
}

// inert reports whether this entity has already expired, so deleting it changes nothing about
// security and only reduces clutter. Unknown expiry counts as live, which is the safe direction: it
// keeps an entity in the priority queue rather than quietly deferring it forever.
func (e UpstreamEntity) inert(now time.Time) bool {
	return !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now)
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

// Registry enumerates every upstream ID this mount OWNS — not merely the ones a
// lease references. Run calls OwnedIDs once per pass and membership-checks in
// memory (O(N), not a List-per-entity O(N^2) scan). Returning an error aborts the
// pass WITHOUT deleting anything: an incomplete owned-set could misclassify a
// live credential as an orphan, so the safe response to "cannot enumerate what we
// own" is to delete nothing.
//
// The method is named for ownership rather than for leases deliberately. It was
// called OwnedIDs and returned lease-tracked IDs only, which meant a rotation
// successor — owner-prefixed, so selected by the lister's filter, but not a lease
// — was classified as an orphan and deleted, destroying the set's only
// mint-capable credential (A1 in docs/audit-2026-08-22.md). Any implementation
// must include minter-owned IDs; see cloudconfig.MinterUpstreamIDs.
type Registry interface {
	OwnedIDs(ctx context.Context) (map[string]struct{}, error)
}

// liveFirst partitions entities so that ones which have not yet expired come first, preserving the
// input order within each group.
//
// Entities whose expiry is unknown are treated as live. That is deliberate: the alternative would
// defer anything the cloud does not describe, which on most clouds is everything.
func liveFirst(entities []UpstreamEntity, now time.Time) []UpstreamEntity {
	ordered := make([]UpstreamEntity, 0, len(entities))
	var inert []UpstreamEntity
	for _, entity := range entities {
		if entity.inert(now) {
			inert = append(inert, entity)
			continue
		}
		ordered = append(ordered, entity)
	}
	return append(ordered, inert...)
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
	// Scanned is how many owned upstream entities the pass examined, so a response
	// can report what is LEFT rather than only what went (A28).
	Scanned      int
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
	config    Config
	cloud     CloudLister
	registry  Registry
	logger    hclog.Logger
	cloudName string
}

// WithLogger attaches the logger that makes a pass auditable.
//
// The package had no logger at all, Result.Deleted was a bare count, and all six
// deleting plugins discarded the Result — so "what did the reconciler delete, and
// when" was unanswerable from any source. The pass is timer-driven, so no OpenBao
// request exists and no audit device can record it either; a structured log line is
// the only channel there is, and metrics are not one (A6, A12 in
// docs/audit-2026-08-22.md).
func (r *reconciler) WithLogger(cloud string, logger hclog.Logger) *reconciler {
	r.logger = logger
	r.cloudName = cloud
	return r
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

	result := &Result{Scanned: len(entities)}

	owned, oerr := r.registry.OwnedIDs(ctx)
	if oerr != nil {
		// Fail closed: without a complete owned-set we cannot safely decide
		// what is an orphan, so abort the pass rather than risk deleting a
		// live credential.
		return nil, oerr
	}

	// Live orphans before inert ones, so the per-pass delete budget is spent where deletion changes
	// the security posture. A stable partition rather than a sort: within each group the listing's
	// own order is preserved, which is oldest-first and is the right order for equals.
	entities = liveFirst(entities, now)

	for _, entity := range entities {
		if _, ok := owned[entity.ID]; ok {
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
			r.warn("reconciler: deleting an orphaned upstream credential failed",
				"id", entity.ID, "name", entity.Name, "error", err)
			continue
		}
		result.Deleted++
		// One line per deletion, naming what was deleted and why it qualified. This
		// is the audit trail for automated destruction of a cloud credential.
		r.info("reconciler: deleted an orphaned upstream credential",
			"id", entity.ID, "name", entity.Name,
			"created_at", entity.CreatedAt, "reason", "not owned by any lease or minter")
	}

	r.summarise(result)
	return result, nil
}

// summarise records the outcome of a pass, including the two conditions that were
// previously invisible: hitting the per-pass delete cap (orphans are accumulating
// faster than they are reclaimed) and per-entity delete failures.
func (r *reconciler) summarise(result *Result) {
	if result.HitLimit {
		r.warn("reconciler: hit the per-pass delete limit; orphans remain",
			"deleted", result.Deleted, "orphans_found", len(result.OrphansFound),
			"limit", r.config.MaxDeletesPerPass)
	}
	if len(result.Errors) > 0 {
		r.warn("reconciler: some orphan deletions failed and will be retried next pass",
			"failed", len(result.Errors), "deleted", result.Deleted)
	}
	if result.Deleted > 0 || len(result.OrphansFound) > 0 {
		r.info("reconciler: pass complete",
			"orphans_found", len(result.OrphansFound), "deleted", result.Deleted,
			"dry_run", r.config.DryRun)
	}
}

func (r *reconciler) info(msg string, args ...interface{}) {
	if r.logger != nil {
		r.logger.Info(msg, append([]interface{}{"cloud", r.cloudName}, args...)...)
	}
}

func (r *reconciler) warn(msg string, args ...interface{}) {
	if r.logger != nil {
		r.logger.Warn(msg, append([]interface{}{"cloud", r.cloudName}, args...)...)
	}
}
