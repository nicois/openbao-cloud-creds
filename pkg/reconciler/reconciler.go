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
	// It exists to separate the two kinds of orphan the per-pass delete budget has to fund. An
	// orphan that has already expired is inert — nothing can use it, so deleting it is housekeeping
	// — while a live one is an exposure. Without this field the reconciler charged both to one
	// budget in creation order, and expired credentials are the OLDEST, so on a cloud that lists
	// them the whole budget went to the harmless ones and live orphans waited for the next pass.
	ExpiresAt time.Time
}

// orphanClass says which delete budget an orphan is funded from. Named rather than a boolean
// because the two are not "on and off" — they are two populations with different consequences.
type orphanClass int

const (
	// liveOrphan can still be used by whoever holds it, so deleting it could break a workload. This
	// is what the conservative per-pass cap exists for.
	liveOrphan orphanClass = iota
	// inertOrphan has already expired upstream. Deleting it is housekeeping.
	inertOrphan
)

// classify decides which budget this entity draws on. Unknown expiry counts as LIVE, which is the
// safe direction: it keeps the entity under the conservative cap rather than on the housekeeping
// budget, and most clouds' listings report no expiry at all.
func (e UpstreamEntity) classify(now time.Time) orphanClass {
	if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
		return inertOrphan
	}
	return liveOrphan
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

// deleteBudget bounds a pass, counting live and already-expired orphans SEPARATELY.
//
// One shared budget conflated two different risks. The budget exists because deletion here is
// INFERRED — an entity is an orphan because this mount cannot find it in its own records — so a
// subtly incomplete owned-set nominates live credentials, and a low per-pass cap is what bounds the
// damage and leaves time for a human to notice (that is the A1 class in docs/audit-2026-08-22.md).
// None of that reasoning applies to a credential the cloud has already expired: nothing can use it,
// so deleting it is housekeeping and cannot break a workload.
//
// Two counters rather than exempting inert entities altogether, because "expired" is derived data
// too. A node whose clock is hours fast, or a lister that misreads the upstream's expiry field,
// reclassifies live credentials as inert — and an exemption would then delete them without bound.
// So the runaway bound is kept (at most 2×limit deletions per pass, the same order of magnitude)
// while guaranteeing the thing that was actually broken: expired clutter can never starve a live
// orphan of budget, however much of it there is.
//
// The consequence to be aware of: a large expired leak still drains at limit-per-pass. That is
// accepted — it is clutter, it costs only listing size, and it is going nowhere on its own.
type deleteBudget struct {
	limit int
	live  int
	inert int
}

// claim reserves one deletion from the counter for this class, reporting false when that counter is
// spent. Charging the right counter is the whole mechanism.
func (b *deleteBudget) claim(class orphanClass) bool {
	spent := &b.live
	if class == inertOrphan {
		spent = &b.inert
	}
	if *spent >= b.limit {
		return false
	}
	*spent++
	return true
}

// MinConfirmationHold is the floor for an operator-requested confirmation hold
// on the manual reconcile path. A hold shorter than this (including zero) would
// re-expose the create-then-track window that the fail-closed guard protects
// against, so operator-facing callers clamp their requested hold up to this
// value. NOTE: this floor is applied by callers (the manual /reconcile
// handlers), NOT inside Run — Run's ConfirmationHold==0 still means "guard
// disabled" for internal/worker use and existing tests.
const MinConfirmationHold = 5 * time.Minute

// WorkerConfirmationHold is the minimum age an orphan must reach before a TIMER-DRIVEN pass will
// delete it. Every background reconciler uses this; the value is far above MinConfirmationHold on
// purpose, because a worker has nobody watching it.
//
// What it protects, in order of how likely each is to be met:
//
//  1. **The create-then-track window.** A credential exists upstream for a moment before this mount
//     records it. In that window it is indistinguishable from an orphan, and the reconciler would
//     delete a credential a client is about to be handed.
//  2. **Handover between cluster nodes.** Background work runs on the ACTIVE node only
//     (pkg/clusterrole), so a failover moves the reconciler to a node whose view of storage is
//     whatever replication has delivered. A tracking record written moments before the handover may
//     not be visible to the promoted node's first pass, which would read a live credential as an
//     orphan. An hour is orders of magnitude more than raft replication needs, and there is no cost
//     to waiting — an orphan an hour old is just as reclaimable.
//  3. **Clock disagreement between nodes.** The age is computed from the cloud's own creation
//     timestamp against the local clock, so the two come from different sources. Minutes of skew
//     cannot reach across an hour.
//
// A named constant rather than the literal it replaces in six workers: the guarantee is a single
// value now, it is greppable from the question "what stops the reconciler racing an issue", and
// TestWorkerHoldClearsTheFloor keeps it above the manual path's floor.
const WorkerConfirmationHold = time.Hour

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
	// HitLimit reports that a pass left orphans undeleted because a delete budget was spent. The
	// budget is per class, so this can be set while deletions of the OTHER class continued.
	HitLimit bool
	// Expired is how many of Deleted had already expired upstream, so an operator reading a
	// deletion count larger than the configured cap can see why: the cap is per class, and this is
	// the half that could not have broken anything.
	Expired int
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

	// Entities are processed in the listing's own order, which listers sort oldest-first — the right
	// order for equals. Priority is handled by charging each deletion to its own budget rather than
	// by reordering, so running out of budget for expired clutter cannot delay a live orphan.
	budget := &deleteBudget{limit: r.config.MaxDeletesPerPass}

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

		// Already expired upstream? Then this deletion is housekeeping and is funded separately.
		class := entity.classify(now)
		if !budget.claim(class) {
			result.HitLimit = true
			// Continue rather than break: the other class may still have budget, and stopping the
			// scan here would also stop counting what remains.
			continue
		}

		if err := r.cloud.DeleteEntity(ctx, entity.ID); err != nil {
			result.Errors = append(result.Errors, entity.ID)
			r.warn("reconciler: deleting an orphaned upstream credential failed",
				"id", entity.ID, "name", entity.Name, "error", err)
			continue
		}
		result.Deleted++
		if class == inertOrphan {
			result.Expired++
		}
		// One line per deletion, naming what was deleted and why it qualified. This
		// is the audit trail for automated destruction of a cloud credential.
		r.info("reconciler: deleted an orphaned upstream credential",
			"id", entity.ID, "name", entity.Name,
			"created_at", entity.CreatedAt, "expired_upstream", class == inertOrphan,
			"reason", "not owned by any lease or minter")
	}

	r.summarise(result)
	return result, nil
}

// summarise records the outcome of a pass, including the two conditions that were
// previously invisible: hitting the per-pass delete cap (orphans are accumulating
// faster than they are reclaimed) and per-entity delete failures.
func (r *reconciler) summarise(result *Result) {
	if result.HitLimit {
		r.warn("reconciler: hit a per-pass delete limit; orphans remain",
			"deleted", result.Deleted, "of_which_expired", result.Expired,
			"orphans_found", len(result.OrphansFound),
			"limit_per_class", r.config.MaxDeletesPerPass)
	}
	if len(result.Errors) > 0 {
		r.warn("reconciler: some orphan deletions failed and will be retried next pass",
			"failed", len(result.Errors), "deleted", result.Deleted)
	}
	if result.Deleted > 0 || len(result.OrphansFound) > 0 {
		r.info("reconciler: pass complete",
			"orphans_found", len(result.OrphansFound), "deleted", result.Deleted,
			"of_which_expired", result.Expired, "dry_run", r.config.DryRun)
	}
}

func (r *reconciler) info(msg string, args ...any) {
	if r.logger != nil {
		r.logger.Info(msg, append([]any{"cloud", r.cloudName}, args...)...)
	}
}

func (r *reconciler) warn(msg string, args ...any) {
	if r.logger != nil {
		r.logger.Warn(msg, append([]any{"cloud", r.cloudName}, args...)...)
	}
}
