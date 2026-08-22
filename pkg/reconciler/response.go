package reconciler

import "time"

// The /reconcile endpoint had three different response schemas across ten plugins
// with the same path and the same documentation: six clouds returned
// orphans_found/hit_limit/delete_errors/confirmation_hold, the three that cannot
// revoke returned expired_found/active_remaining instead, and OCI returned a third
// subset. Every field name was reasonable on its own; together they meant a client
// or a runbook had to be written per cloud for an endpoint whose whole point is that
// it is the same everywhere (A28 in docs/audit-2026-08-22.md).
//
// This is the one shape. The genuine difference between the clouds — whether a pass
// deletes upstream credentials or prunes local tracking entries — is now DATA, in
// Target, rather than a difference in the schema.

// Reconcile targets. Which one a cloud reports follows from its revoke model, and
// says what a `deleted` count actually deleted.
const (
	// TargetUpstreamOrphans: the pass deletes owner-tagged credentials that exist on
	// the cloud with no lease tracking them. `deleted` means gone from the cloud.
	TargetUpstreamOrphans = "upstream_orphans"
	// TargetLocalExpired: the credential expired on its own (AWS STS, GCP tokens, OVH
	// tokens) and the pass prunes the local tracking entry that outlived it.
	// `deleted` means a storage entry is gone; nothing upstream is touched.
	TargetLocalExpired = "local_expired_entries"
)

// ResponseData is the uniform /reconcile response. Every field is meaningful for
// both targets, which is what makes one schema honest rather than a lowest common
// denominator: a target with no confirmation hold reports zero because it needs
// none, not because the field does not apply.
type ResponseData struct {
	// Mode is the requested mode, echoed back after validation.
	Mode string
	// DryRun is what the pass actually did, not what was asked for.
	DryRun bool
	// Target says what the counts below are about.
	Target string
	// Scanned is how many candidates the pass examined.
	Scanned int
	// Found is how many of them it judged reclaimable.
	Found int
	// Deleted is how many it removed (0 in dry-run).
	Deleted int
	// Remaining is how many candidates are left after the pass.
	Remaining int
	// DeleteErrors is how many deletions failed. A per-entity failure does not abort
	// a pass, so this can be non-zero on an otherwise successful response.
	DeleteErrors int
	// HitLimit reports that max_deletes_per_pass stopped the pass early, so another
	// pass has work to do.
	HitLimit bool
	// ConfirmationHold is how recent a candidate may be and still be left alone.
	// Zero for TargetLocalExpired: the credential has already expired, so there is
	// nothing a hold would protect.
	ConfirmationHold time.Duration
}

// Map renders the response for logical.Response.Data.
func (r ResponseData) Map() map[string]interface{} {
	return map[string]interface{}{
		"mode":              r.Mode,
		"dry_run":           r.DryRun,
		"target":            r.Target,
		"scanned":           r.Scanned,
		"found":             r.Found,
		"deleted":           r.Deleted,
		"remaining":         r.Remaining,
		"delete_errors":     r.DeleteErrors,
		"hit_limit":         r.HitLimit,
		"confirmation_hold": r.ConfirmationHold.String(),
	}
}
