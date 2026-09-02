// Package clusterrole answers one question a plugin cannot answer for itself: is this node the one
// that should be doing background work?
//
// # Why it is needed
//
// An OpenBao cluster is for failover, not for concurrent operation: standby nodes forward client
// requests to the active node, so the request path only ever runs in one place. Background workers
// are different — they are started from InitializeFunc, and InitializeFunc runs on EVERY node.
//
// That is not obvious and was verified against OpenBao's source (v2.6.x) rather than assumed,
// because the comment at vault/ha.go:193 says the opposite and is stale:
//
//	ha.go:521      runStandbyOnce  -> c.postUnseal(…, readonlyUnsealStrategy{})
//	core.go:2226   unsealShared    -> c.setupMounts(ctx)      // the standby flag is NOT passed here
//	mount.go:1579  setupMount      -> backend.Initialize(…)   // via a postUnsealFunc
//	core.go:2347   postUnseal      -> runPostUnsealFuncs(…)   // unconditional
//
// So a three-node cluster ran three health-check loops and three reconcilers. For a plugin that
// authenticates to do its work, that multiplies the cost by node count in three ways that matter:
//
//   - three times the upstream sessions and logins, against a quota that is usually per-account;
//   - three times the reconciler's list-and-delete traffic against that same quota;
//   - and worst, a stale credential produced (attempt cap x node count) failed logins in a burst,
//     which is how a cluster locks out an account rather than merely failing.
//
// # How promotion works, and why nothing needs to watch for it
//
// A standby that wins the leadership election is torn down and set up again: preSeal drops the
// mounts, then postUnseal rebuilds them with the standard strategy and calls Initialize a second
// time. So a plugin only has to decide correctly *during Initialize* and does not have to watch for
// promotion — which is fortunate, because there is no notification it could watch.
//
// This is why InitializeFunc must be idempotent, a rule this project already had for the reload
// case. Promotion is the same shape.
package clusterrole

import (
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// ShouldRunBackgroundWork reports whether this node is the one that should run periodic work —
// health checks, reconcilers, anything on a timer.
//
// True on the active node and true when the answer cannot be determined, which is the deliberate
// direction: a mount whose background work never runs is silently broken (no health checks, no
// orphan reclamation), whereas running it on a node that turns out to be a standby costs duplicated
// work and nothing else. Failing towards "run it" keeps a misread from disabling the feature
// entirely.
//
// A nil view means no system view at all, which happens in unit tests that construct a backend
// directly; those want workers.
func ShouldRunBackgroundWork(view logical.SystemView) bool {
	if view == nil {
		return true
	}
	return !view.ReplicationState().HasState(consts.ReplicationPerformanceStandby)
}

// Describe names this node's role for a log line, so an operator reading why workers did or did not
// start sees the reason rather than inferring it from silence.
func Describe(view logical.SystemView) string {
	if view == nil {
		return "unknown (no system view)"
	}
	if view.ReplicationState().HasState(consts.ReplicationPerformanceStandby) {
		return "standby"
	}
	return "active"
}
