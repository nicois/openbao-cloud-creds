package recovery

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
)

// Rate-limit handling: a circuit breaker, not a timer.
//
// The original model was one fixed 5s window per minter, opened by any 429 and
// closed by the clock. Three things were wrong with that, and each is a different
// kind of wrong:
//
//  1. **It ignored what the cloud asked for.** Most clouds say how long to wait
//     (`Retry-After`, or a body field). Guessing 5s when the cloud said 60 means
//     twelve more refused requests and a longer ban; guessing 5s when the cloud
//     said 1 wastes capacity. The cloud's number is authoritative, and jitter is
//     therefore **additive** to it — we may wait longer than asked, never less.
//
//  2. **The window ended for everyone at the same instant.** With N clients
//     waiting, all N were released together onto a cloud that had just refused
//     them, which is how a rate limit becomes a ban. So the window does not simply
//     end: it goes **half-open**, and exactly one caller is let through to find out
//     whether the cloud has forgiven us. That caller's result decides for the rest.
//
//  3. **A repeated 429 got the same 5s as the first.** Consecutive strikes now
//     back off exponentially, capped, with jitter so that independent minters and
//     nodes do not re-converge on the same schedule.
//
// **There is deliberately no waiter here.** Holding a rate-limited request until
// the window opens was considered and rejected: a client that is told to retry
// will retry, so blocking buys nothing and costs three things. It holds an OpenBao
// request slot per waiting caller; it can outlive the caller's own timeout, turning
// an actionable `upstream_quota_exceeded` into an opaque connection timeout; and —
// decisively — the half-open probe could be granted to a request whose client has
// already disconnected, spending the single permitted cloud call on nobody. Failing
// immediately keeps the probe for a live caller and puts the retry loop where it
// belongs. What we owe the client instead is the NUMBER: the error carries the
// remaining cooldown (RetryIn), so its retry is informed rather than blind.
//
// The half-open probe deliberately applies to **issuance only** (TryAcquire).
// Revoke, rotation and the reconciler keep using the observational Selectable:
// gating a revoke behind a single-flight probe would defer the one operation whose
// deferral leaves a live credential nobody is tracking — that is the KI-002 wedge
// with a new cause.

const (
	// RateLimitCooldown is the FIRST cooldown after a 429 when the cloud gives no
	// hint. Subsequent consecutive strikes double it, up to MaxRateLimitCooldown.
	RateLimitCooldown = 5 * time.Second

	// MaxRateLimitCooldown caps the exponential growth. A minter that has been
	// refused for two minutes is not going to be fixed by waiting an hour, and an
	// unbounded cooldown would silently take a minter out of service for longer
	// than an operator would ever guess.
	MaxRateLimitCooldown = 2 * time.Minute

	// MaxCloudHintJitter bounds the jitter added on top of a cloud-specified wait.
	// The jitter exists to decorrelate callers, not to add meaningful delay, so it
	// stays small however long the cloud's hint is.
	MaxCloudHintJitter = 2 * time.Second

	// ProbeGrace is how long a half-open probe holds its claim before another
	// caller may take it. It is a backstop: the claim is normally released the
	// moment the probe records its outcome. Sized above a plugin's 30s upstream
	// HTTP timeout so a hung call cannot be double-probed while still in flight.
	ProbeGrace = 35 * time.Second
)

// Outcome describes one upstream attempt, and is what the state machine records.
//
// It is a struct rather than three parameters because the third one arrived late:
// RetryAfter is only knowable from a response header or body that the plugin's
// client has to surface deliberately, and a struct lets a cloud that cannot
// surface it simply leave it zero.
type Outcome struct {
	// Status is the HTTP status the cloud returned, or credenvelope.StatusNone
	// when there was no response.
	Status int
	// Err is the error, if any. Required for the no-status case: a client-side
	// timeout carries no status by construction.
	Err error
	// RetryAfter is how long the cloud asked us to wait. Zero means it said
	// nothing, NOT "retry immediately".
	RetryAfter time.Duration
}

// jitterFraction returns a value in [0,1). Package-level so tests can make the
// backoff deterministic without threading a source through every constructor.
var jitterFraction = rand.Float64

// cooldownFor computes the next cooldown window from the strike count and
// whatever the cloud told us.
//
// With a cloud hint: hint + a small jitter. Additive because a hint is a promise
// we must not break — retrying before the cloud said to is what turns throttling
// into blocking, and it is the one direction jitter must never move us.
//
// Without one: exponential from RateLimitCooldown, capped, with equal jitter
// (half fixed, half random) so the wait keeps a useful floor while still
// decorrelating.
func cooldownFor(strikes int, hint time.Duration) time.Duration {
	if hint > 0 {
		bound := min(hint, MaxCloudHintJitter)
		return hint + time.Duration(jitterFraction()*float64(bound))
	}
	if strikes < 1 {
		strikes = 1
	}
	backoff := RateLimitCooldown
	for i := 1; i < strikes && backoff < MaxRateLimitCooldown; i++ {
		backoff *= 2
	}
	backoff = min(backoff, MaxRateLimitCooldown)
	half := backoff / 2
	return half + time.Duration(jitterFraction()*float64(half))
}

// InRateLimitCooldown reports whether this minter is currently held back by a
// rate-limit cooldown, as opposed to being unusable for some other reason.
//
// Exported because the difference is what a caller is told: a set whose minters
// are all cooling down is `upstream_quota_exceeded` ("retry shortly"), not
// `upstream_auth_failed` ("your credentials are broken"). Reporting the latter
// sends an operator to look at credentials during a rate-limit storm.
func (sm *StateMachine) InRateLimitCooldown(now time.Time) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return now.Before(sm.cooldownUntil) || sm.rateLimitStrikes > 0
}

// TryAcquire reports whether this minter may be used to ISSUE right now, and is
// the only selector that may mutate state.
//
// While a cooldown is open it refuses everyone. When the cooldown expires but
// strikes remain, the minter is half-open: the first caller is granted the probe
// and every other caller is refused until that probe records an outcome (or
// ProbeGrace elapses). A successful outcome clears the strikes and the minter is
// fully available again; another 429 re-closes the window, longer.
func (sm *StateMachine) TryAcquire(now time.Time) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if !sm.serviceable(now) {
		return false
	}
	if now.Before(sm.cooldownUntil) {
		return false
	}
	if sm.rateLimitStrikes == 0 {
		return true
	}
	// Half-open: one probe at a time.
	if now.Before(sm.probeUntil) {
		return false
	}
	sm.probeUntil = now.Add(ProbeGrace)
	return true
}

// serviceable is the state check shared by TryAcquire and Selectable. Callers
// hold the lock.
func (sm *StateMachine) serviceable(_ time.Time) bool {
	return sm.state == Healthy || sm.state == TransientFailing
}

// RetryIn reports how long to wait before this minter is worth trying again, and
// is what lets a caller sleep until something changes instead of polling blindly.
//
// Zero means "try now". For a half-open minter whose probe is already claimed it
// returns a short interval rather than the probe grace: the probe usually
// finishes in milliseconds, and the point of waiting is to be ready the moment it
// does.
func (sm *StateMachine) RetryIn(now time.Time) time.Duration {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.retryInLocked(now)
}

// retryInLocked is RetryIn's body, for callers already holding the lock, so Snapshot can compute
// every field under one.
func (sm *StateMachine) retryInLocked(now time.Time) time.Duration {
	if !sm.serviceable(now) {
		return 0 // not a rate-limit problem; waiting will not fix it
	}
	if now.Before(sm.cooldownUntil) {
		return sm.cooldownUntil.Sub(now)
	}
	if sm.rateLimitStrikes > 0 && now.Before(sm.probeUntil) {
		return probePollInterval
	}
	return 0
}

// probePollInterval is how long a waiting caller sleeps while another caller's
// half-open probe is in flight.
const probePollInterval = 100 * time.Millisecond

// UnavailableError explains why a set could serve nobody, in the terms a client
// can act on.
//
// The distinction is the whole point. "Every minter is in a rate-limit cooldown"
// and "every minter's credential is rejected" both used to arrive as
// `upstream_auth_failed` — telling a client its credentials were broken, and
// telling the operator to go and look at them, during what was actually a quota
// storm that would clear itself in seconds. Since we return immediately rather
// than waiting, the remaining cooldown is the most useful thing we can hand back:
// the client's retry loop can be informed instead of blind.
func UnavailableError(setName string, machines []*StateMachine, now time.Time) error {
	soonest := time.Duration(-1)
	for _, sm := range machines {
		if !sm.InRateLimitCooldown(now) {
			continue
		}
		if retryIn := sm.RetryIn(now); soonest < 0 || retryIn < soonest {
			soonest = retryIn
		}
	}
	if soonest >= 0 {
		return credenvelope.NewError(credenvelope.ErrUpstreamQuotaExceeded, http.StatusServiceUnavailable,
			fmt.Sprintf("every minter in set %q is rate-limited by the upstream; retry in %s",
				setName, soonest.Round(time.Second)))
	}
	return credenvelope.NewError(credenvelope.ErrUpstreamAuthFailed, http.StatusBadGateway,
		fmt.Sprintf("all minters in set %q are failing", setName))
}

// ParseRetryAfter reads an HTTP Retry-After header, which RFC 9110 allows in two
// forms: delta-seconds, or an HTTP-date. Both appear in the wild — clouds are not
// consistent even with themselves — so both are handled, and anything
// unrecognisable returns 0 meaning "the cloud said nothing".
//
// A past or zero date returns 0 rather than a negative duration: "retry after a
// time that has passed" means retry now, and a negative cooldown would leave the
// breaker permanently open.
func ParseRetryAfter(header http.Header, now time.Time) time.Duration {
	raw := strings.TrimSpace(header.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(raw); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(raw)
	if err != nil {
		return 0
	}
	if wait := when.Sub(now); wait > 0 {
		return wait
	}
	return 0
}

// Snapshot is a point-in-time, secret-free view of a minter's health, for the
// minter-set read endpoint.
//
// None of this was observable. The read endpoint returned {name, minter_count,
// minter_ids} on all ten plugins while recovery state, last success, failure count
// and the rate-limit cooldown all sat in the same process — so after a rotation an
// operator could not see which minter was retired or when the sweep would act, and
// during an outage could not see that a minter was auth_failing or cooling down.
// With metrics going nowhere in the documented deployment (A12), that left
// log-grepping as the only channel (A27 in docs/audit-2026-08-22.md).
type Snapshot struct {
	State               string `json:"state"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	// ConsecutiveAuthFailures is the lockout-relevant count: rejected logins since the last good one.
	ConsecutiveAuthFailures int    `json:"consecutive_auth_failures"`
	LastSuccessAt           string `json:"last_success_at,omitempty"`
	Selectable              bool   `json:"selectable"`
	RateLimited             bool   `json:"rate_limited"`
	RetryInSeconds          int    `json:"retry_in_seconds,omitempty"`
}

// Snapshot renders the machine's current state. It deliberately exposes no
// credential material and no upstream error text — only the operator-facing facts.
//
// One RLock for the whole snapshot, rather than a stack of locking getters. Each getter is
// individually safe, but between them a concurrent Record or RecordSuccess can land, and the caller
// then receives a state that never existed: `state: auth_failing` beside
// `consecutive_auth_failures: 0`, or a cooldown with no retry. That matters more than it reads,
// because this snapshot is not only for human eyes -- the reconcile script fetches it over HTTP and
// refuses an --enable run on one of these fields, so a torn read is a gate deciding on a state the
// minter was never in.
func (sm *StateMachine) Snapshot(now time.Time) Snapshot {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	snap := Snapshot{
		State:                   string(sm.state),
		ConsecutiveFailures:     sm.consecutiveFailures,
		ConsecutiveAuthFailures: sm.consecutiveAuthFailures,
		Selectable:              !now.Before(sm.cooldownUntil) && sm.serviceable(now),
		RateLimited:             now.Before(sm.cooldownUntil) || sm.rateLimitStrikes > 0,
	}
	if !sm.lastSuccessAt.IsZero() {
		snap.LastSuccessAt = sm.lastSuccessAt.UTC().Format(time.RFC3339)
	}
	if retryIn := sm.retryInLocked(now); retryIn > 0 {
		snap.RetryInSeconds = int(retryIn.Seconds())
	}
	return snap
}
