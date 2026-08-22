package recovery

import (
	"net/http"
	"sync"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
)

type State string

const (
	Healthy          State = "healthy"
	TransientFailing State = "transient_failing"
	AuthFailing      State = "auth_failing"
	Missing          State = "missing"
)

type Config struct {
	AuthFailThreshold   time.Duration
	HealthCheckInterval time.Duration
}

type StateMachine struct {
	mu                  sync.RWMutex
	state               State
	config              Config
	firstAuthErrorAt    time.Time
	lastErrorAt         time.Time
	lastSuccessAt       time.Time
	enteredAuthFailed   time.Time
	cooldownUntil       time.Time
	consecutiveFailures int

	// rateLimitStrikes counts CONSECUTIVE 429s, reset by any success. It drives
	// the exponential backoff and marks the half-open window: strikes > 0 with an
	// expired cooldown means "one probe allowed".
	rateLimitStrikes int
	// probeUntil holds the half-open claim, so exactly one caller probes.
	probeUntil time.Time
}

func NewStateMachine(cfg Config) *StateMachine {
	return &StateMachine{
		state:  Healthy,
		config: cfg,
	}
}

func (sm *StateMachine) State() State {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

func (sm *StateMachine) LastSuccessAt() time.Time {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.lastSuccessAt
}

func (sm *StateMachine) RecordSuccess(at time.Time) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.consecutiveFailures = 0
	sm.lastSuccessAt = at
	sm.firstAuthErrorAt = time.Time{}
	sm.cooldownUntil = time.Time{}
	// A success closes the breaker: strikes reset so the next 429 starts the
	// backoff from the bottom, and the half-open claim is released.
	sm.rateLimitStrikes = 0
	sm.probeUntil = time.Time{}
	sm.state = Healthy
}

func (sm *StateMachine) ConsecutiveFailures() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.consecutiveFailures
}

// RecordUpstream records the outcome of one upstream attempt, and is the entry
// point every caller should use: it drops failures that say nothing about this
// minter's credential before they reach the state machine.
//
// The distinction exists because one classification used to serve two consumers.
// A duration the cloud rejects, or a minter set the operator misnamed, is a fault
// in the request — but it was counted as a fault against the *credential*, which
// walked healthy minters toward AuthFailing (the second half of KI-010). Pass the
// error as well as the status: a client-side timeout has no status by
// construction, and without the error it is indistinguishable from a plugin bug.
func (sm *StateMachine) RecordUpstream(httpStatus int, err error, at time.Time) {
	sm.Record(Outcome{Status: httpStatus, Err: err}, at)
}

// Record records one upstream attempt. This is the entry point every caller
// should use: it drops failures that say nothing about this minter's credential,
// and it is where a rate limit becomes a cooldown honouring what the cloud asked
// for (see ratelimit.go).
func (sm *StateMachine) Record(o Outcome, at time.Time) {
	code := credenvelope.Classify(o.Status, o.Err)
	if !credenvelope.IndictsMinter(code) {
		// The outcome says nothing about this minter — but if the caller held the
		// half-open probe, it must still be released, or one malformed request
		// freezes a recovering minter for the whole ProbeGrace (A18). Two correct
		// fixes interacting: the KI-010 exoneration and the breaker.
		sm.releaseProbe()
		return
	}
	if code == credenvelope.ErrUpstreamQuotaExceeded {
		sm.recordRateLimited(o.RetryAfter, at)
		return
	}
	sm.RecordError(credenvelope.HealthStatus(code), at)
}

// recordRateLimited opens (or re-opens, longer) the cooldown window.
func (sm *StateMachine) recordRateLimited(retryAfter time.Duration, at time.Time) {
	sm.mu.Lock()
	sm.rateLimitStrikes++
	sm.cooldownUntil = at.Add(cooldownFor(sm.rateLimitStrikes, retryAfter))
	// A refused probe is finished with; release the claim so the next window's
	// probe is not blocked by this one's grace.
	sm.probeUntil = time.Time{}
	sm.mu.Unlock()

	// The generic bookkeeping (consecutive failures, state transition) still
	// applies, but must not overwrite the cooldown just computed — so 429 is
	// passed as a status the state machine no longer special-cases.
	sm.RecordError(http.StatusServiceUnavailable, at)
}

// RecordError records a failure against this minter unconditionally. Prefer
// RecordUpstream, which first asks whether the failure is about the minter at
// all; this remains for callers that have already made that judgement.
func (sm *StateMachine) RecordError(httpStatus int, at time.Time) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.consecutiveFailures++
	sm.lastErrorAt = at
	if httpStatus == http.StatusTooManyRequests {
		// Kept for direct RecordError callers that have not been migrated to
		// Record: without a cloud hint or a strike count this is the first-strike
		// window, which is what the old behaviour was.
		sm.cooldownUntil = at.Add(cooldownFor(1, 0))
	}

	switch sm.state {
	case Healthy:
		sm.state = TransientFailing
		if isAuthError(httpStatus) {
			sm.firstAuthErrorAt = at
		}

	case TransientFailing:
		if isAuthError(httpStatus) {
			if sm.firstAuthErrorAt.IsZero() {
				sm.firstAuthErrorAt = at
			}
			if at.Sub(sm.firstAuthErrorAt) >= sm.config.AuthFailThreshold {
				sm.state = AuthFailing
				sm.enteredAuthFailed = at
			}
		} else {
			sm.firstAuthErrorAt = time.Time{}
		}

	case AuthFailing:
		// Stay in auth_failing

	case Missing:
		// Already known-missing; an upstream error does not change that.
		// State only leaves Missing via a successful RecordSuccess.
	}
}

// Selectable reports whether a minter in this state may be chosen to mint a
// credential at the given time. False while a 429 cool-down is active and for
// states that must not serve (AuthFailing, Missing).
// Selectable reports whether a minter MAY be used, without claiming anything. It
// is for revoke, rotation and the reconciler — operations that must not be held
// behind a half-open probe. Issuance uses TryAcquire.
func (sm *StateMachine) Selectable(now time.Time) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if now.Before(sm.cooldownUntil) {
		return false
	}
	return sm.serviceable(now)
}

func (sm *StateMachine) RecordMissing() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state = Missing
}

func (sm *StateMachine) NeedsHealthCheck(now time.Time) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.state != AuthFailing {
		return false
	}
	lastCheck := sm.enteredAuthFailed
	if !sm.lastSuccessAt.IsZero() && sm.lastSuccessAt.After(lastCheck) {
		lastCheck = sm.lastSuccessAt
	}
	return now.Sub(lastCheck) >= sm.config.HealthCheckInterval
}

func isAuthError(status int) bool {
	return status == 401 || status == 403
}

// releaseProbe hands the half-open claim back without recording anything against
// the minter, for an outcome that was not the minter's fault.
func (sm *StateMachine) releaseProbe() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.probeUntil = time.Time{}
}
