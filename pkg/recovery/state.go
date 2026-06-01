package recovery

import (
	"net/http"
	"sync"
	"time"
)

type State string

const (
	Healthy          State = "healthy"
	TransientFailing State = "transient_failing"
	AuthFailing      State = "auth_failing"
	Missing          State = "missing"
)

// RateLimitCooldown is how long a minter is skipped by selectors after the
// upstream returns 429, so a rate-limited minter is not immediately re-hammered.
const RateLimitCooldown = 5 * time.Second

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
	sm.state = Healthy
}

func (sm *StateMachine) ConsecutiveFailures() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.consecutiveFailures
}

func (sm *StateMachine) RecordError(httpStatus int, at time.Time) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.consecutiveFailures++
	sm.lastErrorAt = at
	if httpStatus == http.StatusTooManyRequests {
		sm.cooldownUntil = at.Add(RateLimitCooldown)
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
func (sm *StateMachine) Selectable(now time.Time) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if now.Before(sm.cooldownUntil) {
		return false
	}
	return sm.state == Healthy || sm.state == TransientFailing
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
