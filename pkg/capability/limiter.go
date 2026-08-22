package capability

import (
	"fmt"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

// Limiter puts capability probes inside the same circuit breaker as issuance.
//
// A probe is a real mint against the cloud's real quota, but none of the ten
// plugins passed one through the rate limiter: a probe storm was neither refused
// while a cooldown was open nor able to open one, so probes hammered a cloud that
// had just throttled the read path, and a 429 the probes themselves earned stayed
// invisible to the callers sharing that quota (A29).
//
// What it deliberately does NOT do:
//
//   - It does not gate on minter HEALTH, only on the rate-limit window. Gating on
//     health would make a set unfixable: an operator replacing a failed credential
//     writes the same minter id, so a state machine still in AuthFailing from the
//     old credential would refuse the very write that repairs it.
//   - It does not take the half-open single-flight claim. That claim exists for
//     issuance (see the ratelimit.go commentary): spending it on a configuration
//     write would defer a live caller's read to answer a question the operator
//     could ask again a second later.
//   - It does not record a REFUSED probe as a minter failure. A refusal on
//     privilege grounds says the minter lacks a grant for one role's mint shape,
//     not that its credential is failing; indicting it there would pull a minter
//     serving nine other roles out of service because a tenth role was written
//     wrong. Only the rate limit — the genuinely shared resource — and success are
//     recorded.
type Limiter struct {
	// States resolves a minter id to its state machine, across every set, or nil
	// if there is none. A candidate minter being written for the first time has no
	// state yet, which is not an error: it is simply unthrottled as far as we know.
	States func(minterID string) *recovery.StateMachine
	// Now is the clock, for tests. Defaults to time.Now.
	Now func() time.Time
}

// Throttled reports that a probe was not attempted because the cloud has this
// minter in a rate-limit cooldown. It is separate from *Failure because it is a
// different answer: not "this minter cannot mint" but "ask again shortly".
type Throttled struct {
	Minter  string
	RetryIn time.Duration
}

func (t *Throttled) Error() string {
	return fmt.Sprintf("minter %q is in a rate-limit cooldown; retry in %s",
		t.Minter, t.RetryIn.Round(time.Second))
}

// acquire reports whether a probe may call the upstream for this minter now. A nil
// receiver means no limiter was configured, and every probe proceeds.
func (l *Limiter) acquire(minterID string) error {
	sm := l.stateFor(minterID)
	if sm == nil {
		return nil
	}
	now := l.now()
	if sm.InRateLimitCooldown(now) {
		return &Throttled{Minter: minterID, RetryIn: sm.RetryIn(now)}
	}
	return nil
}

// record shares a probe's outcome with the state machine, narrowly: a success
// (which a probe mint genuinely is) and a rate limit (the shared resource). Every
// other failure releases any half-open claim without indicting the minter.
func (l *Limiter) record(minterID string, status int, err error) {
	sm := l.stateFor(minterID)
	if sm == nil {
		return
	}
	now := l.now()
	switch {
	case err == nil:
		sm.RecordSuccess(now)
	case credenvelope.Classify(status, err) == credenvelope.ErrUpstreamQuotaExceeded:
		sm.Record(recovery.Outcome{Status: status, Err: err}, now)
	default:
		sm.ReleaseProbe()
	}
}

func (l *Limiter) stateFor(minterID string) *recovery.StateMachine {
	if l == nil || l.States == nil {
		return nil
	}
	return l.States(minterID)
}

func (l *Limiter) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}
