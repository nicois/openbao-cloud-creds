package capability

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

func limiterFor(sm *recovery.StateMachine, now time.Time) *Limiter {
	return &Limiter{
		States: func(id string) *recovery.StateMachine {
			if id == "minter-1" {
				return sm
			}
			return nil
		},
		Now: func() time.Time { return now },
	}
}

func newSM() *recovery.StateMachine {
	return recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold:   30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})
}

// A probe is a real mint against the same quota as a caller's read, so the two must
// see one cooldown between them: a probe must be refused while a window is open,
// and a probe's own 429 must open one.
func TestLimiterSharesTheCooldownWithIssuance(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	t.Run("a probe is refused while a cooldown the read path opened is still shut", func(t *testing.T) {
		sm := newSM()
		sm.Record(recovery.Outcome{Status: http.StatusTooManyRequests}, now)

		err := limiterFor(sm, now).acquire("minter-1")
		var throttled *Throttled
		if !errors.As(err, &throttled) {
			t.Fatalf("a probe was allowed to call a cloud that had just refused the read path: %v", err)
		}
		if throttled.RetryIn <= 0 {
			t.Errorf("the refusal carries no wait, so an operator's retry is blind: %v", throttled)
		}
	})

	t.Run("a probe's own 429 opens the cooldown for everyone", func(t *testing.T) {
		sm := newSM()
		limiterFor(sm, now).record("minter-1", http.StatusTooManyRequests, errors.New("429 slow down"))
		if !sm.InRateLimitCooldown(now) {
			t.Error("a probe earned a 429 and no cooldown opened, so the readers sharing that quota " +
				"walk straight into the same refusal")
		}
	})

	t.Run("an unknown minter is not blocked", func(t *testing.T) {
		if err := limiterFor(newSM(), now).acquire("brand-new"); err != nil {
			t.Errorf("a minter being written for the first time has no state and must not be "+
				"refused: %v", err)
		}
	})

	t.Run("a nil limiter allows everything", func(t *testing.T) {
		var l *Limiter
		if err := l.acquire("minter-1"); err != nil {
			t.Errorf("an unconfigured limiter must not gate anything: %v", err)
		}
		l.record("minter-1", http.StatusOK, nil) // must not panic
	})
}

// The narrow recording rule, stated as a test because getting it wrong is worse
// than not recording at all: a refusal on privilege grounds is about ONE role's
// mint shape, and indicting the minter for it would pull a credential serving every
// other role out of service.
func TestLimiterDoesNotIndictAMinterForARefusedProbe(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	sm := newSM()

	for range 10 {
		limiterFor(sm, now).record("minter-1", http.StatusForbidden, errors.New("403 forbidden"))
	}

	if sm.State() != recovery.Healthy {
		t.Errorf("ten refused probes moved the minter to %v. A probe proves a GRANT, not a "+
			"credential: the minter is fine and every other role bound to it still needs it",
			sm.State())
	}
	if !sm.Selectable(now) {
		t.Error("the minter is no longer selectable for issuance because a role was written wrong")
	}
}

func TestLimiterRecordsASuccessfulProbeAsHealth(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	sm := newSM()
	sm.RecordError(http.StatusInternalServerError, now.Add(-time.Minute))

	limiterFor(sm, now).record("minter-1", http.StatusOK, nil)

	if sm.ConsecutiveFailures() != 0 {
		t.Errorf("a probe that minted successfully is a successful upstream mint and should clear "+
			"the failure count, got %d", sm.ConsecutiveFailures())
	}
}

// The Runner must consult the limiter BEFORE running a probe, and must not report
// a throttled pass as a capability failure — those are different answers.
func TestRunnerStopsBeforeMintingWhenThrottled(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	sm := newSM()
	sm.Record(recovery.Outcome{Status: http.StatusTooManyRequests}, now)

	ran := 0
	runner := Runner{Limiter: limiterFor(sm, now)}
	_, err := runner.Verify(t.Context(), []Check{{
		Key: "k", Minter: "minter-1", Roles: []string{"role-a"},
		Run: func(context.Context) (int, error) { ran++; return http.StatusOK, nil },
	}})

	if ran != 0 {
		t.Errorf("the probe ran %d times despite an open cooldown", ran)
	}
	var throttled *Throttled
	if !errors.As(err, &throttled) {
		t.Fatalf("want a Throttled, got %#v — a throttled write must not be reported as \"this "+
			"minter cannot mint\", which is a verdict nobody has established", err)
	}
	var failure *Failure
	if errors.As(err, &failure) {
		t.Error("a throttled pass was rendered as a capability failure")
	}
}
