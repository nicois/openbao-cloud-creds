package recovery_test

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

func TestHealthyToTransientOnError(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold:   30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	if sm.State() != recovery.Healthy {
		t.Fatalf("expected initial state healthy, got %s", sm.State())
	}

	sm.RecordError(500, time.Now())
	if sm.State() != recovery.TransientFailing {
		t.Fatalf("expected transient_failing after error, got %s", sm.State())
	}
}

func TestTransientToHealthyOnSuccess(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold:   30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	sm.RecordError(500, time.Now())
	sm.RecordSuccess(time.Now())

	if sm.State() != recovery.Healthy {
		t.Fatalf("expected healthy after success, got %s", sm.State())
	}
}

func TestTransientToAuthFailingOnSustained401(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold:   30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	now := time.Now()
	sm.RecordError(401, now)

	sm.RecordError(401, now.Add(20*time.Second))
	if sm.State() != recovery.TransientFailing {
		t.Fatalf("should still be transient at 20s, got %s", sm.State())
	}

	sm.RecordError(401, now.Add(31*time.Second))
	if sm.State() != recovery.AuthFailing {
		t.Fatalf("expected auth_failing after 31s of 401s, got %s", sm.State())
	}
}

func TestAuthFailingToHealthyOnHealthCheck(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold:   30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	now := time.Now()
	sm.RecordError(403, now)
	sm.RecordError(403, now.Add(31*time.Second))

	if sm.State() != recovery.AuthFailing {
		t.Fatalf("expected auth_failing, got %s", sm.State())
	}

	sm.RecordSuccess(now.Add(6 * time.Minute))
	if sm.State() != recovery.Healthy {
		t.Fatalf("expected healthy after successful health check, got %s", sm.State())
	}
}

func TestConsecutiveFailures(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold:   30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	if sm.ConsecutiveFailures() != 0 {
		t.Fatalf("expected 0 initial failures, got %d", sm.ConsecutiveFailures())
	}

	now := time.Now()
	sm.RecordError(500, now)
	sm.RecordError(500, now.Add(time.Second))
	sm.RecordError(401, now.Add(2*time.Second))

	if sm.ConsecutiveFailures() != 3 {
		t.Fatalf("expected 3 failures, got %d", sm.ConsecutiveFailures())
	}

	sm.RecordSuccess(now.Add(3 * time.Second))
	if sm.ConsecutiveFailures() != 0 {
		t.Fatalf("expected 0 after success, got %d", sm.ConsecutiveFailures())
	}
}

func TestNeedsHealthCheck(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold:   30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	now := time.Now()
	sm.RecordError(401, now)
	sm.RecordError(401, now.Add(31*time.Second))

	if !sm.NeedsHealthCheck(now.Add(6 * time.Minute)) {
		t.Fatal("should need health check after interval")
	}
	if sm.NeedsHealthCheck(now.Add(32 * time.Second)) {
		t.Fatal("should not need health check before interval")
	}
}

// TestStateMachine_ConcurrentAccess hammers the StateMachine from many
// goroutines with a mix of read and write methods. Its purpose is to be run
// under -race: the pass criterion is "no data race and no panic". The final
// state is nondeterministic under concurrency, so we only assert it is one of
// the valid enum values rather than a specific value.
func TestStateMachine_ConcurrentAccess(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold:   30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	now := time.Now()

	const goroutines = 50
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				switch (g + i) % 6 {
				case 0:
					// Transient/server error.
					sm.RecordError(500, now.Add(time.Duration(i)*time.Second))
				case 1:
					// Auth error, advancing time to drive the threshold.
					sm.RecordError(401, now.Add(time.Duration(i)*time.Second))
				case 2:
					sm.RecordSuccess(now.Add(time.Duration(i) * time.Second))
				case 3:
					_ = sm.State()
				case 4:
					_ = sm.ConsecutiveFailures()
				case 5:
					_ = sm.NeedsHealthCheck(now.Add(time.Duration(i) * time.Second))
				}
			}
		}(g)
	}
	wg.Wait()

	switch sm.State() {
	case recovery.Healthy, recovery.TransientFailing, recovery.AuthFailing, recovery.Missing:
		// valid terminal state
	default:
		t.Fatalf("state machine returned invalid state: %q", sm.State())
	}
}

func TestSelectable_429Cooldown(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{AuthFailThreshold: time.Hour, HealthCheckInterval: time.Minute})
	t0 := time.Now()
	sm.RecordError(http.StatusTooManyRequests, t0)
	if sm.Selectable(t0.Add(1 * time.Second)) {
		t.Fatal("expected not selectable during 429 cool-down")
	}
	if !sm.Selectable(t0.Add(recovery.RateLimitCooldown + time.Second)) {
		t.Fatal("expected selectable after cool-down elapsed")
	}
}

func TestSelectable_NonRateLimitErrorNoCooldown(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{AuthFailThreshold: time.Hour, HealthCheckInterval: time.Minute})
	t0 := time.Now()
	sm.RecordError(http.StatusInternalServerError, t0)
	if !sm.Selectable(t0.Add(time.Second)) {
		t.Fatal("a transient (non-429) error must not make the minter unselectable")
	}
}

func TestSelectable_AuthFailingNotSelectable(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{AuthFailThreshold: 0, HealthCheckInterval: time.Minute})
	t0 := time.Now()
	// A single 401 from Healthy only reaches TransientFailing; a second 401
	// (with threshold 0, elapsed >= 0) drives the transition to AuthFailing.
	sm.RecordError(http.StatusUnauthorized, t0)
	sm.RecordError(http.StatusUnauthorized, t0)
	if sm.State() != recovery.AuthFailing {
		t.Fatalf("expected auth_failing, got %q", sm.State())
	}
	if sm.Selectable(t0.Add(time.Second)) {
		t.Fatal("auth_failing minter must not be selectable")
	}
}

func TestSelectable_SuccessClearsCooldown(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{AuthFailThreshold: time.Hour, HealthCheckInterval: time.Minute})
	t0 := time.Now()
	sm.RecordError(http.StatusTooManyRequests, t0)
	sm.RecordSuccess(t0.Add(time.Second))
	if !sm.Selectable(t0.Add(2 * time.Second)) {
		t.Fatal("RecordSuccess must clear the cool-down")
	}
}
