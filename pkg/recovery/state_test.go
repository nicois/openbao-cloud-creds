package recovery_test

import (
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
