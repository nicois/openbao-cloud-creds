package recovery

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// fixJitter makes the backoff deterministic. Tests that care about the jitter
// itself set the fraction they want.
func fixJitter(t *testing.T, fraction float64) {
	t.Helper()
	previous := jitterFraction
	jitterFraction = func() float64 { return fraction }
	t.Cleanup(func() { jitterFraction = previous })
}

func newSM() *StateMachine {
	return NewStateMachine(Config{AuthFailThreshold: 30 * time.Second, HealthCheckInterval: time.Minute})
}

func rateLimited(retryAfter time.Duration) Outcome {
	return Outcome{Status: http.StatusTooManyRequests, RetryAfter: retryAfter}
}

// TestCloudHintIsNeverShortened is the load-bearing property of honouring
// Retry-After: jitter may only ever make us wait LONGER. Retrying before the
// cloud said to is what turns throttling into blocking.
func TestCloudHintIsNeverShortened(t *testing.T) {
	for _, fraction := range []float64{0, 0.5, 0.999} {
		t.Run("", func(t *testing.T) {
			fixJitter(t, fraction)
			const hint = 30 * time.Second
			got := cooldownFor(1, hint)
			if got < hint {
				t.Errorf("cooldown %s is SHORTER than the cloud's %s hint (jitter fraction %v): "+
					"jitter must be additive to a hint, never subtractive", got, hint, fraction)
			}
			if got > hint+MaxCloudHintJitter {
				t.Errorf("cooldown %s exceeds hint+%s; jitter should decorrelate, not delay",
					got, MaxCloudHintJitter)
			}
		})
	}
}

// TestCloudHintWinsOverBackoff: a cloud that says 60s gets 60s even on the first
// strike, where the default would have been 5s.
func TestCloudHintWinsOverBackoff(t *testing.T) {
	fixJitter(t, 0)
	if got := cooldownFor(1, time.Minute); got != time.Minute {
		t.Errorf("first strike with a 60s hint waited %s, want 60s — the hint is authoritative", got)
	}
	if got := cooldownFor(1, 0); got != RateLimitCooldown/2 {
		t.Errorf("first strike with no hint waited %s, want %s (equal jitter, fraction 0)",
			got, RateLimitCooldown/2)
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	fixJitter(t, 1) // full jitter, so cooldownFor returns the whole backoff
	var previous time.Duration
	for strikes := 1; strikes <= 4; strikes++ {
		got := cooldownFor(strikes, 0)
		if got <= previous {
			t.Errorf("strike %d waited %s, not longer than strike %d's %s", strikes, got, strikes-1, previous)
		}
		previous = got
	}
	if got := cooldownFor(20, 0); got > MaxRateLimitCooldown {
		t.Errorf("20 strikes waited %s, above the %s cap", got, MaxRateLimitCooldown)
	}
}

// TestOnlyOneRequestProbesTheHalfOpenWindow is the requirement that a rate limit
// must not be answered by releasing every waiting caller at once. 100 callers
// arrive the instant the cooldown expires; exactly one may touch the cloud.
func TestOnlyOneRequestProbesTheHalfOpenWindow(t *testing.T) {
	fixJitter(t, 0)
	sm := newSM()
	start := time.Now()
	sm.Record(rateLimited(0), start)

	afterCooldown := start.Add(RateLimitCooldown + time.Second)
	if sm.TryAcquire(start) {
		t.Fatal("acquired during the cooldown window")
	}

	const callers = 100
	var granted int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sm.TryAcquire(afterCooldown) {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if granted != 1 {
		t.Errorf("%d of %d callers were let through the half-open window, want exactly 1: "+
			"releasing them together is how a rate limit becomes a ban", granted, callers)
	}
}

func TestSuccessfulProbeReopensForEveryone(t *testing.T) {
	fixJitter(t, 0)
	sm := newSM()
	start := time.Now()
	sm.Record(rateLimited(0), start)
	after := start.Add(RateLimitCooldown + time.Second)

	if !sm.TryAcquire(after) {
		t.Fatal("the first caller after the cooldown should get the probe")
	}
	if sm.TryAcquire(after) {
		t.Fatal("a second caller acquired while the probe was in flight")
	}

	sm.RecordSuccess(after)

	for i := range 5 {
		if !sm.TryAcquire(after) {
			t.Errorf("caller %d refused after a successful probe; the breaker should be fully open", i)
		}
	}
	if sm.InRateLimitCooldown(after) {
		t.Error("still reported as rate-limited after a successful probe")
	}
}

func TestFailedProbeRecloses_Longer(t *testing.T) {
	fixJitter(t, 0)
	sm := newSM()
	start := time.Now()
	sm.Record(rateLimited(0), start)
	first := sm.RetryIn(start)

	after := start.Add(RateLimitCooldown + time.Second)
	if !sm.TryAcquire(after) {
		t.Fatal("expected the half-open probe to be granted")
	}
	sm.Record(rateLimited(0), after) // the probe was refused again

	second := sm.RetryIn(after)
	if second <= first {
		t.Errorf("second strike waits %s, not longer than the first's %s", second, first)
	}
	if sm.TryAcquire(after) {
		t.Error("acquired immediately after a failed probe; the window should have re-closed")
	}
}

// TestRateLimitDiagnosisIsDistinguishable underpins reporting a cooling-down set
// as upstream_quota_exceeded rather than upstream_auth_failed.
func TestRateLimitDiagnosisIsDistinguishable(t *testing.T) {
	fixJitter(t, 0)
	now := time.Now()

	limited := newSM()
	limited.Record(rateLimited(0), now)
	if !limited.InRateLimitCooldown(now) {
		t.Error("a 429'd minter does not report itself as rate-limited, so a caller would be told " +
			"its credentials are broken")
	}

	broken := newSM()
	broken.Record(Outcome{Status: http.StatusForbidden}, now)
	if broken.InRateLimitCooldown(now) {
		t.Error("a 403'd minter reports itself as rate-limited; that would tell a client to retry " +
			"a credential problem forever")
	}
}

// TestRevokeIsNotGatedByTheHalfOpenProbe: Selectable must stay observational.
// Holding a revoke behind a single-flight probe would defer the one operation
// whose deferral leaves a live credential nobody is tracking (the KI-002 class).
func TestRevokeIsNotGatedByTheHalfOpenProbe(t *testing.T) {
	fixJitter(t, 0)
	sm := newSM()
	start := time.Now()
	sm.Record(rateLimited(0), start)
	after := start.Add(RateLimitCooldown + time.Second)

	if !sm.TryAcquire(after) {
		t.Fatal("expected the probe to be granted")
	}
	if !sm.Selectable(after) {
		t.Error("Selectable is false while another caller holds the issuance probe; revoke and the " +
			"reconciler must not be blocked by it")
	}
}

// TestRecordHonoursTheCloudsRetryAfter drives a hint through the full path —
// Record, not just cooldownFor — because that is where a plugin's extracted
// Retry-After actually arrives, and dropping it there would be invisible to the
// unit test of the arithmetic.
func TestRecordHonoursTheCloudsRetryAfter(t *testing.T) {
	fixJitter(t, 0)
	sm := newSM()
	now := time.Now()
	const hint = 45 * time.Second

	sm.Record(rateLimited(hint), now)

	if got := sm.RetryIn(now); got != hint {
		t.Errorf("RetryIn is %s after a %s Retry-After, want %s: the cloud's number must reach the "+
			"cooldown, or honouring it is decorative", got, hint, hint)
	}
	if sm.TryAcquire(now.Add(hint - time.Second)) {
		t.Error("acquired one second before the cloud said we could")
	}
	if !sm.TryAcquire(now.Add(hint + time.Second)) {
		t.Error("still refused after the cloud's window elapsed")
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{"delta-seconds", "30", 30 * time.Second},
		{"http-date in the future", now.Add(45 * time.Second).UTC().Format(http.TimeFormat), 45 * time.Second},
		{"http-date in the past means now", now.Add(-time.Minute).UTC().Format(http.TimeFormat), 0},
		{"zero means now", "0", 0},
		{"negative means now, not a negative cooldown", "-5", 0},
		{"absent", "", 0},
		{"unparseable", "soon please", 0},
		{"whitespace tolerated", "  15  ", 15 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			header := http.Header{}
			if c.value != "" {
				header.Set("Retry-After", c.value)
			}
			if got := ParseRetryAfter(header, now); got != c.want {
				t.Errorf("ParseRetryAfter(%q) = %s, want %s", c.value, got, c.want)
			}
		})
	}
}

// TestNonIndictingOutcomeReleasesTheProbe is the regression guard for A18. The
// half-open window admits exactly one caller; if that caller's outcome is one the
// minter is not responsible for, the claim must come back immediately. Otherwise a
// single malformed request freezes a recovering minter for the whole ProbeGrace —
// the KI-010 exoneration and the circuit breaker, each correct alone, interacting.
func TestNonIndictingOutcomeReleasesTheProbe(t *testing.T) {
	fixJitter(t, 0)
	sm := newSM()
	start := time.Now()
	sm.Record(rateLimited(0), start)
	after := start.Add(RateLimitCooldown + time.Second)

	if !sm.TryAcquire(after) {
		t.Fatal("expected the half-open probe to be granted")
	}
	if sm.TryAcquire(after) {
		t.Fatal("a second caller acquired while the probe was in flight")
	}

	// A request the cloud rejected on its content: not the credential's fault.
	sm.Record(Outcome{Status: http.StatusBadRequest}, after)

	if !sm.TryAcquire(after) {
		t.Error("the half-open probe is still held after an outcome that does not indict the minter, " +
			"so a recovering minter stays unusable for the whole ProbeGrace (A18)")
	}
}
