package credentialdo

import (
	"testing"
	"time"
)

// The reconciler's hold-off must be measured from a restart, not re-armed by every
// write. startWorkers re-runs on every config write, every minter-set write and
// every plugin reload, and the delay used to be passed straight through — so a
// write every 23h re-armed a 24h delay forever and the orphan backstop, the last
// line of defence against a leaked upstream credential, never ran once (A29).
//
// Asserted on this plugin because it is the code-shape reference and the helper is
// identical in all ten; what differs per plugin is only the struct it hangs off.
func TestRemainingBootstrapDelayIsAnchoredToProcessStart(t *testing.T) {
	b := &backend{}

	first := b.remainingBootstrapDelay(time.Hour)
	if first <= 0 || first > time.Hour {
		t.Fatalf("the first call should hold off for about the whole delay, got %s", first)
	}

	// Simulate the process having been up for most of the delay, then another write
	// arriving. The remaining hold-off must have shrunk, not reset.
	b.mu.Lock()
	b.bootstrapAt = time.Now().Add(-59 * time.Minute)
	b.mu.Unlock()

	second := b.remainingBootstrapDelay(time.Hour)
	if second > 2*time.Minute {
		t.Errorf("a later write re-armed the hold-off to %s. A write more often than the delay then "+
			"defers the reconciler forever", second)
	}

	// Once the delay has elapsed, a restart of the workers must not introduce a new one.
	b.mu.Lock()
	b.bootstrapAt = time.Now().Add(-2 * time.Hour)
	b.mu.Unlock()

	if got := b.remainingBootstrapDelay(time.Hour); got != 0 {
		t.Errorf("past the hold-off, the reconciler should start on its next tick; got a delay of %s", got)
	}
}
