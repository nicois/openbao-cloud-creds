package worker

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestNonPositiveIntervalDoesNotPanic is the regression guard for A2. The ticker
// is constructed in run(), outside invoke()'s recover, in a bare goroutine — so a
// persisted flush_interval=0 killed the plugin PROCESS and, because every plugin
// uses ServeMultiplex, every mount served by that binary with it. Durably, since
// Initialize re-runs startWorkers on each unseal and reload.
func TestNonPositiveIntervalDoesNotPanic(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			var mu sync.Mutex
			var reported error
			m := New(WithErrorHandler(func(_ string, err error) {
				mu.Lock()
				defer mu.Unlock()
				reported = err
			}))
			m.Register("poison", interval, Opts{}, func(_ context.Context) error { return nil })

			ctx, cancel := context.WithCancel(t.Context())
			m.Start(ctx)
			// Give run() the chance to reach the ticker; a panic here would take
			// the whole test binary down, which is exactly the production failure.
			time.Sleep(50 * time.Millisecond)
			cancel()
			m.Wait()

			mu.Lock()
			defer mu.Unlock()
			if reported == nil {
				t.Error("a non-positive interval was clamped silently; the operator gets no signal " +
					"that a configured interval is not runnable")
			}
		})
	}
}
