package worker_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/worker"
)

// TestWorkerTicks runs under testing/synctest so the clock is fake and advances
// deterministically. run() uses time.NewTicker(interval) with no initial delay,
// so ticks fire at t=interval, 2*interval, ... (first tick at the END of the
// first interval, never at t=0). invoke() calls fn inline in the run goroutine,
// so after synctest.Wait() returns (all bubble goroutines durably blocked) the
// count is fully settled. Advancing 5 full 10ms intervals yields exactly 5 ticks.
func TestWorkerTicks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var count atomic.Int32
		wm := worker.New()
		wm.Register("counter", 10*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
			count.Add(1)
			return nil
		})

		ctx, cancel := context.WithCancel(context.Background())
		wm.Start(ctx)

		// Advance the fake clock by 5 full intervals. Each Sleep+Wait lands
		// exactly on a tick boundary (t=10,20,30,40,50ms), so we observe one
		// tick per iteration: exactly 5 total.
		for range 5 {
			time.Sleep(10 * time.Millisecond)
			synctest.Wait()
		}

		cancel()
		wm.Wait()

		if got := count.Load(); got != 5 {
			t.Fatalf("expected exactly 5 ticks, got %d", got)
		}
	})
}

// TestWorkerInitialDelay verifies run()'s InitialDelay handling under synctest.
// run() first blocks on time.After(InitialDelay); only then does it create the
// ticker. So with a 30ms delay and 10ms interval, ticks fire at t=40,50,60ms
// (delay ends at 30ms, first tick one interval later). At t=25ms (still inside
// the delay) the count must be 0; at t=40ms exactly one tick has fired.
func TestWorkerInitialDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var count atomic.Int32
		wm := worker.New()
		wm.Register("delayed", 10*time.Millisecond, worker.Opts{InitialDelay: 30 * time.Millisecond}, func(ctx context.Context) error {
			count.Add(1)
			return nil
		})

		ctx, cancel := context.WithCancel(context.Background())
		wm.Start(ctx)

		// t=25ms: still inside the 30ms initial delay, no ticks yet.
		time.Sleep(25 * time.Millisecond)
		synctest.Wait()
		if got := count.Load(); got != 0 {
			t.Fatalf("expected 0 ticks during initial delay, got %d", got)
		}

		// t=40ms: delay ended at 30ms, ticker started, first tick at t=40ms.
		time.Sleep(15 * time.Millisecond)
		synctest.Wait()
		if got := count.Load(); got != 1 {
			t.Fatalf("expected exactly 1 tick at t=40ms, got %d", got)
		}

		cancel()
		wm.Wait()
	})
}

func TestWorkerStopDrainsCleanly(t *testing.T) {
	wm := worker.New()
	wm.Register("noop", 10*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	wm.Start(ctx)
	time.Sleep(20 * time.Millisecond)
	cancel()
	wm.Wait()

	if wm.Running() {
		t.Fatal("expected not running after Wait")
	}
}

func TestWorkerErrorDoesNotCrash(t *testing.T) {
	var count atomic.Int32
	wm := worker.New()
	wm.Register("failer", 10*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		count.Add(1)
		return fmt.Errorf("oops")
	})

	ctx, cancel := context.WithCancel(context.Background())
	wm.Start(ctx)
	time.Sleep(35 * time.Millisecond)
	cancel()
	wm.Wait()

	if count.Load() < 2 {
		t.Fatalf("worker should keep ticking after errors, got %d", count.Load())
	}
}

func TestWorker_ErrorHandlerInvokedOnError(t *testing.T) {
	var mu sync.Mutex
	var gotName string
	var gotErr error
	h := func(name string, err error) {
		mu.Lock()
		gotName, gotErr = name, err
		mu.Unlock()
	}
	m := worker.New(worker.WithErrorHandler(h))
	m.Register("failer", 5*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		return fmt.Errorf("boom")
	})
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	cancel()
	m.Wait()
	mu.Lock()
	defer mu.Unlock()
	if gotName != "failer" {
		t.Fatalf("expected failer, got %q", gotName)
	}
	if gotErr == nil || gotErr.Error() != "boom" {
		t.Fatalf("expected boom, got %v", gotErr)
	}
}

func TestWorker_PanicRecoveredAndReported(t *testing.T) {
	var mu sync.Mutex
	var calls int
	var lastErr error
	h := func(name string, err error) {
		mu.Lock()
		calls++
		lastErr = err
		mu.Unlock()
	}
	m := worker.New(worker.WithErrorHandler(h))
	m.Register("panicker", 5*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		panic("kaboom")
	})
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	cancel()
	m.Wait()
	mu.Lock()
	defer mu.Unlock()
	if calls == 0 {
		t.Fatal("expected panic reported via handler")
	}
	if lastErr == nil || !strings.Contains(lastErr.Error(), "panicked") {
		t.Fatalf("expected panicked error, got %v", lastErr)
	}
}

func TestWorker_NilHandlerStillRecoversPanic(t *testing.T) {
	var ticks int32
	m := worker.New() // no handler
	m.Register("panicker", 5*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		panic("kaboom")
	})
	m.Register("counter", 5*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		atomic.AddInt32(&ticks, 1)
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	time.Sleep(40 * time.Millisecond)
	cancel()
	m.Wait()
	if atomic.LoadInt32(&ticks) == 0 {
		t.Fatal("counter should keep ticking despite sibling panic")
	}
}

// TestConcurrentStartWaitCycles mimics a backend that restarts its workers on
// every config/minter-set write. Each goroutine uses its OWN manager, so this
// guards that a single manager's Start -> cancel -> Wait sequence is race-free.
// Run with -race to catch WaitGroup Add/Wait interleaving regressions.
func TestConcurrentStartWaitCycles(t *testing.T) {
	var wgOuter sync.WaitGroup
	for i := 0; i < 50; i++ {
		wgOuter.Add(1)
		go func() {
			defer wgOuter.Done()
			m := worker.New()
			m.Register("noop", time.Hour, worker.Opts{}, func(ctx context.Context) error { return nil })
			ctx, cancel := context.WithCancel(context.Background())
			m.Start(ctx)
			cancel()
			m.Wait()
		}()
	}
	wgOuter.Wait()
}
