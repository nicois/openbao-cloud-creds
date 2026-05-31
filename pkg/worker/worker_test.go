package worker_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/worker"
)

func TestWorkerTicks(t *testing.T) {
	var count atomic.Int32
	wm := worker.New()
	wm.Register("counter", 10*time.Millisecond, worker.Opts{}, func(ctx context.Context) error {
		count.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	wm.Start(ctx)
	time.Sleep(55 * time.Millisecond)
	cancel()
	wm.Wait()

	got := count.Load()
	if got < 4 || got > 6 {
		t.Fatalf("expected ~5 ticks, got %d", got)
	}
}

func TestWorkerInitialDelay(t *testing.T) {
	var count atomic.Int32
	wm := worker.New()
	wm.Register("delayed", 10*time.Millisecond, worker.Opts{InitialDelay: 30 * time.Millisecond}, func(ctx context.Context) error {
		count.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	wm.Start(ctx)
	time.Sleep(25 * time.Millisecond)

	if count.Load() != 0 {
		t.Fatalf("expected 0 ticks during delay, got %d", count.Load())
	}

	time.Sleep(30 * time.Millisecond)
	cancel()
	wm.Wait()

	got := count.Load()
	if got < 1 {
		t.Fatalf("expected >=1 ticks after delay, got %d", got)
	}
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
