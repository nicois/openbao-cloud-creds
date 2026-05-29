package worker_test

import (
	"context"
	"fmt"
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
