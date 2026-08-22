package worker

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type WorkerFunc func(ctx context.Context) error

// ErrorHandler is called when a worker tick returns an error or panics.
type ErrorHandler func(worker string, err error)

// Option configures a Manager.
type Option func(*Manager)

// WithErrorHandler sets the handler invoked on a worker error or recovered panic.
func WithErrorHandler(h ErrorHandler) Option {
	return func(m *Manager) { m.errHandler = h }
}

type Opts struct {
	InitialDelay time.Duration
}

type registration struct {
	name     string
	interval time.Duration
	opts     Opts
	fn       WorkerFunc
}

// fallbackInterval is used when a registration's interval is non-positive. It is
// deliberately slow: the situation is a misconfiguration, and a fast fallback
// would hammer an upstream while looking healthy.
const fallbackInterval = 15 * time.Minute

type Manager struct {
	mu      sync.Mutex
	workers []registration
	wg      sync.WaitGroup
	running bool
	// errHandler is set once via options in New (before Start) and only read by run goroutines thereafter; do not mutate after Start.
	errHandler ErrorHandler
}

func New(opts ...Option) *Manager {
	m := &Manager{}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *Manager) Register(name string, interval time.Duration, opts Opts, fn WorkerFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workers = append(m.workers, registration{
		name:     name,
		interval: interval,
		opts:     opts,
		fn:       fn,
	})
}

func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = true
	for _, w := range m.workers {
		m.wg.Add(1)
		go m.run(ctx, w)
	}
}

func (m *Manager) Wait() {
	m.wg.Wait()
	m.markStopped()
}

// DrainTimeout bounds how long a shutdown waits for in-flight ticks. It is above a
// plugin's 30s upstream HTTP timeout, so an ordinary in-flight call has time to
// notice its cancelled context, and short enough that a call which does NOT notice
// cannot hold the caller indefinitely.
const DrainTimeout = 35 * time.Second

// WaitFor drains like Wait but gives up after timeout, reporting whether the drain
// completed.
//
// The caller is framework.Backend.Clean, which the SDK invokes while holding a
// process-wide lock — so an unbounded wait there stalls every OTHER mount in the
// multiplexed binary behind one mount's in-flight HTTP call (A29 in
// docs/audit-2026-08-22.md). Returning early is safe: the worker context is already
// cancelled, the goroutines are on their way out, and every storage write they
// could still attempt fails against a cancelled context.
func (m *Manager) WaitFor(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		m.markStopped()
		return true
	case <-time.After(timeout):
		return false
	}
}

func (m *Manager) markStopped() {
	m.mu.Lock()
	m.running = false
	m.mu.Unlock()
}

func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *Manager) run(ctx context.Context, w registration) {
	defer m.wg.Done()

	if w.opts.InitialDelay > 0 {
		select {
		case <-time.After(w.opts.InitialDelay):
		case <-ctx.Done():
			return
		}
	}

	// Clamp defensively. time.NewTicker panics on a non-positive interval, and
	// this line is outside invoke's recover, in a bare goroutine — so a persisted
	// flush_interval=0 killed the plugin PROCESS, taking every mount in the
	// multiplexed binary with it, durably across restarts because Initialize
	// re-runs startWorkers (A2 in docs/audit-2026-08-22.md).
	//
	// Callers validate at config write, which is where an operator gets told they
	// are wrong. This is the seam every plugin already funnels through, so the
	// guard lives here as well: the audit's cross-cutting finding was that guards
	// get applied at one site and not generalised.
	interval := w.interval
	if interval <= 0 {
		interval = fallbackInterval
		if m.errHandler != nil {
			m.errHandler(w.name, fmt.Errorf(
				"non-positive interval %s is not runnable; falling back to %s. A worker interval must be "+
					"positive — fix the config field that produced it", w.interval, interval))
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.invoke(ctx, w); err != nil && m.errHandler != nil {
				m.errHandler(w.name, err)
			}
		}
	}
}

func (m *Manager) invoke(ctx context.Context, w registration) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("worker %q panicked: %v", w.name, r)
		}
	}()
	return w.fn(ctx)
}
