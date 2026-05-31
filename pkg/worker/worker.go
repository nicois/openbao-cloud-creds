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

	ticker := time.NewTicker(w.interval)
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
