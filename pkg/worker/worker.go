package worker

import (
	"context"
	"sync"
	"time"
)

type WorkerFunc func(ctx context.Context) error

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
}

func New() *Manager {
	return &Manager{}
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
			_ = w.fn(ctx)
		}
	}
}
