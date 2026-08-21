package plugintest

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// RunReloadSuite verifies a backend rehydrated from persisted storage (no
// config write) can still issue credentials, and that the persisted role keeps
// its minter-set binding. Catches KI-001: a config field set only in
// pathConfigWrite and never reloaded in Factory.
func RunReloadSuite(t *testing.T, h Harness) {
	t.Run("ReloadFromStorageThenIssue", func(t *testing.T) {
		_, storage := newConfiguredBackend(t, h)
		b2 := Reload(t, h, storage)
		resp, err := issue(t, b2, storage, h.IssuePath)
		if err != nil {
			t.Fatalf("issue after reload errored: %v", err)
		}
		if resp == nil || resp.IsError() {
			t.Fatalf("issue after reload failed (KI-001): %v", resp)
		}
		if resp.Data["credential"] == nil {
			t.Fatalf("issue after reload returned no credential: %v", resp.Data)
		}
	})

	t.Run("InitializeRehydratesAndIssues", func(t *testing.T) { assertInitializeRehydrates(t, h) })

	t.Run("ReloadPreservesRoleAndSet", func(t *testing.T) {
		_, storage := newConfiguredBackend(t, h)
		b2 := Reload(t, h, storage)
		resp := Read(t, b2, storage, h.RolePath)
		if resp == nil || resp.IsError() {
			t.Fatalf("role read after reload failed: %v", resp)
		}
		if resp.Data["minter_set"] != "default" {
			t.Fatalf("reloaded role lost minter_set binding: %v", resp.Data["minter_set"])
		}
	})
}

// assertInitializeRehydrates drives Initialize the way core does. Core calls it on
// a backend it has just built — after mount setup, an unseal, or a plugin reload —
// and that is where the background workers start (KI-007): a plugin with no
// InitializeFunc silently has no health checks, no metrics flush and no reconciler
// on a failed-over node. It is called twice here because an unseal after a reload
// does exactly that, and a plugin whose Initialize errors makes the mount unusable.
func assertInitializeRehydrates(t *testing.T, h Harness) {
	t.Helper()
	_, storage := newConfiguredBackend(t, h)
	b2 := Reload(t, h, storage)
	// Shutdown must still run once the test's context is cancelled — t.Context()
	// is already done by the time cleanups execute — so the teardown path gets an
	// uncancellable derivative rather than the test context.
	ctx := t.Context()
	t.Cleanup(func() { b2.Cleanup(context.WithoutCancel(ctx)) })
	if h.WorkersRunning != nil && h.WorkersRunning(b2) {
		t.Error("workers were already running before Initialize. They must start in Initialize, not " +
			"Factory: Factory also runs for config-less constructions that must not touch the network")
	}
	for pass := range 2 {
		if err := b2.Initialize(ctx, &logical.InitializationRequest{Storage: storage}); err != nil {
			t.Fatalf("Initialize (pass %d) failed, which would fail the mount: %v", pass, err)
		}
		if h.WorkersRunning != nil && !workersStarted(t, h, b2) {
			t.Fatalf("no background workers are running after Initialize (pass %d). This is what KI-007 "+
				"was: a rehydrated backend issues credentials happily while nothing health-checks, "+
				"flushes metrics or reconciles — and since a successful health check is the ONLY exit "+
				"from AuthFailing, one transient blip then withdraws a minter permanently", pass)
		}
	}
	mustIssue(t, b2, storage, h.IssuePath)
}

// workersStarted polls, because Initialize deliberately does not block on worker
// startup (`go b.startWorkers(...)`): core is waiting on Initialize, and a mount
// should not be held up by it. Sampling once would make this assertion a race.
func workersStarted(t *testing.T, h Harness, b logical.Backend) bool {
	t.Helper()
	deadline := time.Now().Add(workerStartTimeout)
	for time.Now().Before(deadline) {
		if h.WorkersRunning(b) {
			return true
		}
		time.Sleep(workerStartPoll)
	}
	return false
}

// workerStartTimeout is generous relative to the work involved (build a manager,
// register a handful of tickers) so this cannot flake on a loaded CI machine,
// while still failing fast when nothing starts at all.
const (
	workerStartTimeout = 5 * time.Second
	workerStartPoll    = 10 * time.Millisecond
)
