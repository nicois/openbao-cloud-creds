package plugintest

import (
	"bytes"
	"context"
	"encoding/json"
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

	t.Run("InvalidPersistedSetIsNotLoaded", func(t *testing.T) { assertInvalidPersistedSetIsRefused(t, h) })

	t.Run("SetFromANewerSchemaIsNotLoaded", func(t *testing.T) { assertFutureSchemaSetIsRefused(t, h) })

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

// assertInvalidPersistedSetIsRefused: validation belonged at config LOAD as well as
// at config write, and was only at write.
//
// OBC-005 calls an invalid minter set a hard config-load failure, but every plugin
// registered whatever was persisted — so a set that no write would accept today was
// loaded fail-OPEN and issued from. That is reachable without anyone doing anything
// exotic: a version-skewed binary that does not know a field drops it on the next
// whole-struct write (A30), and RSK-005's whole point is that a set which has
// quietly become single-minter is the failure nobody notices until the minter dies.
//
// The set is broken here the way either of those would break it — through storage,
// not through the API — because the API is exactly the path that already refuses it.
func assertInvalidPersistedSetIsRefused(t *testing.T, h Harness) {
	t.Helper()
	if h.IssuesFromPreprovisionedSlots {
		t.Skipf("%s: a credential read serves a slot provisioned earlier and selects no minter, so "+
			"refusing to load an invalid set stops the next ROTATION rather than the next read — the "+
			"load-time refusal itself is shared code and is asserted by the nine JIT clouds", h.Cloud)
	}
	_, storage := newConfiguredBackend(t, h)

	entry, err := storage.Get(t.Context(), h.SetPath)
	if err != nil || entry == nil {
		t.Fatalf("could not read the persisted minter set at %q: err=%v entry=%v", h.SetPath, err, entry)
	}
	var set map[string]interface{}
	if err := json.Unmarshal(entry.Value, &set); err != nil {
		t.Fatalf("persisted minter set is not JSON: %v", err)
	}
	minters, ok := set["minters"].([]interface{})
	if !ok || len(minters) == 0 {
		t.Fatalf("persisted minter set holds no minters: %v", set)
	}
	first, ok := minters[0].(map[string]interface{})
	if !ok {
		t.Fatalf("minters[0] is %T, want an object", minters[0])
	}
	// One EXPIRING minter and nothing else: the exact shape the (>=1 never_expires)
	// OR (>=2 with a >=7d gap) rule exists to reject, with the credential material
	// left untouched so the only thing wrong is the set's composition.
	delete(first, "never_expires")
	first["expires_at"] = time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	set["minters"] = []interface{}{first}

	value, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("could not re-encode the minter set: %v", err)
	}
	if err := storage.Put(t.Context(), &logical.StorageEntry{Key: h.SetPath, Value: value}); err != nil {
		t.Fatalf("could not write the broken minter set back: %v", err)
	}

	b2 := Reload(t, h, storage)
	resp, err := issue(t, b2, storage, h.IssuePath)
	if err == nil && resp != nil && !resp.IsError() {
		t.Fatalf("a reloaded backend issued a credential from a minter set that violates RSK-005: "+
			"%v. An invalid set must not be registered — the operator has to be told to rewrite it, "+
			"not served from it", resp.Data)
	}
}

// assertFutureSchemaSetIsRefused: an entry written by a NEWER binary must not be
// loaded by this one.
//
// Every mutation here is read-struct → change → write the whole struct back, and
// encoding/json drops what it does not know — so an older binary silently ERASES a
// field a newer one added. On a minter set that is A13 by version skew: losing
// retired/retired_at un-retires a rotated-out minter, cancelling the sweep that was
// going to delete its upstream credential and returning a replaced minter to the
// selection pool. Refusing to touch the entry leaves it intact and tells the
// operator which node to upgrade (A30).
func assertFutureSchemaSetIsRefused(t *testing.T, h Harness) {
	t.Helper()
	if h.IssuesFromPreprovisionedSlots {
		t.Skipf("%s: a credential read serves a slot provisioned earlier and selects no minter, so "+
			"declining to load a set is not observable at the read path — the refusal is shared code "+
			"and is asserted by the nine JIT clouds", h.Cloud)
	}
	_, storage := newConfiguredBackend(t, h)

	entry, err := storage.Get(t.Context(), h.SetPath)
	if err != nil || entry == nil {
		t.Fatalf("could not read the persisted minter set at %q: err=%v entry=%v", h.SetPath, err, entry)
	}
	var set map[string]interface{}
	if err := json.Unmarshal(entry.Value, &set); err != nil {
		t.Fatalf("persisted minter set is not JSON: %v", err)
	}
	// A version from the future, plus a field this binary knows nothing about — which
	// is the thing a whole-struct rewrite would destroy.
	set["schema_version"] = 9999
	set["a_field_this_binary_does_not_know"] = "must survive"

	value, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("could not re-encode the minter set: %v", err)
	}
	if err := storage.Put(t.Context(), &logical.StorageEntry{Key: h.SetPath, Value: value}); err != nil {
		t.Fatalf("could not write the future-schema minter set back: %v", err)
	}

	b2 := Reload(t, h, storage)
	if resp, issueErr := issue(t, b2, storage, h.IssuePath); issueErr == nil && resp != nil && !resp.IsError() {
		t.Fatalf("a backend that does not understand the persisted schema issued a credential from it "+
			"anyway: %v. The next write of that set would erase whatever the newer binary put there",
			resp.Data)
	}

	// And the entry itself must be untouched: refusing means refusing to write, too.
	after, err := storage.Get(t.Context(), h.SetPath)
	if err != nil || after == nil {
		t.Fatalf("the minter set went missing: err=%v", err)
	}
	if !bytes.Contains(after.Value, []byte("a_field_this_binary_does_not_know")) {
		t.Errorf("the unknown field was erased from the persisted set, which is the exact damage the "+
			"version check exists to prevent: %s", after.Value)
	}
}
