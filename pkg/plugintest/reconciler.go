package plugintest

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// reconcilePath and its modes are uniform across every plugin's API surface.
const (
	reconcilePath = "reconcile"
	fieldMode     = "mode"
	modeNormal    = "normal"
	modeDryRun    = "dry_run"
)

// RunReconcilerSafetySuite covers the load-bearing safety invariant: the
// reconciler may only ever delete entities matching the owner-tag scheme
// (`cloud-creds-<role>-` / `owner=cloud-creds`). Everything upstream that the
// plugin did not create must survive a pass, including a pass that deletes real
// orphans.
//
// That last clause is why assertReclaimsOnlyOwned exists. The suite used to plant
// its foreign entity with NO creation timestamp, which the fail-closed age guard
// skips *before* the prefix filter is consulted — so deleting the prefix filter
// outright left this category green, and DeleteEntity was never called once across
// ten clouds and seven categories (A9 in docs/audit-2026-08-22.md). A safety
// invariant asserted only over a pass that deletes nothing is not asserted at all.
//
// Asserted here rather than per plugin because the invariant is identical on every
// cloud while the entity being planted is not — the harness plants it, the suite
// decides what may happen to it.
func RunReconcilerSafetySuite(t *testing.T, h Harness) {
	t.Run("NeverDeletesForeignEntity", func(t *testing.T) { assertForeignEntitySurvives(t, h) })
	t.Run("DeletesOwnedOrphansAndOnlyThose", func(t *testing.T) { assertReclaimsOnlyOwned(t, h) })
	t.Run("DryRunDeletesNothing", func(t *testing.T) { assertDryRunDeletesNothing(t, h) })
	t.Run("TwoMountsDoNotDeleteEachOthers", func(t *testing.T) { assertMountsAreIsolated(t, h) })
}

// assertMountsAreIsolated is the end-to-end form of A19. The reclaim filter used to be
// the bare `cloud-creds-` prefix while the owned-set was a per-mount storage view, so
// two mounts against ONE cloud account each classified the other's LIVE credentials as
// orphans and deleted up to ten per pass, silently. decisions.md recommended multiple
// mounts as an isolation strategy.
//
// Both backends here share one fake — one cloud account — with separate storage, which
// is exactly the deployment shape that broke.
func assertMountsAreIsolated(t *testing.T, h Harness) {
	t.Helper()
	if h.SeedAgedOrphans == nil {
		t.Skipf("%s: no confirmable creation time is available for an upstream entity, so a "+
			"reclaiming pass cannot be driven here (A5)", h.Cloud)
	}

	// Mount A issues a credential and keeps its lease, so the credential is live.
	backendA, storageA := newConfiguredBackend(t, h)
	respA, err := issue(t, backendA, storageA, h.IssuePath)
	if err != nil || respA == nil || respA.IsError() {
		t.Fatalf("mount A issue failed: err=%v resp=%v", err, respA)
	}
	// Mount B is a second mount of the same plugin against the same upstream. Give it
	// a real orphan of its own so its pass genuinely deletes something.
	backendB, storageB := newConfiguredBackend(t, h)
	_, ownedByB := h.SeedAgedOrphans(t, storageB)

	// Counted AFTER seeding, since seeding itself adds entities: the question is what
	// mount B's pass changes, not what the setup did.
	before := h.ProvisionedCount()

	reconcile(t, backendB, storageB, modeNormal)

	if h.HasEntity(ownedByB) {
		t.Errorf("mount B did not reclaim its own orphan %q, so this test cannot show whether it "+
			"would have taken A's credential too", ownedByB)
	}
	if after := h.ProvisionedCount(); after != before-1 {
		t.Errorf("upstream count went %d -> %d across mount B's pass; expected exactly one deletion, "+
			"its own orphan. Anything more means mount B also took a credential belonging to mount A "+
			"— two mounts against one cloud account destroying each other's live credentials (A19)",
			before, after)
	}
}

func assertForeignEntitySurvives(t *testing.T, h Harness) {
	t.Helper()
	b, storage := newConfiguredBackend(t, h)

	// Issue once so the fake also holds an entity the plugin DOES own: a
	// reconciler that deleted everything it saw would otherwise pass by finding
	// nothing to delete.
	if resp, err := issue(t, b, storage, h.IssuePath); err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	id := h.SeedForeignEntity()
	resp := reconcile(t, b, storage, modeNormal)
	if !h.HasEntity(id) {
		t.Fatalf("reconciler deleted foreign entity %q — the owner-tag invariant is broken", id)
	}
	if orphans, ok := resp.Data["orphans_found"].(int); ok && orphans != 0 {
		t.Fatalf("foreign entity counted as an orphan: orphans_found=%d", orphans)
	}
}

// assertReclaimsOnlyOwned drives a pass that MUST delete something, and checks
// the foreign entity survives that same pass.
//
// Without a deleting pass, "the foreign entity survived" is equally satisfied by a
// reconciler that deletes nothing at all — which is the state Exoscale and Vultr
// are actually in (A5), and the state a removed prefix filter also produces.
func assertReclaimsOnlyOwned(t *testing.T, h Harness) {
	t.Helper()
	if h.SeedAgedOrphans == nil {
		t.Skipf("%s: this cloud can supply no confirmable creation time for an upstream entity, "+
			"neither from its list API nor from a mint ledger, so orphan reclamation cannot be "+
			"exercised (A5)", h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	if resp, err := issue(t, b, storage, h.IssuePath); err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	foreign, owned := h.SeedAgedOrphans(t, storage)
	resp := reconcile(t, b, storage, modeNormal)

	if h.HasEntity(owned) {
		t.Errorf("owner-prefixed orphan %q survived a normal reconcile pass. Either reclamation is "+
			"broken, or the confirmation hold rejected an entity that should have cleared it — "+
			"response: %v", owned, resp.Data)
	}
	if !h.HasEntity(foreign) {
		t.Errorf("reconciler deleted foreign entity %q while reclaiming a real orphan. THIS is the "+
			"owner-tag invariant, and this is the pass that tests it: the case above cannot, because "+
			"nothing is deleted in it", foreign)
	}
}

func assertDryRunDeletesNothing(t *testing.T, h Harness) {
	t.Helper()
	b, storage := newConfiguredBackend(t, h)
	if resp, err := issue(t, b, storage, h.IssuePath); err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	id := h.SeedForeignEntity()
	before := h.ProvisionedCount()
	resp := reconcile(t, b, storage, modeDryRun)
	if dry, ok := resp.Data["dry_run"].(bool); ok && !dry {
		t.Fatalf("reconcile with mode=dry_run reported dry_run=false: %v", resp.Data)
	}
	if !h.HasEntity(id) {
		t.Fatalf("dry-run reconcile deleted foreign entity %q", id)
	}
	if after := h.ProvisionedCount(); after != before {
		t.Fatalf("dry-run reconcile changed the upstream entity count: %d -> %d", before, after)
	}
}

func reconcile(t *testing.T, b logical.Backend, storage logical.Storage, mode string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: reconcilePath, Storage: storage,
		Data: map[string]interface{}{fieldMode: mode},
	})
	if err != nil {
		t.Fatalf("reconcile (%s) errored: %v", mode, err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("reconcile (%s) failed: %v", mode, resp)
	}
	return resp
}
