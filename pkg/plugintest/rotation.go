package plugintest

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// RunRotationSuite covers a credential that is SHARED by every reader and replaced on a
// schedule, rather than minted per lease.
//
// It exists because that lifecycle inverts three assumptions the other categories are built
// on. A read does not mint; a lease ending must not delete anything, or one client's expiry
// cuts off every other holder; and the credential's life is decided by the plugin's own
// schedule rather than by any lease. Nothing in the per-lease categories can catch a
// regression in any of those — a plugin that minted per read, or deleted on revoke, would
// pass all nine of them while breaking every client of a shared credential.
//
// The window it guards is the overlap. A credential with no upstream expiry can only be
// rotated by creating its replacement and then deleting it, so there is necessarily a period
// in which both are live. Both halves are asserted: the replaced credential must keep working
// through the overlap (or a client holding it fails before its lease was up), and it must be
// gone afterwards (or a rotation is a credential leak with extra steps).
//
// Time is not waited for. The periods involved are days, and a fake clock would prove the
// suite's own arithmetic; the harness instead backdates the stored deadlines — the same
// durable state a restart rehydrates — and then makes the ordinary call.
func RunRotationSuite(t *testing.T, h Harness) {
	for _, c := range []struct {
		name string
		run  func(*testing.T, Harness)
	}{
		{"EveryReadServesTheSameCredential", rotSameCredentialEveryRead},
		{"ALeaseIsNotRenewable", rotLeaseIsNotRenewable},
		{"ALeaseCannotOutlastTheOverlap", rotLeaseFitsInTheOverlap},
		{"EndingOneLeaseLeavesTheCredentialForEveryoneElse", rotRevokeDeletesNothing},
		{"AnOverdueCredentialIsReplacedOnTheNextRead", rotOverdueIsReplaced},
		{"TheReplacedCredentialKeepsWorkingThroughTheOverlap", rotReplacedSurvivesTheOverlap},
		{"TheReplacedCredentialIsDeletedOnceTheOverlapHasPassed", rotReplacedIsDeletedAfterwards},
		{"AnOverdueCredentialIsStillServedWhileTheRotationFails", rotOverdueServedWhenRotationFails},
		{"PastTheAgeTheRolePromisesTheReadIsRefused", rotPastTheCeilingIsRefused},
	} {
		t.Run(c.name, func(t *testing.T) { c.run(t, h) })
	}
}

// rotSameCredentialEveryRead is the defining property. A client re-reads before its lease
// expires and gets the credential it already has, which is what lets a fleet share one
// credential against a per-account cap.
//
// The count is asserted as well as the identity, because the identity alone would also be
// satisfied by a plugin that minted a credential per read and happened to return the first
// one's id — and it is the count that the account cap is spent on.
func rotSameCredentialEveryRead(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	before := h.ProvisionedCount()

	first := servedCredentialID(t, b, storage, h)
	if got := h.ProvisionedCount(); got != before+1 {
		t.Fatalf("the cloud holds %d credentials after the first read, want %d: the first read has "+
			"to provision the shared credential or the rest of this case proves nothing", got, before+1)
	}

	const reads = 4
	for i := range reads {
		if again := servedCredentialID(t, b, storage, h); again != first {
			t.Fatalf("read %d served credential %q where the first served %q. Every reader of this "+
				"role holds one credential; a read that mints its own means a client's lease bounds "+
				"nothing and the account cap is spent per reader", i+2, again, first)
		}
	}
	if got := h.ProvisionedCount(); got != before+1 {
		t.Errorf("%d reads left the cloud holding %d credentials, want %d. The ids matched, so each "+
			"read served the right key while provisioning another one nothing will ever delete",
			reads+1, got, before+1)
	}
}

// rotLeaseIsNotRenewable: the credential's life is decided by the rotation schedule, so a
// lease against it must not be extendable.
//
// Asserted positively here rather than left to the lease category, which only checks that the
// envelope and the lease AGREE. A renewal that succeeded would push a lease past the moment
// its credential is deleted, which is the one thing no plugin is allowed to do (techrfc
// OBC-002) — and because framework.Secret.Renewable() is (Renew != nil), the way to get this
// wrong is to reuse the per-lease secret type rather than to write anything.
func rotLeaseIsNotRenewable(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil || resp == nil || resp.IsError() || resp.Secret == nil {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}
	if resp.Secret.Renewable {
		t.Errorf("the lease advertises renewable=true. Its credential is deleted on the role's own " +
			"schedule, so a renewal that core honours hands the client a lease outliving the " +
			"credential it names")
	}
	if renewable, ok := resp.Data["renewable"].(bool); ok && renewable {
		t.Errorf("the envelope tells the client renewable=true, so a client that renews rather than " +
			"re-reads never picks up the replacement")
	}
}

// rotLeaseFitsInTheOverlap: no lease may be longer than the shortest life the served
// credential is guaranteed.
//
// That guarantee is the overlap, and it is the worst case rather than the typical one: a read
// answered a moment before the credential rotates leaves the client holding one that will be
// deleted overlap_ttl later. A TTL within the overlap is therefore what makes the schedule
// safe for every reader, however unlucky their timing — and it is checked here rather than
// only at role write because a plugin that clamped nothing would still pass a role-write test.
func rotLeaseFitsInTheOverlap(t *testing.T, h Harness) {
	if h.RotationOverlapTTL <= 0 {
		t.Fatalf("%s: the harness declares no RotationOverlapTTL, so the bound every lease on a "+
			"shared credential has to respect is unstated", h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil || resp == nil || resp.IsError() || resp.Secret == nil {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	if resp.Secret.TTL > h.RotationOverlapTTL {
		t.Errorf("the lease TTL is %s, longer than the %s overlap. A client reading just before a "+
			"rotation would hold a lease for %s after its credential was deleted",
			resp.Secret.TTL, h.RotationOverlapTTL, resp.Secret.TTL-h.RotationOverlapTTL)
	}
	seconds, ok := resp.Data["ttl_seconds"].(int)
	if !ok {
		t.Fatalf("the envelope's ttl_seconds is %v (%T), which a client cannot read as a duration",
			resp.Data["ttl_seconds"], resp.Data["ttl_seconds"])
	}
	if got := time.Duration(seconds) * time.Second; got > h.RotationOverlapTTL {
		t.Errorf("the envelope promises the client %s, longer than the %s overlap", got,
			h.RotationOverlapTTL)
	}
}

// rotRevokeDeletesNothing: one reader's lease ending must leave the credential alone.
//
// This is the assumption a shared credential inverts most sharply, and the failure is not
// subtle: reusing the per-lease revoke would delete a credential every other reader is still
// using, at whatever moment the first of them happened to stop renewing. The next read is
// checked too, because a plugin that deleted the credential and then re-minted on demand
// would keep the count right while every holder's copy stopped working.
func rotRevokeDeletesNothing(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	before := h.ProvisionedCount()

	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil || resp == nil || resp.IsError() || resp.Secret == nil {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}
	served := credentialID(t, resp)

	if r, e := revokeSecret(t, b, storage, h.IssuePath, resp.Secret); e != nil || (r != nil && r.IsError()) {
		t.Fatalf("revoke failed: err=%v resp=%v", e, r)
	}

	if got := h.ProvisionedCount(); got != before+1 {
		t.Errorf("the cloud holds %d credentials after one lease was revoked, want %d. The "+
			"credential is shared, so deleting it when one reader's lease ends breaks every other "+
			"reader at a moment none of them can predict", got, before+1)
	}
	if again := servedCredentialID(t, b, storage, h); again != served {
		t.Errorf("after a lease revoke the role serves %q where it served %q. Whether it was deleted "+
			"and re-minted or merely forgotten, every client still holding the old one is broken",
			again, served)
	}
}

// rotOverdueIsReplaced: the schedule is honoured on the read path, so a role that is read is
// rotated whether or not any background worker ran.
func rotOverdueIsReplaced(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	before := h.ProvisionedCount()
	old := servedCredentialID(t, b, storage, h)

	forceRotationDue(t, h, b, storage)

	replacement := servedCredentialID(t, b, storage, h)
	if replacement == old {
		t.Fatalf("a credential past its rotation age is still being served (%q). Nothing else bounds "+
			"it: the cloud gives it no expiry, so the schedule is the only thing that ever replaces "+
			"it", old)
	}
	if got := h.ProvisionedCount(); got != before+2 {
		t.Errorf("the cloud holds %d credentials after a rotation, want %d: one replacement and the "+
			"credential it replaced, which is still inside its overlap", got, before+2)
	}
}

// rotReplacedSurvivesTheOverlap: the whole point of the overlap.
//
// A rotation cannot be atomic — the cloud has no way to hand out a replacement and expire the
// original in one call — so the clients holding the original have to keep working until they
// next read. Deleting it at rotation time would fail every one of them, and they would have
// no way to tell that from a leak.
//
// The sweep is run deliberately: it is the only thing that ever deletes a retired credential,
// so a sweep that ignored the deadline would be indistinguishable from an atomic rotation.
func rotReplacedSurvivesTheOverlap(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	before := h.ProvisionedCount()
	old := servedCredentialID(t, b, storage, h)

	forceRotationDue(t, h, b, storage)
	if replacement := servedCredentialID(t, b, storage, h); replacement == old {
		t.Fatalf("the credential was not rotated, so there is no retired one to keep alive")
	}

	sweep(t, h, b, storage)

	if got := h.ProvisionedCount(); got != before+2 {
		t.Errorf("the cloud holds %d credentials after a sweep inside the overlap, want %d: the "+
			"replaced credential was deleted early, and every client still holding it is now failing "+
			"against the cloud with a lease that has not expired", got, before+2)
	}
	if h.HasEntity != nil && !h.HasEntity(old) {
		t.Errorf("the replaced credential %q is gone from the cloud although its %s overlap has not "+
			"passed", old, h.RotationOverlapTTL)
	}
}

// rotReplacedIsDeletedAfterwards: the other half. An overlap that never ends is a leak, and on
// a cloud whose credential has no expiry of its own it is a permanent one — the sweep is the
// only thing that will ever delete it.
func rotReplacedIsDeletedAfterwards(t *testing.T, h Harness) {
	b, storage := newConfiguredBackend(t, h)
	before := h.ProvisionedCount()
	old := servedCredentialID(t, b, storage, h)

	forceRotationDue(t, h, b, storage)
	replacement := servedCredentialID(t, b, storage, h)
	if replacement == old {
		t.Fatalf("the credential was not rotated, so there is no retired one to delete")
	}

	forceOverlapExpired(t, h, b, storage)
	sweep(t, h, b, storage)

	if got := h.ProvisionedCount(); got != before+1 {
		t.Errorf("the cloud holds %d credentials after the overlap passed and a sweep ran, want %d. "+
			"A replaced credential nothing deletes stays usable by whoever copied it, and this "+
			"cloud gives it no expiry of its own", got, before+1)
	}
	if h.HasEntity != nil && h.HasEntity(old) {
		t.Errorf("the replaced credential %q is still live on the cloud after its overlap passed", old)
	}
	if again := servedCredentialID(t, b, storage, h); again != replacement {
		t.Errorf("after the sweep the role serves %q where it served %q: the sweep took the live "+
			"credential rather than the retired one", again, replacement)
	}
}

// servedCredentialID reads the issuing path and returns the id of the credential it served.
// Read from the envelope rather than from storage, because it is what a client compares to
// decide whether it has anything new to install.
// rotOverdueServedWhenRotationFails: a rotation that CANNOT happen must not cost a client the
// credential it already holds.
//
// The credential is shared, it has no upstream expiry, and the reader had a working copy of it a
// moment ago — so an upstream fault at the instant the key comes due changes nothing about the
// credential itself. Refusing the read denies a client a credential that works, and denies it again
// on every subsequent read for as long as the cloud is unreachable. The window is bounded, which is
// what the next case asserts; inside it, the answer is the credential.
func rotOverdueServedWhenRotationFails(t *testing.T, h Harness) {
	if h.DenyMint == nil || h.AllowMint == nil {
		t.Skipf("%s declares no mint-refusal knob, so a FAILING rotation cannot be produced", h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	served := servedCredentialID(t, b, storage, h)
	// Counted AFTER the first read, which is what mints the role's credential: the number this
	// case is about is what a FAILED rotation adds to a mount that already has one.
	before := h.ProvisionedCount()

	forceRotationDue(t, h, b, storage)
	h.DenyMint()
	t.Cleanup(h.AllowMint)

	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil {
		t.Fatalf("reading %s returned a transport error: %v", h.IssuePath, err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("a read was refused because the ROTATION failed, while a working credential sat "+
			"in storage unreturned: %v", resp)
	}
	if got := credentialID(t, resp); got != served {
		t.Errorf("the read served %q, want the credential the role already had (%q): a failed "+
			"rotation must fall back to what exists, not invent something", got, served)
	}
	if got := h.ProvisionedCount(); got != before {
		t.Errorf("the cloud holds %d credentials after a FAILED rotation, want %d: a refusal "+
			"upstream must leave nothing behind", got, before)
	}
	// The client is told, because it is holding a credential whose replacement is overdue and
	// whose window is closing — which is invisible from a successful response otherwise.
	if len(resp.Warnings) == 0 {
		t.Errorf("the response carries no warning, so a client cannot tell it was served an " +
			"overdue credential on a failing rotation")
	}

	// And the fallback is not a new steady state: once the cloud recovers, the next read rotates.
	h.AllowMint()
	if got := servedCredentialID(t, b, storage, h); got == served {
		t.Errorf("the credential was still %q after the cloud recovered: the fallback has to end "+
			"at the first successful rotation, or the key never rotates again", got)
	}
}

// rotPastTheCeilingIsRefused: the fallback above is a WINDOW, not a licence.
//
// A rotation period reads as a promise about the maximum age of a credential — which is why the
// jitter is subtracted rather than added — so serving indefinitely because rotation keeps failing
// would quietly convert "rotate every 90 days" into "rotate when the cloud lets us". Past the age
// the role promises, the read is refused and the operator is left with an unambiguous failure
// rather than a credential older than their policy allows.
func rotPastTheCeilingIsRefused(t *testing.T, h Harness) {
	if h.DenyMint == nil || h.AllowMint == nil {
		t.Skipf("%s declares no mint-refusal knob, so a FAILING rotation cannot be produced", h.Cloud)
	}
	if h.ForcePastRotationCeiling == nil {
		t.Skipf("%s declares no ForcePastRotationCeiling, so the far side of the window cannot be "+
			"reached; the case inside the window still runs", h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	servedCredentialID(t, b, storage, h)

	if err := h.ForcePastRotationCeiling(t, b, storage); err != nil {
		t.Fatalf("ageing the credential past its ceiling failed: %v", err)
	}
	h.DenyMint()
	t.Cleanup(h.AllowMint)

	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil {
		t.Fatalf("reading %s returned a transport error: %v", h.IssuePath, err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("a credential older than the age its role promises was served anyway: %v", resp)
	}
	// The code is the ROTATION's own, because what a client must decide is whether the upstream
	// failure is worth retrying — not that this mount has a window and it closed.
	if _, known := credenvelope.CodeOf(resp.Error().Error()); !known {
		t.Errorf("the refusal carries no recognised error_code: %q", resp.Error())
	}
}

func servedCredentialID(t *testing.T, b logical.Backend, storage logical.Storage, h Harness) string {
	t.Helper()
	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}
	return credentialID(t, resp)
}

func credentialID(t *testing.T, resp *logical.Response) string {
	t.Helper()
	id, _ := resp.Data["credential_id"].(string)
	if id == "" {
		t.Fatalf("the envelope carries no credential_id, so a client cannot tell a re-served "+
			"credential from a replacement: %#v", resp.Data)
	}
	return id
}

// The three seams below only report a failure. Each one edits stored deadlines, so an error
// means the suite is asserting against state it did not manage to set up, and every later
// assertion in that case would pass or fail for the wrong reason.

func forceRotationDue(t *testing.T, h Harness, b logical.Backend, storage logical.Storage) {
	t.Helper()
	if err := h.ForceRotationDue(t, b, storage); err != nil {
		t.Fatalf("bringing the rotation forward failed: %v", err)
	}
}

func forceOverlapExpired(t *testing.T, h Harness, b logical.Backend, storage logical.Storage) {
	t.Helper()
	if err := h.ForceOverlapExpired(t, b, storage); err != nil {
		t.Fatalf("bringing the retired credential's deletion forward failed: %v", err)
	}
}

func sweep(t *testing.T, h Harness, b logical.Backend, storage logical.Storage) {
	t.Helper()
	if err := h.SweepRetiredCredentials(t, b, storage); err != nil {
		t.Fatalf("the retirement sweep failed: %v", err)
	}
}
