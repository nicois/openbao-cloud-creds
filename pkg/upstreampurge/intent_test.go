package upstreampurge

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// Arming persists the decision BEFORE any credential is deleted. A purge that deleted first
// and recorded afterwards would, if the node died in between, leave an operator with
// credentials destroyed and nothing saying a purge was ever asked for.
func TestArmPersistsTheDecisionAndCountsWhatIsInScope(t *testing.T) {
	storage := newInmemStorage()
	for _, id := range []string{"a", "b", "c"} {
		track(t, storage, id, testRole, time.Now().Add(-time.Minute), nil)
	}
	track(t, storage, "not-ours", otherRole, time.Now().Add(-time.Minute), nil)

	intent, err := Arm(t.Context(), storage, testPrefix, testRole, time.Now())
	if err != nil {
		t.Fatalf("arming the purge: %v", err)
	}
	if intent.Tracked != 3 || intent.Deleted != 0 || intent.Complete {
		t.Errorf("the armed intent is %+v, want tracked=3 deleted=0 incomplete", intent)
	}

	stored, err := LoadIntent(t.Context(), storage, testRole)
	if err != nil || stored == nil {
		t.Fatalf("the intent was not stored: %+v %v", stored, err)
	}
	if !stored.Cutoff.Equal(intent.Cutoff) {
		t.Errorf("the stored cutoff is %v, want %v: a worker resuming after a restart must purge "+
			"exactly what the operator's call covered", stored.Cutoff, intent.Cutoff)
	}
}

// Arming a second time replaces the first. The operator is asking about the leak they have
// now, so the new call's cutoff — and its count — are the ones that apply.
func TestArmReplacesAnEarlierPurge(t *testing.T) {
	storage := newInmemStorage()
	first, err := Arm(t.Context(), storage, testPrefix, testRole, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("arming the first purge: %v", err)
	}
	track(t, storage, "issued-since", testRole, time.Now().Add(-time.Minute), nil)

	second, err := Arm(t.Context(), storage, testPrefix, testRole, time.Now())
	if err != nil {
		t.Fatalf("arming the second purge: %v", err)
	}
	if second.Tracked != 1 {
		t.Errorf("the re-armed intent reports tracked=%d, want 1: the credential issued since the "+
			"first purge is what the operator is now asking about", second.Tracked)
	}
	if !second.Cutoff.After(first.Cutoff) {
		t.Errorf("the re-armed cutoff is %v, not after the first's %v", second.Cutoff, first.Cutoff)
	}
}

// A purge finishes over several passes, and the count an operator watches has to accumulate
// across them — otherwise progress reads as though each pass started over.
func TestAdvanceAccumulatesAcrossPassesAndCompletesWhenTheScopeIsEmpty(t *testing.T) {
	storage := newInmemStorage()
	for _, id := range []string{"a", "b", "c"} {
		track(t, storage, id, testRole, time.Now().Add(-time.Minute), nil)
	}
	intent, err := Arm(t.Context(), storage, testPrefix, testRole, time.Now())
	if err != nil {
		t.Fatalf("arming the purge: %v", err)
	}
	del := &deleted{}

	if _, err := intent.Advance(t.Context(), storage, testPrefix, 2, del.delete); err != nil {
		t.Fatalf("the first pass failed: %v", err)
	}
	if intent.Deleted != 2 || intent.Complete {
		t.Fatalf("after one bounded pass the intent is %+v, want deleted=2 incomplete", intent)
	}

	if _, err := intent.Advance(t.Context(), storage, testPrefix, 2, del.delete); err != nil {
		t.Fatalf("the second pass failed: %v", err)
	}
	if intent.Deleted != 3 || !intent.Complete {
		t.Errorf("after the purge finished the intent is %+v, want deleted=3 complete", intent)
	}

	stored, err := LoadIntent(t.Context(), storage, testRole)
	if err != nil || stored == nil {
		t.Fatalf("loading the intent: %+v %v", stored, err)
	}
	if !stored.Complete || stored.Deleted != 3 {
		t.Errorf("the stored intent is %+v, want the completion recorded: a worker that cannot see "+
			"a finished purge keeps scanning for it forever", stored)
	}
}

// Failures are this pass's, so an operator reading progress learns whether it is STILL going
// wrong. A running total would report the one delete that failed and later succeeded for as
// long as the intent is kept.
func TestAdvanceReportsTheLatestPassesFailuresOnly(t *testing.T) {
	storage := newInmemStorage()
	track(t, storage, "stubborn", testRole, time.Now().Add(-time.Minute), nil)
	intent, err := Arm(t.Context(), storage, testPrefix, testRole, time.Now())
	if err != nil {
		t.Fatalf("arming the purge: %v", err)
	}

	failing := &deleted{err: errors.New("upstream said no")}
	if _, err := intent.Advance(t.Context(), storage, testPrefix, 10, failing.delete); err != nil {
		t.Fatalf("the failing pass returned an error: %v", err)
	}
	if intent.Failed != 1 || intent.Complete {
		t.Fatalf("after a failed delete the intent is %+v, want failed=1 incomplete", intent)
	}

	succeeding := &deleted{}
	if _, err := intent.Advance(t.Context(), storage, testPrefix, 10, succeeding.delete); err != nil {
		t.Fatalf("the retry pass returned an error: %v", err)
	}
	if intent.Failed != 0 || !intent.Complete {
		t.Errorf("after the retry succeeded the intent is %+v, want failed=0 complete", intent)
	}
}

// A finished purge is not re-run. The worker sweeps every role with an intent, and an intent
// is kept after completion so the outcome stays readable — so "complete" has to mean the
// deleter is not called again.
func TestAdvanceOnAFinishedPurgeDoesNothing(t *testing.T) {
	storage := newInmemStorage()
	intent := &Intent{Role: testRole, Complete: true}
	track(t, storage, "issued-later", testRole, time.Now(), nil)
	del := &deleted{}

	result, err := intent.Advance(t.Context(), storage, testPrefix, 10, del.delete)
	if err != nil {
		t.Fatalf("advancing a finished purge: %v", err)
	}
	if len(del.ids) != 0 {
		t.Errorf("a finished purge deleted %v", del.ids)
	}
	if result.Deleted != 0 || !result.Complete() {
		t.Errorf("advancing a finished purge reported %+v", result)
	}
}

// A pass with no budget is still bounded. An unbounded one is the failure mode this whole
// design exists to avoid, so the absence of a number must not be the way to ask for it.
func TestPassWithNoBudgetIsStillBounded(t *testing.T) {
	if DefaultMaxDeletes <= 0 {
		t.Fatalf("DefaultMaxDeletes is %d, so a pass with no budget deletes nothing", DefaultMaxDeletes)
	}
	storage := newInmemStorage()
	for i := range DefaultMaxDeletes + 2 {
		track(t, storage, fmt.Sprintf("id-%03d", i), testRole, time.Now().Add(-time.Minute), nil)
	}
	del := &deleted{}

	result, err := Pass(t.Context(), storage, Config{
		Prefix: testPrefix, Role: testRole, Cutoff: time.Now(),
	}, del.delete)
	if err != nil {
		t.Fatalf("pass failed: %v", err)
	}
	if result.Deleted != DefaultMaxDeletes {
		t.Errorf("a pass with no budget deleted %d, want the default bound of %d",
			result.Deleted, DefaultMaxDeletes)
	}
}

// Progress is what the read endpoint answers and what the worker decides on, so it derives
// what is left rather than trusting a stored count.
func TestProgressDerivesWhatIsLeftInScope(t *testing.T) {
	storage := newInmemStorage()
	for _, id := range []string{"a", "b"} {
		track(t, storage, id, testRole, time.Now().Add(-time.Minute), nil)
	}
	if _, err := Arm(t.Context(), storage, testPrefix, testRole, time.Now()); err != nil {
		t.Fatalf("arming the purge: %v", err)
	}

	report, err := Progress(t.Context(), storage, testPrefix, testRole)
	if err != nil {
		t.Fatalf("reading progress: %v", err)
	}
	if report[keyRemaining] != 2 || report[keyArmed] != true {
		t.Errorf("progress reports %v, want remaining=2 and armed", report)
	}

	// A credential issued after the purge was armed is outside its scope, which is what makes
	// the purge terminate on a mount that is still issuing.
	track(t, storage, "issued-after", testRole, time.Now().Add(time.Minute), nil)
	report, err = Progress(t.Context(), storage, testPrefix, testRole)
	if err != nil {
		t.Fatalf("reading progress: %v", err)
	}
	if report[keyRemaining] != 2 {
		t.Errorf("progress reports remaining=%v after the role issued again, want 2",
			report[keyRemaining])
	}
}

// A role nobody has purged answers the same shape as one that has, so no reader has to
// handle an absence specially.
func TestProgressOfANeverPurgedRoleReportsNoPurge(t *testing.T) {
	report, err := Progress(t.Context(), newInmemStorage(), testPrefix, testRole)
	if err != nil {
		t.Fatalf("reading progress: %v", err)
	}
	if report[keyArmed] != false || report[keyCutoff] != "" {
		t.Errorf("a never-purged role reports %v", report)
	}
}
