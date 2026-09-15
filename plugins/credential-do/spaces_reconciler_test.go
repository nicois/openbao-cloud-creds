package credentialdo

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Orphan reclamation across TWO credential classes.
//
// The reconciler is class-agnostic — it moves opaque ids between a lister and a registry — so
// everything that makes the two classes distinguishable has to live here, in the lister. Three
// properties are load-bearing:
//
//  1. An id carries its class, because a token id and a Spaces access key come from different id
//     spaces and DeleteEntity has to know which endpoint to call. Prefixing is also what stops the
//     owned-set of one class shielding an orphan of the other.
//  2. One class failing to LIST cannot fail the pass. On real DigitalOcean GET /v2/tokens is fenced
//     for every PAT (KI-009), so an aborting pass would mean no orphaned Spaces key — the class that
//     works — is ever reclaimed.
//  3. Every class failing is still an error, because then the pass genuinely knows nothing.

// testInstanceID is the mount identity every lister here is built with. One mount is enough for
// these tests: what a SECOND mount must not do — reclaim the first's credentials, for the Spaces
// class as much as the token one — is asserted by the shared reconciler-safety suite, which runs
// over the do (spaces_key) harness variant (pkg/plugintest/reconciler.go,
// TwoMountsDoNotDeleteEachOthers).
const testInstanceID = "inst-1"

// testLister builds a lister against the fake, as the two production construction sites do,
// returning the buffer its warnings land in. A partial listing MUST be visible to an operator:
// silently returning fewer classes than exist is how a fence becomes invisible.
func testLister(t *testing.T, srv *fakes.DOServer) (*doCloudLister, *bytes.Buffer) {
	t.Helper()
	logs := &bytes.Buffer{}
	return &doCloudLister{
		instanceID: testInstanceID,
		client:     newDOClient(srv.URL, "dop_v1_minter_pat"),
		logger:     hclog.New(&hclog.LoggerOptions{Output: logs, Level: hclog.Warn}),
	}, logs
}

// entityIDs returns the listed ids, sorted, so an assertion does not depend on map order.
func entityIDs(t *testing.T, l *doCloudLister) []string {
	t.Helper()
	entities, err := l.ListTaggedEntities(t.Context())
	if err != nil {
		t.Fatalf("listing tagged entities failed: %v", err)
	}
	ids := make([]string, 0, len(entities))
	for _, e := range entities {
		ids = append(ids, e.ID)
	}
	sort.Strings(ids)
	return ids
}

func TestDOCloudLister_ListsBothCredentialClassesWithDistinguishableIDs(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	owned := ownertag.CredentialName(testInstanceID, "role-x", "seed")

	srv.AddRawToken("tok-1", owned)
	srv.AddRawSpacesKey("DO00ACCESS1", owned)
	// Foreign-named credentials of BOTH classes: the owner-tag filter has to apply to the new
	// class exactly as it does to the old one, or the reconciler would delete a Spaces key
	// somebody else created in the same account.
	srv.AddRawToken("tok-foreign", "somebody-elses-token")
	srv.AddRawSpacesKey("DO00FOREIGN", "somebody-elses-key")

	l, _ := testLister(t, srv)
	got := entityIDs(t, l)
	want := []string{"spaces_key:DO00ACCESS1", "token:tok-1"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected both classes listed with class-prefixed ids %v, got %v", want, got)
	}
}

// The class prefix is not cosmetic: DeleteEntity is handed nothing but the id, and the two
// classes are different endpoints. Without it, deleting a Spaces key would DELETE /v2/tokens
// and report success on the 404.
func TestDOCloudLister_DeleteDispatchesOnTheCredentialClass(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	owned := ownertag.CredentialName(testInstanceID, "role-x", "seed")
	srv.AddRawToken("tok-1", owned)
	srv.AddRawSpacesKey("DO00ACCESS1", owned)

	l, _ := testLister(t, srv)
	if err := l.DeleteEntity(t.Context(), "token:tok-1"); err != nil {
		t.Fatalf("deleting a token orphan failed: %v", err)
	}
	if err := l.DeleteEntity(t.Context(), "spaces_key:DO00ACCESS1"); err != nil {
		t.Fatalf("deleting a Spaces-key orphan failed: %v", err)
	}

	if srv.HasToken("tok-1") {
		t.Error("the token orphan survived its delete")
	}
	if srv.HasSpacesKey("DO00ACCESS1") {
		t.Error("the Spaces-key orphan survived its delete, so the delete went to the wrong endpoint")
	}
}

// An unparseable id must be refused rather than guessed at. A bare id reaching DeleteEntity means
// something upstream of here is out of step, and picking a class for it would delete from the wrong
// id space — the one failure mode the prefix exists to prevent.
func TestDOCloudLister_DeleteRefusesAnIDWithoutAClass(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	l, _ := testLister(t, srv)
	if err := l.DeleteEntity(t.Context(), "tok-1"); err == nil {
		t.Fatal("a class-less id was accepted for deletion; it has to be refused, because choosing " +
			"a class on its behalf means deleting from an id space it may not belong to")
	}
}

// This is the case every real DigitalOcean account is in: token management is fenced at the edge
// gateway, Spaces keys are not. A pass that aborted here would leave orphaned Spaces keys — which
// have NO upstream expiry, so nothing else removes them — accumulating against a 200-key cap.
func TestDOCloudLister_AFencedClassWarnsRatherThanFailingThePass(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	owned := ownertag.CredentialName(testInstanceID, "role-x", "seed")
	srv.AddRawToken("tok-1", owned)
	srv.AddRawSpacesKey("DO00ACCESS1", owned)

	srv.SetFenceTokenManagement(true)

	l, logs := testLister(t, srv)
	got := entityIDs(t, l)
	if len(got) != 1 || got[0] != "spaces_key:DO00ACCESS1" {
		t.Fatalf("with token listing fenced, the pass must still yield the Spaces key and nothing "+
			"else; got %v", got)
	}
	// Tolerating the failure is not the same as hiding it: a pass that can only see half of what
	// it owns has to say so, or an operator reads a clean reconcile report as full coverage.
	if !strings.Contains(logs.String(), credentialTypeToken) {
		t.Errorf("a class that could not be listed was skipped silently; the warning must name it: %q",
			logs.String())
	}
}

// The converse bound on that tolerance. If NOTHING could be listed, the pass knows nothing about
// what exists upstream, and reporting an empty listing would let the reconciler proceed on that
// emptiness. It has to be an error.
func TestDOCloudLister_ListFailsWhenEveryClassFails(t *testing.T) {
	srv := fakes.NewDOServer()
	l, _ := testLister(t, srv)
	srv.Close()

	if _, err := l.ListTaggedEntities(t.Context()); err == nil {
		t.Fatal("listing succeeded with the cloud unreachable; an empty listing from a pass that " +
			"learned nothing is indistinguishable from an account with no credentials")
	}
}

// The registry has to speak the same id language as the lister, from both tracking prefixes —
// otherwise every live credential of the untranslated class reads as an orphan and is deleted on
// the next pass.
func TestLeaseRegistry_OwnsBothCredentialClasses(t *testing.T) {
	storage := &logical.InmemStorage{}
	putTracking(t, storage, activeTrackingPrefix+"tok-1")
	putTracking(t, storage, spacesTrackingPrefix+"DO00ACCESS1")

	owned, err := (&leaseRegistry{storage: storage}).OwnedIDs(t.Context())
	if err != nil {
		t.Fatalf("enumerating owned ids failed: %v", err)
	}
	for _, want := range []string{"token:tok-1", "spaces_key:DO00ACCESS1"} {
		if _, ok := owned[want]; !ok {
			t.Errorf("owned set is missing %q; the live credential it tracks would be deleted as an "+
				"orphan (got %v)", want, owned)
		}
	}
}

// The reason ownership is keyed by class rather than by bare id. The two id spaces are independent,
// so the same string can name a live credential in one class and an orphan in the other; a shared
// key space would silently shield the orphan forever.
func TestLeaseRegistry_OwningOneClassDoesNotShieldTheOtherClassesSameID(t *testing.T) {
	storage := &logical.InmemStorage{}
	putTracking(t, storage, activeTrackingPrefix+"COLLIDE")

	owned, err := (&leaseRegistry{storage: storage}).OwnedIDs(t.Context())
	if err != nil {
		t.Fatalf("enumerating owned ids failed: %v", err)
	}
	if _, ok := owned["spaces_key:COLLIDE"]; ok {
		t.Error("a tracked TOKEN made a Spaces key of the same name owned, so that key could never " +
			"be reclaimed")
	}
	if _, ok := owned["token:COLLIDE"]; !ok {
		t.Error("the tracked token is not owned under its own class")
	}
}

// putTracking writes one tracking record, as issuance does.
func putTracking(t *testing.T, storage logical.Storage, key string) {
	t.Helper()
	entry, err := logical.StorageEntryJSON(key, map[string]interface{}{fieldRole: "role-x"})
	if err != nil {
		t.Fatalf("encoding a tracking record failed: %v", err)
	}
	if err := storage.Put(t.Context(), entry); err != nil {
		t.Fatalf("writing a tracking record failed: %v", err)
	}
}
