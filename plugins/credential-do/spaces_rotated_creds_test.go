package credentialdo_test

import (
	"sync"
	"testing"
	"time"

	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	rotatedRoleName    = "shared"
	rotatedDefaultTTL  = 900  // 15m
	rotatedMaxTTL      = 3600 // 1h
	rotatedOverlapTTL  = 7200 // 2h
	rotatedPeriodHours = 2160 * time.Hour
)

// setupRotatedBackend returns a backend whose `shared` role serves ONE Spaces key to every
// reader, beside the per-lease `spaces` role and the token role — so these tests also prove
// the three lifecycles coexist on one mount.
func setupRotatedBackend(t *testing.T, srv *fakes.DOServer) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := setupSpacesBackend(t, srv)
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/" + rotatedRoleName, Storage: storage,
		Data: map[string]interface{}{
			"default_ttl":     rotatedDefaultTTL,
			"max_ttl":         rotatedMaxTTL,
			"credential_type": "spaces_key_rotated",
			"grants":          "backups:read",
			"region":          "nyc3",
			"rotation_period": int(rotatedPeriodHours.Seconds()),
			"overlap_ttl":     rotatedOverlapTTL,
			"minter_set":      "default",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotated role write failed: err=%v resp=%v", err, resp)
	}
	return b, storage
}

// accessKeyOf reads the served access key out of a successful credential response.
func accessKeyOf(t *testing.T, resp *logical.Response) string {
	t.Helper()
	if resp == nil || resp.IsError() {
		t.Fatalf("credential read failed: %v", resp)
	}
	cred, ok := resp.Data["credential"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected a credential object, got %T", resp.Data["credential"])
	}
	key, _ := cred["access_key_id"].(string)
	if key == "" {
		t.Fatalf("no access_key_id in the credential: %v", cred)
	}
	return key
}

// The whole point of the type: a client that re-fetches periodically gets the credential it
// already has, so re-fetching costs the account nothing and the client's cache stays valid.
func TestRotatedSpacesCreds_ReServesTheSameCredential(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	first := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))
	for range 4 {
		if got := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil)); got != first {
			t.Fatalf("a re-read served a different key (%s, was %s): every re-fetch would mint "+
				"against a 200-key account cap", got, first)
		}
	}
	if n := srv.ProvisionedSpacesKeyCount(); n != 1 {
		t.Errorf("expected exactly one key upstream after five reads, got %d", n)
	}
	if records, err := storage.List(t.Context(), "active-spaces-keys/"); err != nil {
		t.Fatalf("listing the tracking prefix failed: %v", err)
	} else if len(records) != 1 {
		t.Errorf("expected one tracking record, got %v — the record is what the reconciler and "+
			"the capacity counter read, so one per read would misreport both", records)
	}
}

// Simultaneous first reads are the case that decides whether the account gets one key or
// one per caller, and a cold cache is exactly when every client arrives at once.
func TestRotatedSpacesCreds_ConcurrentFirstReadsMintOnce(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	const readers = 8
	keys := make([]string, readers)
	var wg sync.WaitGroup
	for i := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "creds/" + rotatedRoleName,
				Storage:   storage,
			})
			if err != nil || resp == nil || resp.IsError() {
				return
			}
			if cred, ok := resp.Data["credential"].(map[string]interface{}); ok {
				keys[i], _ = cred["access_key_id"].(string)
			}
		}()
	}
	wg.Wait()

	if n := srv.ProvisionedSpacesKeyCount(); n != 1 {
		t.Errorf("%d concurrent first reads minted %d keys; they must serve one", readers, n)
	}
	for i, key := range keys {
		if key == "" {
			t.Errorf("reader %d got no credential", i)
			continue
		}
		if key != keys[0] {
			t.Errorf("reader %d was served %s, reader 0 %s", i, key, keys[0])
		}
	}
}

// A shared credential cannot be renewed by one holder: renewal defers a revoke, and there
// is no per-holder revoke to defer. framework.Secret.Renewable() is (Renew != nil), so the
// lease is non-renewable only if the type registers no callback at all.
func TestRotatedSpacesCreds_LeaseIsNotRenewable(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	resp := issueFrom(t, b, storage, rotatedRoleName, nil)
	if resp == nil || resp.IsError() {
		t.Fatalf("issue failed: %v", resp)
	}
	if resp.Secret == nil {
		t.Fatal("no lease on the response")
	}
	if resp.Secret.Renewable {
		t.Error("the lease is renewable: OpenBao revokes a lease whose renewal fails, so a " +
			"callback that merely errors would destroy the client's credential")
	}
	if resp.Data["renewable"] != false {
		t.Errorf("the envelope says renewable=%v while the lease says %v; a client trusts the "+
			"envelope", resp.Data["renewable"], resp.Secret.Renewable)
	}
	if got := resp.Secret.InternalData["secret_type"]; got != "do_spaces_key_rotated" {
		t.Errorf("expected the rotated lease to carry its own secret type, got %v — OpenBao "+
			"dispatches revoke on it, so sharing the per-lease type would delete a shared key", got)
	}
	if got, want := resp.Secret.TTL, rotatedDefaultTTL*time.Second; got != want {
		t.Errorf("expected the role's default TTL %s, got %s: the key's remaining life is at "+
			"least overlap_ttl, so the clamp must not bite on a fresh key", want, got)
	}
}

// The lease ending must not touch the credential: every other reader is still using it.
// This is OCI's soft revoke, for the same reason — the credential is not the lease's.
func TestRotatedSpacesCreds_RevokeLeavesTheCredentialAlone(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	resp := issueFrom(t, b, storage, rotatedRoleName, nil)
	accessKey := accessKeyOf(t, resp)

	revoke, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/" + rotatedRoleName,
		Storage:   storage,
		Secret:    resp.Secret,
	})
	if err != nil || (revoke != nil && revoke.IsError()) {
		t.Fatalf("revoke failed: err=%v resp=%v", err, revoke)
	}
	if !srv.HasSpacesKey(accessKey) {
		t.Fatal("one lease ending deleted the shared key, which every other holder is using")
	}
	if got := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil)); got != accessKey {
		t.Errorf("after a revoke the role served %s instead of the live shared key %s", got, accessKey)
	}
}

// The rotation itself: past the key's age the next read mints a replacement, and the key it
// replaces keeps working for the overlap — which is the whole reason two keys exist at once.
func TestRotatedSpacesCreds_RotatesWhenDueAndKeepsTheOldKeyForTheOverlap(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	old := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))
	if err := credentialdo.ForceRotationDue(t.Context(), b, storage, rotatedRoleName); err != nil {
		t.Fatalf("forcing the rotation due failed: %v", err)
	}

	fresh := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))
	if fresh == old {
		t.Fatal("the key was served past its rotation age; the period would be unbounded")
	}
	if !srv.HasSpacesKey(old) {
		t.Error("the replaced key was deleted immediately, so every client holding it broke at " +
			"the moment of rotation — the overlap exists to prevent exactly that")
	}
	if !srv.HasSpacesKey(fresh) {
		t.Error("the replacement was not created upstream")
	}
	// Both keys must stay tracked: the retiring one is not an orphan, and the reconciler
	// deletes what it cannot account for.
	records, err := storage.List(t.Context(), "active-spaces-keys/")
	if err != nil {
		t.Fatalf("listing the tracking prefix failed: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("expected the retiring and the current key both tracked, got %v", records)
	}
	// A further read serves the new key and rotates nothing more.
	if got := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil)); got != fresh {
		t.Errorf("the read after a rotation served %s, not the fresh key %s", got, fresh)
	}
	if n := srv.ProvisionedSpacesKeyCount(); n != 2 {
		t.Errorf("expected two keys during the overlap, got %d", n)
	}
}

// The end of the overlap is enforced here and nowhere else: DigitalOcean cannot be told a
// key expires, and the reconciler cannot help because a retiring key still has a tracking
// record and so is not an orphan.
func TestRotatedSpacesCreds_SweepDeletesTheRetiredKeyAfterTheOverlap(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	old := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))
	if err := credentialdo.ForceRotationDue(t.Context(), b, storage, rotatedRoleName); err != nil {
		t.Fatalf("forcing the rotation due failed: %v", err)
	}
	fresh := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))

	// Mid-overlap a sweep must delete nothing: the grace is the contract.
	if err := credentialdo.SweepSharedSpacesKeys(t.Context(), b, storage); err != nil {
		t.Fatalf("sweep failed: %v", err)
	}
	if !srv.HasSpacesKey(old) {
		t.Fatal("the sweep deleted the retiring key inside its overlap window")
	}

	if err := credentialdo.ForceOverlapExpired(t.Context(), b, storage, rotatedRoleName); err != nil {
		t.Fatalf("forcing the overlap expired failed: %v", err)
	}
	if err := credentialdo.SweepSharedSpacesKeys(t.Context(), b, storage); err != nil {
		t.Fatalf("sweep failed: %v", err)
	}
	if srv.HasSpacesKey(old) {
		t.Error("the retired key survived its overlap; nothing else bounds it, so it is now " +
			"permanent and counts against the account cap for ever")
	}
	if !srv.HasSpacesKey(fresh) {
		t.Error("the sweep deleted the key currently being served")
	}
	records, err := storage.List(t.Context(), "active-spaces-keys/")
	if err != nil {
		t.Fatalf("listing the tracking prefix failed: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("expected only the current key tracked after the sweep, got %v — a record for a "+
			"deleted key makes the capacity counter refuse issuance a minter could serve", records)
	}
}

// A quiet role must still honour its period: "rotate every 90 days" cannot depend on a
// client happening to read on the right day, or a role read once a year holds one key for
// a year.
func TestRotatedSpacesCreds_WorkerRotatesARoleNobodyIsReading(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	old := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))
	if err := credentialdo.ForceRotationDue(t.Context(), b, storage, rotatedRoleName); err != nil {
		t.Fatalf("forcing the rotation due failed: %v", err)
	}
	if err := credentialdo.SweepSharedSpacesKeys(t.Context(), b, storage); err != nil {
		t.Fatalf("sweep failed: %v", err)
	}
	// Counted BEFORE reading again: a read would rotate the overdue key by itself, so
	// asserting on what the next read serves would pass whether the worker did anything or
	// not.
	if n := srv.ProvisionedSpacesKeyCount(); n != 2 {
		t.Fatalf("expected the worker to have minted a replacement (2 keys live), got %d — the "+
			"role's rotation period is otherwise only honoured for roles that happen to be read", n)
	}
	if got := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil)); got == old {
		t.Error("the worker minted a replacement but the role still serves the overdue key")
	}
}

// Narrowing a role's grants is a privilege change, and a shared key already handed out
// still carries the old ones. Rotating at once is what makes the role's text and the
// credential's privilege agree.
func TestRotatedSpacesCreds_ChangingGrantsRotatesAtOnce(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	old := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/" + rotatedRoleName, Storage: storage,
		Data: map[string]interface{}{"grants": "archive:read"},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("narrowing the grants was refused: err=%v resp=%v", err, resp)
	}

	fresh := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))
	if fresh == old {
		t.Fatal("the role kept serving a key minted with the old grants, so the role and the " +
			"credential it names disagree about privilege")
	}
	// The old key still gets the overlap: the grant change is not a containment action, and
	// revoke-upstream is the lever that is.
	if !srv.HasSpacesKey(old) {
		t.Error("the old key was deleted without its overlap; use revoke-upstream for that")
	}
}

// A disabled role serves nothing, and must not have a key minted for it either — the flag
// is the incident lever, so it has to stop the plugin touching the cloud on that role's
// behalf at all.
func TestRotatedSpacesCreds_DisabledRoleNeitherServesNorMints(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/" + rotatedRoleName, Storage: storage,
		Data: map[string]interface{}{"disabled": true},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("disabling the role failed: err=%v resp=%v", err, resp)
	}

	read := issueFrom(t, b, storage, rotatedRoleName, nil)
	if read == nil || !read.IsError() {
		t.Fatalf("a disabled role served a credential: %v", read)
	}
	if n := srv.ProvisionedSpacesKeyCount(); n != 0 {
		t.Errorf("a disabled role minted %d keys", n)
	}
	if err := credentialdo.SweepSharedSpacesKeys(t.Context(), b, storage); err != nil {
		t.Fatalf("sweep failed: %v", err)
	}
	if n := srv.ProvisionedSpacesKeyCount(); n != 0 {
		t.Errorf("the worker minted %d keys for a disabled role", n)
	}
}
