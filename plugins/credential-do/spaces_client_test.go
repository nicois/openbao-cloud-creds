package credentialdo

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// The whole reason this credential type exists in this plugin: unlike /v2/tokens, which
// DO's edge gateway refuses for every PAT (KI-009), /v2/spaces/keys is reachable with a
// PLAIN BEARER PAT holding spaces_key:create_credentials. That is the fact the client
// must not quietly diverge from — no signed scheme, no OAuth exchange, no separate
// Spaces credential to bootstrap — so it is asserted on the wire rather than assumed.
func TestSpacesClient_AuthenticatesWithABearerPAT(t *testing.T) {
	var gotAuth, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key":{"name":"n","access_key":"AK","secret_key":"SK"}}`))
	}))
	defer srv.Close()

	client := newDOClient(srv.URL, "dop_v1_minter_pat")
	if _, _, err := client.CreateSpacesKey(t.Context(), "n", nil); err != nil {
		t.Fatalf("create: %v", err)
	}

	if gotAuth != "Bearer dop_v1_minter_pat" {
		t.Errorf("Spaces key creation must authenticate with the minter PAT as a plain bearer "+
			"token; got Authorization %q", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("expected a JSON content type, got %q", gotContentType)
	}
}

func TestSpacesClient_CreateReturnsTheKeyAndItsSecret(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	client := newDOClient(srv.URL, "fake-minter-token")
	resp, status, err := client.CreateSpacesKey(t.Context(), "cloud-creds-role-abc",
		[]spacesGrant{{Bucket: "backups", Permission: permissionReadWrite}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if status != http.StatusCreated {
		t.Errorf("expected 201, got %d", status)
	}
	if resp.Key.AccessKey == "" {
		t.Error("no access_key: the credential is unusable and, since DO deletes by access key, " +
			"unrevokable")
	}
	if resp.Key.SecretKey == "" {
		t.Error("no secret_key: DO returns it only on create, so a client that does not capture " +
			"it here can never obtain it")
	}
	if resp.Key.Name != "cloud-creds-role-abc" {
		t.Errorf("the name did not round-trip: %q — the name IS the owner tag the reconciler "+
			"matches on", resp.Key.Name)
	}
	if len(resp.Key.Grants) != 1 || resp.Key.Grants[0].Bucket != "backups" ||
		resp.Key.Grants[0].Permission != permissionReadWrite {
		t.Errorf("the grants did not round-trip: %+v", resp.Key.Grants)
	}
}

// A refused mint must surface DO's status, because that status is what decides whether
// the minter is indicted: a 403 on this path means the PAT lacks a spaces_key scope (a
// capability fault), and swallowing it into a bare error would classify as internal and
// walk a healthy minter towards AuthFailing.
func TestSpacesClient_CreateSurfacesTheRefusalStatus(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	srv.SetForbidSpacesKeyCreate(true)

	client := newDOClient(srv.URL, "fake-minter-token")
	_, status, err := client.CreateSpacesKey(t.Context(), "cloud-creds-role-abc", nil)
	if err == nil {
		t.Fatal("a 403 was reported as a successful mint")
	}
	if status != http.StatusForbidden {
		t.Errorf("expected the 403 to be surfaced for classification, got %d", status)
	}
}

func TestSpacesClient_ListReportsNameAndCreatedAt(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	client := newDOClient(srv.URL, "fake-minter-token")
	created, _, err := client.CreateSpacesKey(t.Context(), "cloud-creds-role-abc", nil)
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}

	keys, err := client.ListSpacesKeys(t.Context())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected the one seeded key, got %d", len(keys))
	}
	// The reconciler needs exactly these three: the name to match the owner tag, the
	// access key to delete by, and created_at to apply the confirmation hold.
	if keys[0].Name != "cloud-creds-role-abc" {
		t.Errorf("name missing from the listing: %+v", keys[0])
	}
	if keys[0].AccessKey != created.Key.AccessKey {
		t.Errorf("access_key missing or wrong in the listing: %+v", keys[0])
	}
	if keys[0].CreatedAt == "" {
		t.Error("created_at missing from the listing, so the reconciler cannot tell an orphan " +
			"from a credential that is mid-issuance")
	}
	if keys[0].SecretKey != "" {
		t.Error("the listing carried a secret; nothing may depend on recovering it, since real " +
			"DO returns it only at creation")
	}
}

func TestSpacesClient_DeleteByAccessKey(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	client := newDOClient(srv.URL, "fake-minter-token")
	created, _, err := client.CreateSpacesKey(t.Context(), "cloud-creds-role-abc", nil)
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	accessKey := created.Key.AccessKey

	status, err := client.DeleteSpacesKey(t.Context(), accessKey)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if status != http.StatusNoContent {
		t.Errorf("expected 204, got %d", status)
	}
	if srv.HasSpacesKey(accessKey) {
		t.Error("the key survived its delete upstream")
	}
}

// Revoke has to be able to treat "already gone" as done, or a lease whose credential was
// deleted out of band retries forever (KI-002's shape). That decision is made from the
// status, so the status must survive the error.
func TestSpacesClient_DeleteOfAMissingKeyReports404(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	client := newDOClient(srv.URL, "fake-minter-token")
	status, err := client.DeleteSpacesKey(t.Context(), "DO00FAKEACCESS999999")
	if err == nil {
		t.Fatal("deleting a key that does not exist was reported as a success")
	}
	if status != http.StatusNotFound {
		t.Errorf("expected 404 so revoke can treat it as already-revoked, got %d", status)
	}
}

// DigitalOcean paginates the Spaces-key listing at 20 per page by default (its spec caps
// per_page at 200) and an account may hold 200 keys — a limit DO support will raise, so
// "one page of 200 is enough" is not a safe reading either.
//
// A truncated listing is worse here than anywhere else in this plugin. A Spaces key has NO
// upstream expiry, so the owner-tag reconciler is the ONLY thing that ever reclaims a
// leaked one (docs/ttl-semantics.md); a key it never sees is a credential that lives until
// somebody deletes it by hand, while still counting against the account's cap.
func TestSpacesClient_ListTraversesEveryPage(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	client := newDOClient(srv.URL, "fake-minter-token")
	const seeded = 45 // more than two of DO's default pages
	want := map[string]bool{}
	for i := range seeded {
		name := fmt.Sprintf("cloud-creds-role-%02d", i)
		if _, _, err := client.CreateSpacesKey(t.Context(), name, nil); err != nil {
			t.Fatalf("seed create %d: %v", i, err)
		}
		want[name] = true
	}

	keys, err := client.ListSpacesKeys(t.Context())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != seeded {
		t.Fatalf("the listing returned %d of %d keys: everything past the first page is invisible "+
			"to the reconciler, which is the only thing that reclaims a leaked Spaces key",
			len(keys), seeded)
	}
	for _, key := range keys {
		if !want[key.Name] {
			t.Errorf("listing yielded %q twice, or a key that was never seeded", key.Name)
		}
		delete(want, key.Name)
	}
	if len(want) != 0 {
		t.Errorf("%d seeded keys never appeared in the listing: %v", len(want), want)
	}
}
