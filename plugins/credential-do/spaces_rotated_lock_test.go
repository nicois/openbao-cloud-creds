package credentialdo_test

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// A rotation is exclusive for its OWN role and for no other.
//
// This is not a contention nicety. One lock used to guard the whole mount, so any role's
// upstream mint — and the sweeper's entire pass over every role — blocked every client's read.
// On a mount holding hundreds of thousands of rotated roles, each rotating a few times a year,
// that single lock is the throughput ceiling rather than a detail: two roles share no state,
// no bucket, no key and no minter.
//
// Driven by holding one role's mint open at the HTTP layer and requiring the other role's read
// to complete anyway. Against a mount-wide lock this test blocks until the timeout.
func TestRotatedSpacesCreds_OneRolesRotationDoesNotBlockAnother(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing the fake's URL: %v", err)
	}
	var (
		arm     sync.Once
		armed   = make(chan struct{})
		entered = make(chan struct{})
		release = make(chan struct{})
	)
	// Forwards everything, but once armed it holds the NEXT key creation open until released.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/v2/spaces/keys") {
			select {
			case <-armed:
				arm.Do(func() { close(entered) })
				<-release
			default:
			}
		}
		httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
	}))
	defer proxy.Close()

	b, storage := setupTwoRotatedRoles(t, proxy.URL)

	// Both roles hold a key already, so neither read below can mint for the first time.
	blocked := accessKeyOf(t, issueFrom(t, b, storage, "role-blocked", nil))
	free := accessKeyOf(t, issueFrom(t, b, storage, "role-free", nil))

	if err := credentialdo.ForceRotationDue(t.Context(), b, storage, "role-blocked"); err != nil {
		t.Fatalf("forcing role-blocked overdue: %v", err)
	}

	close(armed)
	rotating := make(chan string, 1)
	go func() { rotating <- accessKeyOf(t, issueFrom(t, b, storage, "role-blocked", nil)) }()

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("role-blocked never reached its upstream mint, so this test proves nothing")
	}

	// The whole assertion: a different role's read, while that mint is held open.
	served := make(chan string, 1)
	go func() { served <- accessKeyOf(t, issueFrom(t, b, storage, "role-free", nil)) }()
	select {
	case got := <-served:
		if got != free {
			t.Errorf("role-free was served %q, want the key it already had (%q)", got, free)
		}
	case <-time.After(10 * time.Second):
		t.Error("a read of role-free blocked behind role-blocked's rotation: the lock is still " +
			"mount-wide, so one role's upstream mint stalls every client on the mount")
	}

	close(release)
	select {
	case got := <-rotating:
		if got == blocked {
			t.Errorf("role-blocked served its old key %q after being forced overdue", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("role-blocked's rotation never completed after release")
	}
}

// setupTwoRotatedRoles builds a mount with two independent rotated roles, which is the smallest
// arrangement in which "per role" and "per mount" differ at all.
func setupTwoRotatedRoles(t *testing.T, doURL string) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := setupConfiguredBackend(t, doURL)
	for _, name := range []string{"role-blocked", "role-free"} {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.UpdateOperation, Path: "roles/" + name, Storage: storage,
			Data: map[string]any{
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
			t.Fatalf("writing rotated role %q failed: err=%v resp=%v", name, err, resp)
		}
	}
	return b, storage
}
