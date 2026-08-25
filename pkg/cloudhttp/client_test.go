package cloudhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudhttp"
)

// A cookie jar is opt-in, and the opt-in is the whole point: Go's default client has no jar, so
// a session-authenticated API fails every call after the login with something that reads as "the
// API rejected us" rather than "we discarded the credential".
func TestCookieJarIsOptInAndActuallyWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("session"); err == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "granted", Path: "/"})
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	t.Run("without a jar the cookie is discarded", func(t *testing.T) {
		client, err := cloudhttp.New(cloudhttp.Options{})
		if err != nil {
			t.Fatalf("building the client failed: %v", err)
		}
		if client.Jar != nil {
			t.Error("a client that did not ask for a jar was given one")
		}
		first := get(t, client, srv.URL)
		second := get(t, client, srv.URL)
		if second != http.StatusAccepted {
			t.Errorf("the second request presented a cookie the client should not have kept "+
				"(%d then %d)", first, second)
		}
	})

	t.Run("with a jar the session survives", func(t *testing.T) {
		client, err := cloudhttp.New(cloudhttp.Options{CookieJar: true})
		if err != nil {
			t.Fatalf("building the client failed: %v", err)
		}
		if got := get(t, client, srv.URL); got != http.StatusAccepted {
			t.Fatalf("the first request should have been handed a cookie, got %d", got)
		}
		if got := get(t, client, srv.URL); got != http.StatusOK {
			t.Errorf("the second request did not present the stored cookie (%d). A session-"+
				"authenticated API would fail here as unauthenticated", got)
		}
	})
}

// Pinning must REFUSE IPv6, not merely deprioritise it: an allowlist holds addresses, and a
// request that quietly egresses over IPv6 comes from one nobody allowlisted.
func TestForceIPv4RefusesAnIPv6OnlyTarget(t *testing.T) {
	client, err := cloudhttp.New(cloudhttp.Options{ForceIPv4: true, Timeout: time.Second})
	if err != nil {
		t.Fatalf("building the client failed: %v", err)
	}
	// A literal IPv6 loopback: with tcp4 there is no way to reach it, so the dial must fail
	// rather than succeed over IPv6.
	if _, err := client.Get("http://[::1]:1/"); err == nil {
		t.Error("a request to an IPv6-only address succeeded despite ForceIPv4")
	}
}

func TestTimeoutDefaultsRatherThanBeingZero(t *testing.T) {
	client, err := cloudhttp.New(cloudhttp.Options{})
	if err != nil {
		t.Fatalf("building the client failed: %v", err)
	}
	if client.Timeout != cloudhttp.DefaultTimeout {
		t.Errorf("timeout is %s, want the default %s: a zero timeout means WAIT FOREVER, which is "+
			"how a worker tick outlives the thing that scheduled it", client.Timeout, cloudhttp.DefaultTimeout)
	}
}

func TestAnUnparseableProxyIsRefusedAtConstruction(t *testing.T) {
	if _, err := cloudhttp.New(cloudhttp.Options{ProxyURL: "://not a url"}); err == nil {
		t.Error("a malformed proxy URL was accepted; it would fail later, per request, as something " +
			"that looks like an upstream problem")
	}
}

func get(t *testing.T, client *http.Client, url string) int {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}
