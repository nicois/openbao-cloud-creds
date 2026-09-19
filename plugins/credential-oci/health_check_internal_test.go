package credentialoci

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// failingUserClient is a fake whose GetUser always returns one chosen error, so a health check's
// classification can be observed. NewTestFakeClient's failNext is single-shot, and the worker calls
// GetUser once per due minter, but an always-failing client keeps the test independent of that.
type failingUserClient struct {
	OCIIAMClient
	err error
}

func (c *failingUserClient) GetUser(context.Context, string) error { return c.err }

// The health check worker probes a minter that is ALREADY auth-failing -- that is what
// NeedsHealthCheck gates on -- and what it records decides whether the minter stays indicted.
//
// It used to record every failure as RecordError(401): a probe that could not reach OCI at all was
// counted as another rejected login, inflating a count an operator reads to decide whether a
// credential needs replacing, and holding the minter indicted on evidence about the network. It now
// passes the error to RecordUpstream, so the classifier decides.
//
// The two cases below are the whole contract: an error that says the credential was rejected counts,
// and one that says nothing about the credential does not.
func TestHealthCheckWorkerCountsOnlyRejectedLogins(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		wantR int
	}{
		{
			name:  "a rejected login is recorded",
			err:   credenvelope.NewError(credenvelope.ErrUpstreamAuthFailed, http.StatusUnauthorized, "bad key"),
			wantR: 3,
		},
		{
			name:  "an unreachable upstream is not",
			err:   &net.DNSError{Err: "no such host", Name: "iam.oci", IsNotFound: true},
			wantR: 2,
		},
		{
			name:  "nor is an unimplemented client",
			err:   credenvelope.NewError(credenvelope.ErrUnsupported, http.StatusNotImplemented, "stub"),
			wantR: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bk := healthWorkerBackend(t)
			bk.SetClientFactory(func(string) OCIIAMClient {
				return &failingUserClient{OCIIAMClient: NewTestFakeClient(), err: tc.err}
			})

			bk.mu.RLock()
			ms := bk.minterSets["default"]["minter-1"]
			bk.mu.RUnlock()
			if ms == nil {
				t.Fatal("minter-1 state not loaded")
			}

			// Two rejections far enough apart to reach auth_failing, which is the only state the
			// worker probes at all, and far enough in the past that a check is due.
			long := time.Now().Add(-2 * time.Hour)
			ms.sm.RecordUpstream(http.StatusUnauthorized, nil, long)
			ms.sm.RecordUpstream(http.StatusUnauthorized, nil, long.Add(time.Minute))
			if got := ms.sm.ConsecutiveAuthFailures(); got != 2 {
				t.Fatalf("fixture has %d rejected logins, want 2", got)
			}
			if !ms.sm.NeedsHealthCheck(time.Now()) {
				t.Fatal("fixture is not due for a health check, so the worker would skip it")
			}

			if err := bk.healthCheckWorker(t.Context()); err != nil {
				t.Fatalf("healthCheckWorker: %v", err)
			}
			if got := ms.sm.ConsecutiveAuthFailures(); got != tc.wantR {
				t.Errorf("rejected logins = %d, want %d. A failure that says nothing about the "+
					"credential must not be counted as one that does: the count is what an operator "+
					"reads to decide whether to replace it, and what gates a role write", got, tc.wantR)
			}
		})
	}
}

// A health check that SUCCEEDS clears the count, which is the only thing that does.
func TestHealthCheckWorkerClearsTheCountOnSuccess(t *testing.T) {
	bk := healthWorkerBackend(t)

	bk.mu.RLock()
	ms := bk.minterSets["default"]["minter-1"]
	bk.mu.RUnlock()
	if ms == nil {
		t.Fatal("minter-1 state not loaded")
	}
	long := time.Now().Add(-2 * time.Hour)
	ms.sm.RecordUpstream(http.StatusUnauthorized, nil, long)
	ms.sm.RecordUpstream(http.StatusUnauthorized, nil, long.Add(time.Minute))

	if err := bk.healthCheckWorker(t.Context()); err != nil {
		t.Fatalf("healthCheckWorker: %v", err)
	}
	if got := ms.sm.ConsecutiveAuthFailures(); got != 0 {
		t.Fatalf("rejected logins = %d after a successful check, want 0", got)
	}
}

// healthWorkerBackend stands up a backend with one minter set holding one minter.
func healthWorkerBackend(t *testing.T) *backend {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	bk, ok := b.(*backend)
	if !ok {
		t.Fatalf("Factory returned %T, want *backend", b)
	}
	bk.SetClientFactory(func(string) OCIIAMClient { return NewTestFakeClient() })
	storage := config.StorageView

	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{testRegionField: testRegionValue},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]interface{}{
			mintersKey: []interface{}{
				map[string]interface{}{
					"id": "minter-1", minterTokenKey: "tenancy:user1:fp:key", "never_expires": true,
				},
			},
		},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}
	return bk
}
