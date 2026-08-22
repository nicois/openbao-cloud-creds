package credenvelope

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"testing"
)

func TestClassifyUpstream(t *testing.T) {
	cases := []struct {
		status int
		want   ErrorCode
	}{
		{http.StatusTooManyRequests, ErrUpstreamQuotaExceeded},       // 429
		{http.StatusRequestTimeout, ErrUpstreamTimeout},              // 408
		{http.StatusGatewayTimeout, ErrUpstreamTimeout},              // 504
		{http.StatusUnauthorized, ErrUpstreamAuthFailed},             // 401
		{http.StatusForbidden, ErrUpstreamAuthFailed},                // 403
		{http.StatusNotFound, ErrEntityUnavailable},                  // 404
		{http.StatusBadRequest, ErrUpstreamRequestInvalid},           // 400 — KI-010
		{http.StatusUnprocessableEntity, ErrUpstreamRequestInvalid},  // 422
		{http.StatusConflict, ErrUpstreamRequestInvalid},             // 409
		{http.StatusInternalServerError, ErrUpstreamUnavailable},     // 500
		{http.StatusBadGateway, ErrUpstreamUnavailable},              // 502
		{http.StatusServiceUnavailable, ErrUpstreamUnavailable},      // 503
		{http.StatusHTTPVersionNotSupported, ErrUpstreamUnavailable}, // 505
		{http.StatusTeapot, ErrInternal},                             // 418, unclassifiable 4xx
		{http.StatusOK, ErrInternal},                                 // not an error at all
		{StatusNone, ErrInternal},                                    // no status, no error
	}
	for _, c := range cases {
		if got := ClassifyUpstream(c.status); got != c.want {
			t.Errorf("ClassifyUpstream(%d) = %q, want %q", c.status, got, c.want)
		}
	}
}

// TestClassifyTransportFailures is the case the old model could not express at
// all: every plugin sets a 30s HTTP client timeout, a client-side timeout carries
// no status code by construction, and nothing inspected the error — so the most
// retryable failure in the system was reported as `internal`, and
// ErrUpstreamTimeout was unreachable outside its own unit test.
func TestClassifyTransportFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want ErrorCode
	}{
		{
			name: "http.Client timeout (what a 30s httpTimeout actually produces)",
			err:  &url.Error{Op: "Post", URL: "https://api.example.com/v2/tokens", Err: timeoutError{}},
			want: ErrUpstreamTimeout,
		},
		{
			name: "context deadline exceeded",
			err:  fmt.Errorf("minting: %w", context.DeadlineExceeded),
			want: ErrUpstreamTimeout,
		},
		{
			name: "connection refused",
			err:  &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
			want: ErrUpstreamUnavailable,
		},
		{
			name: "DNS failure",
			err:  &net.DNSError{Err: "no such host", Name: "api.example.com", IsNotFound: true},
			want: ErrUpstreamUnavailable,
		},
		{
			name: "caller went away",
			err:  fmt.Errorf("minting: %w", context.Canceled),
			want: ErrUpstreamUnavailable,
		},
		{
			name: "an error that is genuinely ours",
			err:  errors.New("json: cannot unmarshal number into Go value of type string"),
			want: ErrInternal,
		},
		{
			name: "no error and no status",
			err:  nil,
			want: ErrInternal,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(StatusNone, c.err); got != c.want {
				t.Errorf("Classify(StatusNone, %v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}

// timeoutError is what *url.Error wraps when http.Client's own timeout fires.
type timeoutError struct{}

func (timeoutError) Error() string { return "context deadline exceeded (Client.Timeout exceeded)" }
func (timeoutError) Timeout() bool { return true }

// TestClassifyPrefersStatusOverError: once the cloud has answered, its status is
// the authority. A 403 delivered over a connection that later errors is still an
// authorization failure.
func TestClassifyPrefersStatusOverError(t *testing.T) {
	got := Classify(http.StatusForbidden, errors.New("connection reset by peer"))
	if got != ErrUpstreamAuthFailed {
		t.Errorf("Classify(403, err) = %q, want %q", got, ErrUpstreamAuthFailed)
	}
}

// TestIndictsMinter pins the split between "what to tell the client" and "does
// this count against the minter". Both used to be the same integer, which is why
// KI-010 marked healthy minters unhealthy for a caller's mistake.
func TestIndictsMinter(t *testing.T) {
	indicts := []ErrorCode{
		ErrUpstreamAuthFailed, ErrUpstreamQuotaExceeded, ErrUpstreamTimeout,
		ErrUpstreamUnavailable, ErrPoolExhausted,
	}
	// ErrEntityUnavailable moved here (A17). A 404 says the thing the REQUEST
	// named is absent — a mistyped app_object_id or role_id — which is a fault in
	// the request, not evidence against the credential. This test previously
	// required the opposite and so cemented the wrong partition.
	exonerates := []ErrorCode{
		ErrUpstreamRequestInvalid, ErrConfigInvalid, ErrRoleNotFound,
		ErrRoleDisabled, ErrUnsupported, ErrInternal, ErrEntityUnavailable,
	}
	for _, code := range indicts {
		if !IndictsMinter(code) {
			t.Errorf("%q should count against the minter's health", code)
		}
	}
	for _, code := range exonerates {
		if IndictsMinter(code) {
			t.Errorf("%q must NOT count against the minter's health: it says nothing about the "+
				"credential, and counting it drives a healthy minter toward AuthFailing", code)
		}
	}
}

// TestHealthStatusPreservesWhatTheStateMachineReads: pkg/recovery only
// distinguishes auth failures and quota exhaustion from everything else, so this
// mapping need only preserve that much — but it must preserve it.
func TestHealthStatusPreservesWhatTheStateMachineReads(t *testing.T) {
	if got := HealthStatus(ErrUpstreamAuthFailed); got != http.StatusForbidden {
		t.Errorf("auth failure maps to %d, want %d — the AuthFailing transition would never fire",
			got, http.StatusForbidden)
	}
	if got := HealthStatus(ErrUpstreamQuotaExceeded); got != http.StatusTooManyRequests {
		t.Errorf("quota maps to %d, want %d — the state machine special-cases 429",
			got, http.StatusTooManyRequests)
	}
	for _, code := range []ErrorCode{ErrUpstreamUnavailable, ErrEntityUnavailable, ErrPoolExhausted} {
		if status := HealthStatus(code); status == http.StatusForbidden {
			t.Errorf("%q maps to 403, which would drive a minter to AuthFailing for a failure that "+
				"is not about its credential", code)
		}
	}
}
