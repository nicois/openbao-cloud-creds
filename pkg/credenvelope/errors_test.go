package credenvelope_test

import (
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
)

func TestErrorResponseCarriesCode(t *testing.T) {
	resp := credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role %q does not exist", "snapshot-rw")
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error response, got %v", resp)
	}
	// The code must reach the client via the error string (Error()), since
	// OpenBao drops Data side-channels on error responses.
	got := resp.Error().Error()
	if !strings.HasPrefix(got, string(credenvelope.ErrRoleNotFound)+": ") {
		t.Fatalf("error string missing %q prefix: %q", credenvelope.ErrRoleNotFound, got)
	}
	if !strings.Contains(got, `role "snapshot-rw" does not exist`) {
		t.Fatalf("error string missing message: %q", got)
	}
}

// ErrorCodeOf extracts the stable error_code prefix from an error response's
// message, or "" if absent. Provided as a helper consumers/tests can rely on.
func TestErrorCodeRoundTrips(t *testing.T) {
	resp := credenvelope.ErrorResponse(credenvelope.ErrUpstreamAuthFailed, "all minters failing")
	got := resp.Error().Error()
	if !strings.HasPrefix(got, "upstream_auth_failed: ") {
		t.Fatalf("unexpected: %q", got)
	}
}
