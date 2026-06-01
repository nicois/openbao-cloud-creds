package credenvelope

import (
	"net/http"
	"testing"
)

func TestClassifyUpstream(t *testing.T) {
	cases := []struct {
		status int
		want   ErrorCode
	}{
		{http.StatusTooManyRequests, ErrUpstreamQuotaExceeded}, // 429
		{http.StatusRequestTimeout, ErrUpstreamTimeout},        // 408
		{http.StatusGatewayTimeout, ErrUpstreamTimeout},        // 504
		{http.StatusUnauthorized, ErrUpstreamAuthFailed},       // 401
		{http.StatusForbidden, ErrUpstreamAuthFailed},          // 403
		{http.StatusNotFound, ErrEntityUnavailable},            // 404
		{http.StatusInternalServerError, ErrInternal},          // 500
		{http.StatusBadGateway, ErrInternal},                   // 502
		{http.StatusServiceUnavailable, ErrInternal},           // 503
		{0, ErrInternal},
		{http.StatusOK, ErrInternal},
	}
	for _, c := range cases {
		if got := ClassifyUpstream(c.status); got != c.want {
			t.Errorf("ClassifyUpstream(%d) = %q, want %q", c.status, got, c.want)
		}
	}
}
