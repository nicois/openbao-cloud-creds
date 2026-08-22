package credentialaws

import (
	"errors"
	"net/http"
	"testing"
)

// TestClassifyDoesNotMatchDigitsInsideIdentifiers is the regression guard for A16.
// The needle tables used to be matched against the whole SDK error string, which
// carries request-ID hex, ARNs and 12-digit account numbers — so a 500 whose
// request id happened to contain "403" was classified as an authorization failure
// and indicted a healthy minter during a cloud outage.
func TestClassifyDoesNotMatchDigitsInsideIdentifiers(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{
			name: "a 500 whose request id contains 403",
			err:  errors.New("operation error STS: AssumeRole, https response error StatusCode: 500, RequestID: 4038e1a2-1f0e-4c33-9b6a-b5e2c1d0f9aa, InternalFailure"),
			want: http.StatusInternalServerError,
		},
		{
			name: "a validation error naming an account that contains 403",
			err:  errors.New("ValidationError: role arn:aws:iam::403912345678:role/app is invalid"),
			want: http.StatusBadRequest,
		},
		{
			name: "a genuine AccessDenied",
			err:  errors.New("AccessDenied: User is not authorized to perform: sts:AssumeRole"),
			want: http.StatusForbidden,
		},
		{
			name: "IAM's key-quota error is a quota, not a bug",
			err:  errors.New("LimitExceeded: Cannot exceed quota for AccessKeysPerUser: 2"),
			want: http.StatusTooManyRequests,
		},
		{
			name: "nothing recognised defers to error inspection",
			err:  errors.New("json: cannot unmarshal number into Go value of type string"),
			want: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyAWSError(c.err); got != c.want {
				t.Errorf("classifyAWSError = %d, want %d\nerror: %v", got, c.want, c.err)
			}
		})
	}
}
