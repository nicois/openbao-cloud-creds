package credenvelope

import "fmt"

// ErrorCode is a stable string identifier for plugin error conditions.
// Adding a new code is a spec change — update the techrfc first.
type ErrorCode string

const (
	ErrRoleNotFound          ErrorCode = "role_not_found"
	ErrRoleDisabled          ErrorCode = "role_disabled"
	ErrEntityUnavailable     ErrorCode = "entity_unavailable"
	ErrUpstreamQuotaExceeded ErrorCode = "upstream_quota_exceeded"
	ErrUpstreamAuthFailed    ErrorCode = "upstream_auth_failed"
	ErrUpstreamTimeout       ErrorCode = "upstream_timeout"
	ErrConsentRequired       ErrorCode = "consent_required"
	ErrPoolExhausted         ErrorCode = "pool_exhausted"
	ErrLeaseRevokeFailed     ErrorCode = "lease_revoke_failed"
	ErrInternal              ErrorCode = "internal"
)

// PluginError is the structured error type returned by all plugin operations.
// It carries a stable error code, an HTTP-style status code, and a human
// message.
type PluginError struct {
	Code       ErrorCode
	Message    string
	StatusCode int
}

// Error implements the error interface.
func (e *PluginError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewError constructs a PluginError with the given code, HTTP status, and
// message.
func NewError(code ErrorCode, statusCode int, msg string) *PluginError {
	return &PluginError{Code: code, Message: msg, StatusCode: statusCode}
}
