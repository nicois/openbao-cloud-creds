package credenvelope

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// ErrorCode is a stable string identifier for plugin error conditions.
//
// # The vocabulary is additive, and api_version does not version it
//
// An error_code travels in the error *string* (see ErrorResponse), because
// OpenBao surfaces only resp.Error() on an error response. An error response
// therefore carries no envelope, and `metadata.api_version` exists only inside an
// envelope — that is, only on success. A client cannot read api_version off a
// response that carries an error_code, so bumping api_version could never
// communicate a change to this list.
//
// The contract is instead: **the code set is additive, and a client MUST treat an
// unrecognised code exactly as it treats `internal`.** New codes may be added in a
// documented spec revision without an api_version bump; api_version continues to
// mean one thing only, the envelope's shape. Removing or redefining a code is a
// breaking change and does need a bump.
//
// # A code exists only if a client would act differently
//
// That is the test for adding one. The current set maps onto four actions:
//
//	retry with backoff        upstream_unavailable, upstream_timeout, upstream_quota_exceeded
//	do not retry, fix config  config_invalid, upstream_request_invalid, role_not_found, role_disabled, unsupported
//	ask for a different shape credential_kind_unsupported
//	do not retry, fix creds   upstream_auth_failed
//	do not retry, page someone internal, lease_revoke_failed, entity_unavailable, pool_exhausted
type ErrorCode string

const (
	// Request-shaped: the caller or the operator must change something. Retrying
	// an identical request cannot succeed.
	ErrRoleNotFound  ErrorCode = "role_not_found"
	ErrRoleDisabled  ErrorCode = "role_disabled"
	ErrConfigInvalid ErrorCode = "config_invalid"
	ErrUnsupported   ErrorCode = "unsupported"

	// ErrCredentialKindUnsupported: the client pinned a credential shape
	// (credential_kind) that this role does not serve. It earns its own code because
	// it is the one refusal a client can resolve WITHOUT an operator: a library that
	// can parse two shapes retries asking for the other. Every other
	// "do not retry, fix config" code needs a human.
	ErrCredentialKindUnsupported ErrorCode = "credential_kind_unsupported"

	// Upstream-shaped: the cloud answered, or failed to answer.
	ErrUpstreamAuthFailed     ErrorCode = "upstream_auth_failed"
	ErrUpstreamQuotaExceeded  ErrorCode = "upstream_quota_exceeded"
	ErrUpstreamTimeout        ErrorCode = "upstream_timeout"
	ErrUpstreamUnavailable    ErrorCode = "upstream_unavailable"
	ErrUpstreamRequestInvalid ErrorCode = "upstream_request_invalid"
	ErrEntityUnavailable      ErrorCode = "entity_unavailable"
	ErrPoolExhausted          ErrorCode = "pool_exhausted"

	// Plugin-shaped.
	ErrLeaseRevokeFailed ErrorCode = "lease_revoke_failed"
	ErrInternal          ErrorCode = "internal"
)

// AllCodes is the whole vocabulary, which is what makes "every error response
// carries a known code" checkable rather than aspirational: the shared
// error-taxonomy conformance suite parses each plugin's error responses and
// requires the code to be one of these.
func AllCodes() []ErrorCode {
	return []ErrorCode{
		ErrRoleNotFound, ErrRoleDisabled, ErrConfigInvalid, ErrUnsupported,
		ErrCredentialKindUnsupported,
		ErrUpstreamAuthFailed, ErrUpstreamQuotaExceeded, ErrUpstreamTimeout,
		ErrUpstreamUnavailable, ErrUpstreamRequestInvalid, ErrEntityUnavailable,
		ErrPoolExhausted, ErrLeaseRevokeFailed, ErrInternal,
	}
}

// CodeOf extracts the error_code from a response message, which arrives as
// "<code>: <human message>". This is the parse a client performs, so it lives
// here rather than being re-implemented per caller: if the prefix format ever
// changes, one function and its tests change with it.
//
// The second result is false when the message carries no recognised code — which
// a client must treat exactly as ErrInternal, per the additive-vocabulary rule.
func CodeOf(message string) (ErrorCode, bool) {
	prefix, _, found := strings.Cut(message, ": ")
	if !found {
		return ErrInternal, false
	}
	for _, code := range AllCodes() {
		if prefix == string(code) {
			return code, true
		}
	}
	return ErrInternal, false
}

// StatusNone is the httpStatus to pass to Classify when the request produced no
// HTTP response at all — a transport failure, a client-side deadline, or an
// upstream error this plugin's own classifier did not recognise. Classify then
// inspects the error itself, which is the only way a client-side timeout can be
// told apart from a plugin bug: a timeout has no status code by construction.
const StatusNone = 0

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

// ErrorResponse builds a logical error response whose message is prefixed with a
// stable, machine-readable error_code in the form "<code>: <message>". The code
// travels in the error string itself because OpenBao only surfaces the error
// message (resp.Error()) to clients on error responses — Data side-channels are
// dropped. Clients parse the "<code>: " prefix; the codes are the stable
// constants in this package.
func ErrorResponse(code ErrorCode, msg string, args ...interface{}) *logical.Response {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	return logical.ErrorResponse("%s: %s", string(code), msg)
}

// Classify maps one upstream attempt to the code a client sees.
//
// httpStatus is the status the cloud returned, or StatusNone when there was no
// response — pass the error too, always. Without the error, a client-side timeout
// (the single most retryable failure there is) cannot be told apart from a defect
// in this plugin, and both would be reported as `internal`.
func Classify(httpStatus int, err error) ErrorCode {
	if httpStatus <= 0 {
		return classifyTransport(err)
	}
	return ClassifyUpstream(httpStatus)
}

// ClassifyUpstream maps an upstream HTTP status to a stable error_code, so
// callers can distinguish retryable (unavailable/timeout/quota) from fatal
// (auth/invalid/not-found). Prefer Classify, which also handles the no-response
// case; this remains for call sites that genuinely have a status and no error.
func ClassifyUpstream(httpStatus int) ErrorCode {
	switch httpStatus {
	case http.StatusTooManyRequests:
		return ErrUpstreamQuotaExceeded
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return ErrUpstreamTimeout
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrUpstreamAuthFailed
	case http.StatusNotFound:
		return ErrEntityUnavailable
	case http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusConflict:
		// The cloud understood the request and rejected its content. Permanent
		// for an identical retry, and the operator's or plugin's fault rather
		// than the credential's — see KI-010 for the case that motivated this.
		return ErrUpstreamRequestInvalid
	}
	if httpStatus >= http.StatusInternalServerError {
		// The cloud is broken or degraded, not this plugin. Reporting it as
		// `internal` told a client "stop retrying, page an engineer" about the
		// most retryable condition there is.
		return ErrUpstreamUnavailable
	}
	return ErrInternal
}

// classifyTransport reads the error when there is no HTTP status to read.
func classifyTransport(err error) ErrorCode {
	if err == nil {
		return ErrInternal
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrUpstreamTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return ErrUpstreamTimeout
		}
		// Refused, DNS failure, TLS failure, reset: the cloud could not be
		// reached, which is retryable and is not a plugin bug.
		return ErrUpstreamUnavailable
	}
	if errors.Is(err, context.Canceled) {
		// The caller (or core) went away mid-request. Nothing is wrong upstream
		// and nothing is wrong here.
		return ErrUpstreamUnavailable
	}
	return ErrInternal
}

// IndictsMinter reports whether a failure says anything about the *minter's own*
// health, and so whether it belongs in the recovery state machine.
//
// One classification used to serve two consumers with different needs: what to
// tell the client, and whether to hold the minter responsible. It cannot. A role
// TTL the cloud rejects, or a minter set that does not exist, is not evidence
// against a credential — but counting it drove healthy minters toward AuthFailing
// (the second half of KI-010).
func IndictsMinter(code ErrorCode) bool {
	switch code {
	case ErrUpstreamRequestInvalid, ErrConfigInvalid, ErrRoleNotFound,
		ErrRoleDisabled, ErrUnsupported, ErrInternal,
		// A 404 says the thing we NAMED is absent — a mistyped app_object_id,
		// role_id or any other role-supplied upstream target. That is a fault in
		// the request, not evidence against the credential, and counting it walked
		// healthy minters to AuthFailing for an operator's typo (A17).
		ErrEntityUnavailable:
		return false
	default:
		return true
	}
}

// HealthStatus is the representative HTTP status to feed pkg/recovery for a code,
// for call sites that hold a code rather than the original status. The state
// machine only distinguishes auth failures and quota exhaustion from everything
// else, so this need only preserve that much.
func HealthStatus(code ErrorCode) int {
	switch code {
	case ErrUpstreamAuthFailed:
		return http.StatusForbidden
	case ErrUpstreamQuotaExceeded:
		return http.StatusTooManyRequests
	case ErrUpstreamTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusServiceUnavailable
	}
}

// ResponseFor turns an error into an error response, using the code the error
// already carries when it is a *PluginError and ErrInternal otherwise.
//
// It exists because the alternative was writing the code twice: 31 call sites
// embedded "upstream_auth_failed: " in an error string and then passed that string
// to ErrorResponse(ErrUpstreamAuthFailed, ...), so the client received the prefix
// twice and the code had two sources of truth that could disagree. Producers now
// attach the code to the error; this is the one place that unwraps it.
func ResponseFor(err error) *logical.Response {
	if err == nil {
		return ErrorResponse(ErrInternal, "no error")
	}
	var pluginErr *PluginError
	if errors.As(err, &pluginErr) {
		return ErrorResponse(pluginErr.Code, "%s", pluginErr.Message)
	}
	return ErrorResponse(ErrInternal, "%s", err.Error())
}

// InternalResponse renders a failure that is genuinely ours — a storage fault, an
// entry that will not parse — as a coded response rather than a bare Go error.
//
// A bare `return nil, err` from a handler is rendered by core as a 500 with NO
// error_code, which is the same defect as the 166 code-less responses fixed earlier,
// at a larger count (229 sites) and through a door the forbidigo rule does not watch.
// A client switching on the code cannot tell raft quorum loss from anything else
// (A7 in docs/audit-2026-08-22.md).
//
// The upstream detail goes to the caller only as a class, never verbatim: the
// operator's log gets the error, per the same split as the capability gate (A4).
func InternalResponse(logger func(msg string, args ...interface{}), what string, err error,
) *logical.Response {
	if logger != nil {
		logger("plugin-internal failure", "operation", what, "error", err)
	}
	return ErrorResponse(ErrInternal, "%s failed inside the plugin; see the OpenBao server log", what)
}

// opaqueIDBytes is the length of a generated fallback credential id: enough that two
// credentials issued in the same instant cannot collide, short enough to read in a log.
const opaqueIDBytes = 8

// OpaqueCredentialID returns a non-secret identifier for a credential the cloud does
// not identify.
//
// Two clouds (GCP, OVH) issue OAuth2 access tokens with no upstream id. Their
// credential_id used to be an unsalted SHA-256 of the token's own first 16 characters,
// which correlated with nothing in any cloud's records, collided for tokens sharing a
// prefix, and published a digest of secret material as an identifier (A29).
//
// The request id is preferred, because it joins the credential to the OpenBao audit
// device and to this plugin's log lines. A random value is used when there is no request
// id — core assigns one in production, but the field must never be empty, since clients
// key on it and an empty key silently collapses distinct credentials into one.
func OpaqueCredentialID(requestID string) string {
	if requestID != "" {
		return requestID
	}
	buf := make([]byte, opaqueIDBytes)
	if _, err := rand.Read(buf); err != nil {
		// Cannot happen on any supported platform; a fixed marker is still better
		// than an empty id, and it is visibly not a real identifier.
		return "unidentified-credential"
	}
	return hex.EncodeToString(buf)
}
