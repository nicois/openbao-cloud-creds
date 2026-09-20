package cloudconfig

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateEndpoint rejects an endpoint override that could be used to steal the
// minter credential.
//
// Every plugin exposes an endpoint field described as "(for testing)", persisted
// and used in production, and none validated it. The minter token is sent to
// whatever host it names as `Authorization: Bearer` — so config-write privilege,
// which is strictly less than any read endpoint grants (none expose a minter
// secret), was enough to exfiltrate every minter in every set within one
// health-check interval, in plaintext if http:// was chosen (A3 in
// docs/audit-2026-08-22.md).
//
// The rule: TLS for anything that is not loopback.
//
//   - `https://` — allowed to any host. Confidentiality and server identity are
//     then the operator's TLS trust decision, which is the right place for it.
//   - `http://` — allowed ONLY to a loopback address. This is what keeps the
//     httptest-based cloud fakes and the e2e layer working, and it is safe for the
//     reason that matters: a loopback request cannot leave the machine, so it
//     cannot carry a credential to an attacker.
//   - anything else — refused, including userinfo in the URL (a credential in a
//     config field that would be logged by any proxy) and a missing host.
//
// Deliberately NOT a per-cloud host allowlist. An allowlist would have to
// enumerate every sovereign, gov-cloud and partner endpoint each provider
// operates, and would be wrong the day one is added — a stale allowlist fails
// closed against legitimate operators, and the property actually needed here is
// "the credential cannot reach an eavesdropper", which TLS provides.
func ValidateEndpoint(field, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil // unset means "use the built-in default"
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", field, err)
	}
	if parsed.User != nil {
		return fmt.Errorf("%s must not contain credentials in the URL; supply them as minters", field)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("%s must include a host, got %q", field, raw)
	}

	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(host) {
			return nil
		}
		return fmt.Errorf("%s must use https for a non-loopback host: %q would send the minter "+
			"credential over an unencrypted connection to %s", field, raw, host)
	default:
		return fmt.Errorf("%s must be an http(s) URL, got scheme %q", field, parsed.Scheme)
	}
}

// isLoopback reports whether a host is unambiguously local. Names other than
// "localhost" are refused rather than resolved: resolution is attacker-influenced
// (DNS) and would make the check depend on the network at validation time.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// PathSegment escapes a value being interpolated into ONE segment of an upstream
// URL path.
//
// Not one plugin client escaped anything: every upstream id — a token id, an Azure
// app object id, a tenant id, a service-account email, and every
// `rotation_params` value the six rotation clouds record — was concatenated into a
// path raw. Most of those come from an operator's own configuration, and a value
// containing `../` therefore aimed a DELETE at a resource nobody named: Go's
// transport writes the path as given and lets the server resolve the dots (A29 in
// docs/audit-2026-08-22.md).
//
// It is deliberately not a validator. Escaping is total — every character survives
// as itself, so a legitimately odd id still works — whereas a character allowlist
// would have to guess each cloud's id grammar and would reject something real.
func PathSegment(value string) string {
	return url.PathEscape(value)
}

// ValidateResourcePath checks a value that is a MULTI-segment upstream resource
// path, where escaping the separators would break it. GCP's `key_name` is the one
// such field: it is literally
// `projects/-/serviceAccounts/<sa>/keys/<id>` and is appended to the API root.
//
// So this rejects rather than transforms: no traversal, no absolute path, no
// scheme, no empty segment. A rotation_params value written by an operator can
// otherwise point a DELETE at any resource the minter can reach.
func ValidateResourcePath(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if strings.HasPrefix(value, "/") || strings.Contains(value, "://") {
		return fmt.Errorf("%s must be a relative resource path, not %q", field, value)
	}
	for segment := range strings.SplitSeq(value, "/") {
		if segment == "" {
			return fmt.Errorf("%s contains an empty path segment: %q", field, value)
		}
		if segment == "." || segment == ".." {
			return fmt.Errorf("%s must not contain a %q traversal segment: %q", field, segment, value)
		}
	}
	return nil
}
