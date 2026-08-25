// Package cloudhttp builds the HTTP client a cloud API needs when *where the request comes
// from* is part of whether it is allowed.
//
// Most of this project's clients need nothing but a timeout. Some clouds care about more:
//
// # Egress address
//
// An API whose access is gated on an allowlist of static addresses will refuse a request from
// anywhere else — and typically refuse it as bot traffic rather than as an auth failure, which
// is a confusing way to lose an afternoon. Two knobs address that: pin to IPv4, because
// allowlists hold IPv4 addresses and a dual-stack host that prefers IPv6 egresses from an
// address nobody allowlisted; and route through a proxy whose address IS allowlisted. Pinning
// REFUSES IPv6 rather than merely deprioritising it, which is what "pinned" has to mean when an
// allowlist is involved.
//
// # Cookie jar
//
// For an API that authenticates with a session rather than a header. Go's default http.Client
// has NO jar, so a cookie the server sets is silently discarded and every later call fails as
// unauthenticated — a failure that reads as "the API rejected us" rather than "we threw the
// credential away". Opt in explicitly, so a client that does not need one does not carry one.
package cloudhttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

// DefaultTimeout bounds every request. It matches the timeout the plugins already use for
// their own clients, so a cloud added here behaves like the rest.
const DefaultTimeout = 30 * time.Second

// Options are the settings that decide where a request comes from and whether a session
// survives. A struct rather than positional arguments because a bare boolean at a call site
// says nothing about which way round it goes.
type Options struct {
	// ForceIPv4 refuses IPv6 rather than merely preferring not to use it.
	ForceIPv4 bool
	// ProxyURL is optional; any scheme net/http understands, including socks5.
	ProxyURL string
	// CookieJar gives the client a jar, for an API that authenticates with a session.
	CookieJar bool
	// Timeout defaults to DefaultTimeout.
	Timeout time.Duration
}

// New builds a client from opts.
func New(opts Options) (*http.Client, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	var jar http.CookieJar
	if opts.CookieJar {
		built, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("building a cookie jar: %w", err)
		}
		jar = built
	}

	dialer := &net.Dialer{Timeout: timeout, KeepAlive: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if opts.ForceIPv4 {
				// tcp4 rather than a zero LocalAddr: it refuses to fall back to IPv6 rather
				// than merely preferring not to, which is what "pinned" has to mean when an
				// allowlist is involved.
				network = "tcp4"
			}
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2: true,
	}

	if opts.ProxyURL != "" {
		parsed, err := url.Parse(opts.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("parsing the proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(parsed)
	}

	return &http.Client{Timeout: timeout, Transport: transport, Jar: jar}, nil
}
