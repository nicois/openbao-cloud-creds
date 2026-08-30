package cloudhttp_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudhttp"
)

// A SOCKS5 proxy is not a nice-to-have for the clouds this package exists for. Where an API is
// gated on an allowlist of static egress addresses, routing through an allowlisted address is the
// ONLY way a host that is not itself allowlisted can reach it at all — including every developer
// machine, so it is also the only way such an API can be exercised by hand.
//
// That made "ProxyURL accepts any scheme net/http understands, including socks5" the most
// load-bearing untested claim in this package: the previous tests only proved an UNPARSEABLE
// proxy URL is refused at construction, which says nothing about whether a well-formed one
// works.

// TestASocks5ProxyIsActuallyUsed drives a real request through a real SOCKS5 handshake.
func TestASocks5ProxyIsActuallyUsed(t *testing.T) {
	const body = "served through the proxy"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(target.Close)

	proxy := startSocks5(t)

	client, err := cloudhttp.New(cloudhttp.Options{ProxyURL: "socks5://" + proxy.addr})
	if err != nil {
		t.Fatalf("building a client with a socks5 proxy failed: %v", err)
	}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("a request through the socks5 proxy failed: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the proxied response failed: %v", err)
	}
	if string(got) != body {
		t.Errorf("the proxied response was %q, want %q", got, body)
	}
	if n := proxy.connections(); n != 1 {
		t.Errorf("the proxy handled %d connections, want 1: the request did not go through it", n)
	}
}

// TestTheProxyResolvesTheHostnameRatherThanUs is the assertion that matters operationally.
//
// If Go resolved the destination locally and handed the proxy an IP, then a host whose DNS
// differs from the proxy's would be routed somewhere the proxy never chose — and the point of
// proxying here is that the PROXY's view of the network is the one that counts, because its
// address is the allowlisted one. The reference implementation this was learned from lists
// "issues related to IPv4/IPv6, DNS resolution and the SOCKS proxy" among its common problems,
// so this is a trap somebody has already fallen into.
//
// Go sends a SOCKS5 domain-name request (ATYP 3) when the URL host is not already an IP, which
// is remote resolution. Pinned here because it is a property of net/http rather than of this
// package, and a change to it would silently move where DNS happens.
func TestTheProxyResolvesTheHostnameRatherThanUs(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(target.Close)

	_, port, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatalf("splitting the target address failed: %v", err)
	}

	proxy := startSocks5(t)
	client, err := cloudhttp.New(cloudhttp.Options{ProxyURL: "socks5://" + proxy.addr})
	if err != nil {
		t.Fatalf("building the client failed: %v", err)
	}

	// A hostname rather than the loopback literal, so there is something to resolve.
	want := "localhost:" + port
	resp, err := client.Get("http://" + want + "/")
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	_ = resp.Body.Close()

	if got := proxy.lastRequested(); got != want {
		t.Errorf("the proxy was asked to connect to %q, want the unresolved %q. An IP address here "+
			"means resolution happened LOCALLY — and the proxy's view of DNS is the one that "+
			"matters, because its egress address is the allowlisted one", got, want)
	}
}

// TestForceIPv4AndAProxyCompose: both are set together in practice, because a minter that carries
// a proxy usually carries the IPv4 pin too. They must not conflict.
//
// Worth knowing what it does and does not buy, which is why this test exists rather than just a
// comment: with a proxy in play, ForceIPv4 governs the hop to the PROXY. The address an allowlist
// sees is the proxy's own egress, which this client cannot influence at all. So setting both is
// harmless and slightly redundant — not belt-and-braces.
func TestForceIPv4AndAProxyCompose(t *testing.T) {
	const body = "ok"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(target.Close)

	proxy := startSocks5(t)
	client, err := cloudhttp.New(cloudhttp.Options{
		ForceIPv4: true, ProxyURL: "socks5://" + proxy.addr, CookieJar: true,
	})
	if err != nil {
		t.Fatalf("building the client failed: %v", err)
	}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("a request with both ForceIPv4 and a proxy failed: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != body {
		t.Errorf("the response was %q (err %v), want %q", got, err, body)
	}
}

// The SOCKS5 wire protocol, only as much of it as a no-auth CONNECT needs (RFC 1928).
const (
	socksVersion  = 0x05
	socksNoAuth   = 0x00
	socksConnect  = 0x01
	socksSucceed  = 0x00
	socksReserved = 0x00

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	ipv4Len = 4
	ipv6Len = 16
	portLen = 2
)

// socks5Server is a minimal no-auth SOCKS5 proxy. Real rather than mocked: the thing under test
// is whether net/http performs the handshake as this package assumes, and a stub of the proxy
// would be a stub of exactly that.
type socks5Server struct {
	addr string

	mu        sync.Mutex
	requested []string
}

func (s *socks5Server) record(target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requested = append(s.requested, target)
}

func (s *socks5Server) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requested)
}

func (s *socks5Server) lastRequested() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requested) == 0 {
		return ""
	}
	return s.requested[len(s.requested)-1]
}

func startSocks5(t *testing.T) *socks5Server {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for the fake socks5 proxy failed: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	server := &socks5Server{addr: listener.Addr().String()}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return // the listener closed at test end
			}
			go server.handle(conn)
		}
	}()
	return server
}

func (s *socks5Server) handle(client net.Conn) {
	defer func() { _ = client.Close() }()

	target, err := s.negotiate(client)
	if err != nil {
		return
	}
	s.record(target)

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		// Refusal reply; the client turns it into a connection error, which is the honest outcome.
		_, _ = client.Write([]byte{socksVersion, 0x05, socksReserved, atypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = upstream.Close() }()

	// Success. The bound address is not used by a client that only needs CONNECT, so zeroes.
	if _, err := client.Write([]byte{
		socksVersion, socksSucceed, socksReserved, atypIPv4, 0, 0, 0, 0, 0, 0,
	}); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(upstream, client) }()
	go func() { defer wg.Done(); _, _ = io.Copy(client, upstream) }()
	wg.Wait()
}

// negotiate performs the greeting and reads the CONNECT request, returning the destination the
// client asked for — verbatim, so a test can tell a hostname from an address.
func (s *socks5Server) negotiate(client net.Conn) (string, error) {
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(client, greeting); err != nil {
		return "", err
	}
	if greeting[0] != socksVersion {
		return "", fmt.Errorf("socks version %d, want %d", greeting[0], socksVersion)
	}
	if _, err := io.ReadFull(client, make([]byte, int(greeting[1]))); err != nil {
		return "", err
	}
	if _, err := client.Write([]byte{socksVersion, socksNoAuth}); err != nil {
		return "", err
	}

	header := make([]byte, 4) // version, command, reserved, address type
	if _, err := io.ReadFull(client, header); err != nil {
		return "", err
	}
	if header[1] != socksConnect {
		return "", fmt.Errorf("socks command %d, want CONNECT", header[1])
	}

	host, err := readSocksHost(client, header[3])
	if err != nil {
		return "", err
	}
	rawPort := make([]byte, portLen)
	if _, err := io.ReadFull(client, rawPort); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(rawPort)))), nil
}

// readSocksHost reads the destination host for one of the three address types. A domain name is
// returned as the name, which is the whole point of the DNS assertion above.
func readSocksHost(client net.Conn, addressType byte) (string, error) {
	switch addressType {
	case atypIPv4, atypIPv6:
		length := ipv4Len
		if addressType == atypIPv6 {
			length = ipv6Len
		}
		raw := make([]byte, length)
		if _, err := io.ReadFull(client, raw); err != nil {
			return "", err
		}
		return net.IP(raw).String(), nil
	case atypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(client, length); err != nil {
			return "", err
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(client, name); err != nil {
			return "", err
		}
		return string(name), nil
	default:
		return "", fmt.Errorf("unknown socks address type %d", addressType)
	}
}
