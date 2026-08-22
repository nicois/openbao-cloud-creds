package cloudconfig

import (
	"strings"
	"testing"
)

// TestValidateEndpointRefusesExfiltration is the regression guard for A3. The
// field is described as "(for testing)" but is persisted and used in production,
// and the minter credential is sent to whatever host it names as a Bearer token.
func TestValidateEndpointRefusesExfiltration(t *testing.T) {
	refused := []struct {
		name string
		raw  string
	}{
		{"plaintext to an attacker", "http://attacker.example"},
		{"plaintext to a public host", "http://api.digitalocean.com"},
		{"an ip that is not loopback", "http://169.254.169.254"},
		{"a scheme that is not http(s)", "file:///etc/passwd"},
		{"a URL carrying credentials", "https://user:pw@api.example.com"},
		{"no host", "https:///v2/tokens"},
		{"a name that merely looks local", "http://localhost.attacker.example"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateEndpoint("api_url", c.raw); err == nil {
				t.Errorf("ValidateEndpoint accepted %q — config-write privilege is then enough to "+
					"exfiltrate every minter credential", c.raw)
			}
		})
	}

	allowed := []struct {
		name string
		raw  string
	}{
		{"unset means default", ""},
		{"https anywhere", "https://api.digitalocean.com"},
		{"https to a sovereign endpoint", "https://graph.microsoft.us"},
		{"loopback over http, which is what the fakes use", "http://127.0.0.1:45231"},
		{"loopback by name", "http://localhost:8200"},
		{"ipv6 loopback", "http://[::1]:45231"},
	}
	for _, c := range allowed {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateEndpoint("api_url", c.raw); err != nil {
				t.Errorf("ValidateEndpoint refused %q: %v. The cloud fakes and the e2e layer point "+
					"these fields at loopback, so refusing it breaks every HTTP-fake test", c.raw, err)
			}
		})
	}
}

// Not one plugin client escaped an interpolated path segment. Most of those values
// are operator-supplied (an Azure app object id, a tenant id, a service-account
// email, every rotation_params entry), and Go's transport writes the path as given
// — so a value with a traversal in it aimed a DELETE at a resource nobody named.
func TestPathSegmentNeutralisesTraversal(t *testing.T) {
	cases := map[string]string{
		"../../v2/droplets":  "..%2F..%2Fv2%2Fdroplets",
		"tok/../../account":  "tok%2F..%2F..%2Faccount",
		"plain-token-id":     "plain-token-id",
		"sa@project.iam.com": "sa@project.iam.com",
	}
	for in, want := range cases {
		if got := PathSegment(in); got != want {
			t.Errorf("PathSegment(%q) = %q, want %q", in, got, want)
		}
	}
	if strings.Contains(PathSegment("a/../b"), "/") {
		t.Error("a separator survived escaping, so the value still spans path segments")
	}
}

// GCP's key_name is a whole multi-segment resource path, so escaping would break
// it. It is validated instead — and it reaches the delete call from rotation_params,
// which an operator writes by hand.
func TestValidateResourcePath(t *testing.T) {
	valid := "projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/abc123"
	if err := ValidateResourcePath("key_name", valid); err != nil {
		t.Errorf("a real GCP key resource name was rejected: %v", err)
	}

	for _, bad := range []string{
		"",
		"/projects/-/keys/abc",
		"projects/../../keys/abc",
		"projects//keys/abc",
		"https://iam.googleapis.com/v1/projects/-/keys/abc",
		"projects/-/serviceAccounts/sa/keys/.",
	} {
		if err := ValidateResourcePath("key_name", bad); err == nil {
			t.Errorf("ValidateResourcePath accepted %q, which can point a delete at another resource", bad)
		}
	}
}
