package cloudconfig

import "testing"

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
