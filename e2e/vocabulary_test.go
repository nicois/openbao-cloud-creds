//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Paths inside a mount. Uniform across the plugins by design (CLAUDE.md), so a
// case needing a different one would be saying something about its cloud.
const (
	configPath = "config"
	setPath    = "minter-sets/default"
	defaultSet = "default"
	roleName   = "e2e-role"
	rolePath   = "roles/" + roleName
	issuePath  = "creds/" + roleName
)

// The single minter every case writes. Its id is asserted back out of the
// response envelope's provenance metadata.
const liveMinterID = "minter-1"

// Field names shared by more than one cloud's API.
const (
	fieldMinters      = "minters"
	fieldID           = "id"
	fieldToken        = "token"
	fieldNeverExpires = "never_expires"
	fieldDefaultTTL   = "default_ttl"
	fieldMaxTTL       = "max_ttl"
	fieldScopes       = "scopes"
	fieldMinterSet    = "minter_set"
)

// TTLs the cases request. Each is inside its cloud's enforceable range
// (docs/ttl-semantics.md) and is asserted against the lease OpenBao creates, so
// a value core would clamp would show up as a failure rather than as a shorter
// lease nobody looked at.
const (
	shortTTL = 900
	hourTTL  = 3600
	dayTTL   = 86400
)

// mountFor is the mount path for a cloud; pluginBinary is its plugin/binary
// name. Both are fixed by convention, not per cloud.
func mountFor(cloud string) string     { return "cloud-creds/" + cloud }
func pluginBinary(cloud string) string { return "credential-" + cloud }

// minterSet wraps minter maps in the "minters" field every minter-set write
// takes. Values must be JSON-encodable: unlike the in-process tests, these
// cross the HTTP API.
func minterSet(m ...map[string]interface{}) map[string]interface{} {
	list := make([]interface{}, 0, len(m))
	for _, one := range m {
		list = append(list, one)
	}
	return map[string]interface{}{fieldMinters: list}
}

// tokenMinter builds the liveMinterID/token/never_expires minter the token-style
// clouds take (DO, UpCloud, Azure, Vultr, Akamai). The id is fixed: every case
// writes one minter and asserts that same id back out of the envelope's
// provenance metadata.
func tokenMinter(token string) map[string]interface{} {
	return map[string]interface{}{fieldID: liveMinterID, fieldToken: token, fieldNeverExpires: true}
}

// jsonInt reads a number that has been through the API's JSON decoder, which
// uses json.Number — an int in the plugin is not an int by the time it lands
// here, which is exactly the coercion this layer exists to exercise.
func jsonInt(t *testing.T, raw interface{}) int {
	t.Helper()
	switch v := raw.(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			t.Fatalf("%v is not an integer: %v", raw, err)
		}
		return int(n)
	case float64:
		return int(v)
	case int:
		return v
	default:
		t.Fatalf("expected a number, got %T (%v)", raw, raw)
		return 0
	}
}

// str reads a string field, failing with the field name rather than a bare type
// assertion panic.
func str(t *testing.T, data map[string]interface{}, key string) string {
	t.Helper()
	raw, ok := data[key]
	if !ok {
		t.Fatalf("field %q is absent from %s", key, keys(data))
	}
	value, ok := raw.(string)
	if !ok {
		t.Fatalf("field %q is %T, want string", key, raw)
	}
	return value
}

func nested(t *testing.T, data map[string]interface{}, key string) map[string]interface{} {
	t.Helper()
	raw, ok := data[key]
	if !ok {
		t.Fatalf("field %q is absent from %s", key, keys(data))
	}
	value, ok := raw.(map[string]interface{})
	if !ok {
		t.Fatalf("field %q is %T, want an object", key, raw)
	}
	return value
}

func keys(data map[string]interface{}) string {
	names := make([]string, 0, len(data))
	for name := range data {
		names = append(names, name)
	}
	return fmt.Sprintf("%v", names)
}
