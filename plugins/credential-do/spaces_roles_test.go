package credentialdo_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// spacesRoleSetup creates the minter set every role below binds to.
func spacesRoleSetup(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "minter-sets/default",
		Storage:   storage,
		Data: map[string]any{
			"minters": []any{
				map[string]any{"id": "minter-1", "token": "dop_v1_test", "never_expires": true},
			},
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}
	return b, storage
}

// writeRole writes a role and returns the response, without failing the test — callers
// that expect a refusal need to inspect it.
func writeRole(t *testing.T, b logical.Backend, storage logical.Storage, name string,
	data map[string]any,
) *logical.Response {
	t.Helper()
	data["minter_set"] = "default"
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + name,
		Storage:   storage,
		Data:      data,
	})
	if err != nil {
		t.Fatalf("role write returned a hard error: %v", err)
	}
	return resp
}

// requireRoleRefused asserts the write was refused with config_invalid and that the
// message explains the rule, since an operator's only feedback here is that string.
func requireRoleRefused(t *testing.T, resp *logical.Response, mustMention ...string) {
	t.Helper()
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the role write to be refused, got %v", resp)
	}
	msg := resp.Error().Error()
	if !strings.Contains(msg, string(credenvelope.ErrConfigInvalid)) {
		t.Errorf("expected error_code %q, got: %v", credenvelope.ErrConfigInvalid, msg)
	}
	for _, want := range mustMention {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q, so an operator cannot tell what to fix: %v",
				want, msg)
		}
	}
}

func readRole(t *testing.T, b logical.Backend, storage logical.Storage, name string) map[string]any {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/" + name,
		Storage:   storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("role read failed: err=%v resp=%v", err, resp)
	}
	return resp.Data
}

func TestSpacesRole_WriteAndRead(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	resp := writeRole(t, b, storage, "backup-reader", map[string]any{
		"credential_type": "spaces_key",
		"grants":          "backups:read,archive:readwrite",
		"region":          "nyc3",
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}

	data := readRole(t, b, storage, "backup-reader")
	if data["credential_type"] != "spaces_key" {
		t.Errorf("credential_type did not round-trip: %v", data["credential_type"])
	}
	if got := fmt.Sprint(data["grants"]); got != "[backups:read archive:readwrite]" {
		t.Errorf("grants did not round-trip as a list: %v", data["grants"])
	}
	if data["region"] != "nyc3" {
		t.Errorf("region did not round-trip: %v", data["region"])
	}
	// The endpoint is derived at role write rather than at each issuance, so an operator
	// can SEE what a client will be handed instead of having to know DO's URL scheme.
	if data["endpoint"] != "https://nyc3.digitaloceanspaces.com" {
		t.Errorf("expected the endpoint to be derived from the region, got %v", data["endpoint"])
	}
	// scopes belong to the other credential type and must not appear as an empty
	// suggestion that they could be set.
	if s, ok := data["scopes"].([]string); ok && len(s) != 0 {
		t.Errorf("a spaces_key role reports scopes: %v", data["scopes"])
	}
}

// Every role written before this credential type existed omits the field, and must keep
// issuing exactly what it issued before.
func TestSpacesRole_DefaultsToToken(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	resp := writeRole(t, b, storage, "legacy", map[string]any{
		"scopes": "droplet:read",
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("a role with no credential_type was refused: %v", resp.Error())
	}
	if got := readRole(t, b, storage, "legacy")["credential_type"]; got != "token" {
		t.Errorf("expected an omitted credential_type to read back as token, got %v", got)
	}
}

func TestSpacesRole_RejectsAnUnknownCredentialType(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	resp := writeRole(t, b, storage, "bogus", map[string]any{
		"credential_type": "spaces-key",
		"grants":          "backups:read",
		"region":          "nyc3",
	})
	requireRoleRefused(t, resp, "credential_type", "spaces_key")
}

func TestSpacesRole_RequiresGrantsAndRegion(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	t.Run("no grants", func(t *testing.T) {
		resp := writeRole(t, b, storage, "nogrants", map[string]any{
			"credential_type": "spaces_key",
			"region":          "nyc3",
		})
		requireRoleRefused(t, resp, "grants")
	})

	// Without a region there is no endpoint, and without an endpoint the credential
	// cannot be used at all — so an unset region is a broken role, not a default.
	t.Run("no region", func(t *testing.T) {
		resp := writeRole(t, b, storage, "noregion", map[string]any{
			"credential_type": "spaces_key",
			"grants":          "backups:read",
		})
		requireRoleRefused(t, resp, "region")
	})
}

// The two credential types have disjoint privilege models, so a field belonging to the
// other one is refused rather than ignored: silently dropping `scopes` from a Spaces role
// would let an operator believe they had narrowed a credential they had not.
func TestSpacesRole_RejectsFieldsBelongingToTheOtherCredentialType(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	t.Run("scopes on a spaces_key role", func(t *testing.T) {
		resp := writeRole(t, b, storage, "mixed1", map[string]any{
			"credential_type": "spaces_key",
			"grants":          "backups:read",
			"region":          "nyc3",
			"scopes":          "droplet:read",
		})
		requireRoleRefused(t, resp, "scopes")
	})

	t.Run("grants on a token role", func(t *testing.T) {
		resp := writeRole(t, b, storage, "mixed2", map[string]any{
			"credential_type": "token",
			"scopes":          "droplet:read",
			"grants":          "backups:read",
		})
		requireRoleRefused(t, resp, "grants")
	})

	t.Run("region on a token role", func(t *testing.T) {
		resp := writeRole(t, b, storage, "mixed3", map[string]any{
			"credential_type": "token",
			"scopes":          "droplet:read",
			"region":          "nyc3",
		})
		requireRoleRefused(t, resp, "region")
	})
}

// The privilege-escalation case, and the reason grants are parsed rather than passed
// through. What DigitalOcean does with a grant list mixing `fullaccess` and per-bucket
// entries is undetermined — its spec documents a 400 for the mix and also says fullaccess
// is prioritised when both are sent — so a role that looks least-privilege in the API
// either fails at every issuance or gets an account-wide key. Refusing the combination is
// what makes the role's text and the credential's privilege agree under either reading.
func TestSpacesRole_RejectsFullAccessMixedWithScopedGrants(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	resp := writeRole(t, b, storage, "escalate", map[string]any{
		"credential_type": "spaces_key",
		"grants":          "backups:read,*:fullaccess",
		"region":          "nyc3",
	})
	requireRoleRefused(t, resp, "fullaccess")
}

// The same escalation from the other direction: DO's spec shows fullaccess only against an
// empty bucket — the whole account — and says nothing about what naming a bucket beside it
// does, so a grant that names a bucket AND asks for fullaccess claims a privilege nothing
// has established.
func TestSpacesRole_RejectsFullAccessOnANamedBucket(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	resp := writeRole(t, b, storage, "escalate2", map[string]any{
		"credential_type": "spaces_key",
		"grants":          "backups:fullaccess",
		"region":          "nyc3",
	})
	requireRoleRefused(t, resp, "fullaccess")
}

// Account-wide access is expressible, but only as itself: one grant, `*:fullaccess`.
func TestSpacesRole_AcceptsAccountWideFullAccessAlone(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	resp := writeRole(t, b, storage, "everything", map[string]any{
		"credential_type": "spaces_key",
		"grants":          "*:fullaccess",
		"region":          "nyc3",
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("an account-wide role was refused: %v", resp.Error())
	}
	if got := fmt.Sprint(readRole(t, b, storage, "everything")["grants"]); got != "[*:fullaccess]" {
		t.Errorf("grants did not round-trip: %v", got)
	}
}

func TestSpacesRole_RejectsAMalformedGrant(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	for _, grant := range []string{"backups", "backups:", ":read", "backups:sideways", "*:read"} {
		t.Run(grant, func(t *testing.T) {
			resp := writeRole(t, b, storage, "malformed", map[string]any{
				"credential_type": "spaces_key",
				"grants":          grant,
				"region":          "nyc3",
			})
			requireRoleRefused(t, resp)
		})
	}
}

// An operator whose Spaces live behind a custom or non-default host must be able to say
// so, since the endpoint is part of the credential a client is handed.
func TestSpacesRole_EndpointOverrideIsKept(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	resp := writeRole(t, b, storage, "custom", map[string]any{
		"credential_type": "spaces_key",
		"grants":          "backups:read",
		"region":          "nyc3",
		"endpoint":        "https://spaces.example.internal",
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("an endpoint override was refused: %v", resp.Error())
	}
	if got := readRole(t, b, storage, "custom")["endpoint"]; got != "https://spaces.example.internal" {
		t.Errorf("the endpoint override was not kept: %v", got)
	}
}
