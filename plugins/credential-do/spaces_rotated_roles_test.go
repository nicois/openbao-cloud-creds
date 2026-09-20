package credentialdo_test

import (
	"fmt"
	"maps"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// rotatedRole is the smallest complete rotated-Spaces role: the two Spaces fields plus the
// two lifecycle fields, both of which an operator must state rather than inherit.
func rotatedRole(extra map[string]any) map[string]any {
	data := map[string]any{
		"credential_type": "spaces_key_rotated",
		"grants":          "backups:read",
		"region":          "nyc3",
		"rotation_period": "2160h", // 90 days
		"overlap_ttl":     "48h",
	}
	maps.Copy(data, extra)
	return data
}

func TestRotatedSpacesRole_WriteAndRead(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	resp := writeRole(t, b, storage, "shared-backup-reader", rotatedRole(nil))
	if resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}

	data := readRole(t, b, storage, "shared-backup-reader")
	if data["credential_type"] != "spaces_key_rotated" {
		t.Errorf("credential_type did not round-trip: %v", data["credential_type"])
	}
	if got := fmt.Sprint(data["grants"]); got != "[backups:read]" {
		t.Errorf("grants did not round-trip: %v", data["grants"])
	}
	if data["endpoint"] != "https://nyc3.digitaloceanspaces.com" {
		t.Errorf("expected the endpoint to be derived from the region, got %v", data["endpoint"])
	}
	if got := data["rotation_period"]; got != 90*24*60*60 {
		t.Errorf("rotation_period did not round-trip in seconds: %v", got)
	}
	if got := data["overlap_ttl"]; got != 48*60*60 {
		t.Errorf("overlap_ttl did not round-trip in seconds: %v", got)
	}
	// An unstated jitter defaults to a tenth of the period: a fleet that all rotates in the
	// same minute is what jitter exists to prevent, so the safe value is the default rather
	// than none.
	if got := data["rotation_jitter"]; got != 9*24*60*60 {
		t.Errorf("expected rotation_jitter to default to a tenth of the period, got %v", got)
	}
}

// The rotated type is the one lifecycle where the operator's own numbers can contradict
// each other, so each rule is refused at write with the reason named.
func TestRotatedSpacesRole_ValidatesTheLifecycleNumbers(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	// A lease must never outlive the credential it names. The active key's minimum
	// remaining life is exactly overlap_ttl — the instant it rotates — so max_ttl above
	// that is a promise the plugin cannot keep.
	t.Run("max_ttl above overlap_ttl", func(t *testing.T) {
		resp := writeRole(t, b, storage, "toolong", rotatedRole(map[string]any{
			"max_ttl": "72h",
		}))
		requireRoleRefused(t, resp, "max_ttl", "overlap_ttl")
	})

	t.Run("rotation_period missing", func(t *testing.T) {
		data := rotatedRole(nil)
		delete(data, "rotation_period")
		requireRoleRefused(t, writeRole(t, b, storage, "noperiod", data), "rotation_period")
	})

	t.Run("overlap_ttl missing", func(t *testing.T) {
		data := rotatedRole(nil)
		delete(data, "overlap_ttl")
		requireRoleRefused(t, writeRole(t, b, storage, "nooverlap", data), "overlap_ttl")
	})

	t.Run("rotation_period below the floor", func(t *testing.T) {
		resp := writeRole(t, b, storage, "tooshort", rotatedRole(map[string]any{
			"rotation_period": "30m",
			"overlap_ttl":     "10m",
			"max_ttl":         "5m",
		}))
		requireRoleRefused(t, resp, "rotation_period")
	})

	// Jitter is subtracted from the period, so a jitter at or above it could schedule a
	// rotation at or before the mint itself.
	t.Run("rotation_jitter at the period", func(t *testing.T) {
		resp := writeRole(t, b, storage, "alljitter", rotatedRole(map[string]any{
			"rotation_jitter": "2160h",
		}))
		requireRoleRefused(t, resp, "rotation_jitter", "rotation_period")
	})

	// An overlap longer than the period would keep more than two keys alive at once,
	// which is how a 200-per-account cap is reached without anybody adding a role.
	t.Run("overlap_ttl above the period", func(t *testing.T) {
		resp := writeRole(t, b, storage, "bigoverlap", rotatedRole(map[string]any{
			"overlap_ttl": "4320h",
		}))
		requireRoleRefused(t, resp, "overlap_ttl", "rotation_period")
	})
}

// Zero jitter is a legitimate choice — an operator wanting a predictable rotation date —
// so it has to be distinguishable from an unstated one.
func TestRotatedSpacesRole_AcceptsAnExplicitZeroJitter(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	resp := writeRole(t, b, storage, "predictable", rotatedRole(map[string]any{
		"rotation_jitter": "0",
	}))
	if resp != nil && resp.IsError() {
		t.Fatalf("an explicit zero jitter was refused: %v", resp.Error())
	}
	if got := readRole(t, b, storage, "predictable")["rotation_jitter"]; got != 0 {
		t.Errorf("expected an explicit zero jitter to stay zero, got %v", got)
	}
}

// The lifecycle fields describe a shared credential's rotation. On the per-lease types
// nothing would honour them, and a field that is accepted and ignored is how an operator
// comes to believe a credential rotates when it does not.
func TestRotatedSpacesRole_RejectsLifecycleFieldsOnTheOtherTypes(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	for _, tc := range []struct {
		name  string
		data  map[string]any
		field string
	}{
		{"rotation_period on a spaces_key role", map[string]any{
			"credential_type": "spaces_key", "grants": "backups:read", "region": "nyc3",
			"rotation_period": "2160h",
		}, "rotation_period"},
		{"overlap_ttl on a spaces_key role", map[string]any{
			"credential_type": "spaces_key", "grants": "backups:read", "region": "nyc3",
			"overlap_ttl": "48h",
		}, "overlap_ttl"},
		{"rotation_jitter on a token role", map[string]any{
			"credential_type": "token", "scopes": "droplet:read",
			"rotation_jitter": "1h",
		}, "rotation_jitter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireRoleRefused(t, writeRole(t, b, storage, "mixedlifecycle", tc.data), tc.field)
		})
	}
}

// A rotated role is still a Spaces role, so it inherits that type's privilege model whole:
// grants and a region are required, and scopes belong to the token type.
func TestRotatedSpacesRole_KeepsTheSpacesPrivilegeModel(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	t.Run("no grants", func(t *testing.T) {
		data := rotatedRole(nil)
		delete(data, "grants")
		requireRoleRefused(t, writeRole(t, b, storage, "nogrants2", data), "grants")
	})

	t.Run("no region", func(t *testing.T) {
		data := rotatedRole(nil)
		delete(data, "region")
		requireRoleRefused(t, writeRole(t, b, storage, "noregion2", data), "region")
	})

	t.Run("scopes", func(t *testing.T) {
		resp := writeRole(t, b, storage, "scoped2", rotatedRole(map[string]any{
			"scopes": "droplet:read",
		}))
		requireRoleRefused(t, resp, "scopes")
	})
}

// Patching one field of an existing rotated role must not have to restate the lifecycle,
// or an operator disabling a role in an incident would be asked for its rotation period.
func TestRotatedSpacesRole_DisableAloneIsACompleteWrite(t *testing.T) {
	b, storage := spacesRoleSetup(t)

	if resp := writeRole(t, b, storage, "patchme", rotatedRole(nil)); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/patchme",
		Storage:   storage,
		Data:      map[string]any{"disabled": true},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("disabling the role alone was refused: err=%v resp=%v", err, resp)
	}
	data := readRole(t, b, storage, "patchme")
	if data["disabled"] != true {
		t.Errorf("the role was not disabled: %v", data["disabled"])
	}
	if got := data["overlap_ttl"]; got != 48*60*60 {
		t.Errorf("the patch lost the overlap_ttl: %v", got)
	}
}
