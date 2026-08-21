package plugintest

import (
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// capabilityFailureFragment is the operator-facing text every plugin's
// capability rejection carries (from pkg/capability). Asserting on it keeps the
// failure attributable to the probe rather than to some other validation.
const capabilityFailureFragment = "capability verification failed"

// RunCapabilitySuite covers the configuration-time capability probe. Every
// assertion here is cloud-agnostic: what the probe MINTS differs per cloud (and
// stays in each plugin's own capability_test.go), but what a probe result must do
// to stored state does not.
//
// Health is not capability: a minter that authenticates but may not mint is
// otherwise reported healthy indefinitely and fails at the first credential read,
// as an upstream 403 delivered to someone other than the operator who caused it.
func RunCapabilitySuite(t *testing.T, h Harness) {
	t.Run("ProbeSucceedsAndRoleCommits", func(t *testing.T) {
		capProbeSucceeds(t, h)
	})
	// A successful probe mints and then deletes. On the clouds that can revoke,
	// nothing may be left upstream; the no-revoke clouds pin the probe's
	// requested lifetime to the cloud minimum instead and are excluded here.
	if h.ExpectsHardRevoke {
		t.Run("ProbeLeavesNoUpstreamResidue", func(t *testing.T) {
			capProbeLeavesNoResidue(t, h)
		})
	}
	t.Run("RoleWriteRejectedWhenMinterCannotMint", func(t *testing.T) {
		capRoleWriteRejected(t, h)
	})
	t.Run("SetRewriteRejectedWhenReplacementCannotMint", func(t *testing.T) {
		capSetRewriteRejected(t, h)
	})
	t.Run("DisabledRoleNotProbedOnSetWrite", func(t *testing.T) {
		capDisabledRoleNotProbed(t, h)
	})
	t.Run("VerificationDisabledSkipsProbe", func(t *testing.T) {
		capVerificationDisabled(t, h)
	})
}

// denyMint makes the harness's minter incapable for the rest of the subtest, and
// restores it afterwards. A cloud fake is a live server shared by every subtest in
// a category, and the deny knobs are deliberately sticky (they model a standing
// upstream authorization state, not a one-shot failure) — so a deny that is not
// undone silently poisons whatever runs next.
func denyMint(t *testing.T, h Harness) {
	t.Helper()
	h.DenyMint()
	t.Cleanup(h.AllowMint)
}

// capProbeSucceeds: a capable minter lets the role bind, and the role persists.
func capProbeSucceeds(t *testing.T, h Harness) {
	b, storage := newBackend(t, h)
	h.ConfigureProbe(t, b, storage, true)

	resp := h.WriteProbeRole(t, b, storage)
	if resp != nil && resp.IsError() {
		t.Fatalf("role write with a capable minter was rejected: %v", resp.Error())
	}
	if read := Read(t, b, storage, h.ProbeRolePath); read == nil {
		t.Fatal("role write succeeded but persisted no role")
	}
}

// capProbeLeavesNoResidue: the probe is a real mint, so it must be a real delete.
func capProbeLeavesNoResidue(t *testing.T, h Harness) {
	b, storage := newBackend(t, h)
	h.ConfigureProbe(t, b, storage, true)

	if resp := h.WriteProbeRole(t, b, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write was rejected: %v", resp.Error())
	}
	if n := h.ProvisionedCount(); n != 0 {
		t.Fatalf("capability probe left %d credential(s) upstream, want 0", n)
	}
}

// capRoleWriteRejected: the role-write probe is what stops an operator binding a
// role to a minter set whose minting credential is unsuitable for it.
func capRoleWriteRejected(t *testing.T, h Harness) {
	b, storage := newBackend(t, h)
	h.ConfigureProbe(t, b, storage, true)

	denyMint(t, h)
	resp := h.WriteProbeRole(t, b, storage)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the role write to be rejected, got %v", resp)
	}
	if got := resp.Error().Error(); !strings.Contains(got, capabilityFailureFragment) {
		t.Fatalf("expected a capability failure containing %q, got %v", capabilityFailureFragment, got)
	}
	// A rejected write must leave no role behind for a later read — or a later
	// credential request — to succeed against.
	if read := Read(t, b, storage, h.ProbeRolePath); read != nil {
		t.Fatalf("rejected role write persisted the role: %v", read.Data)
	}
}

// capSetRewriteRejected: replacing a set's minters re-probes the roles already
// bound to it, and a rejected replacement must leave the working set as it was.
func capSetRewriteRejected(t *testing.T, h Harness) {
	b, storage := newBackend(t, h)
	h.ConfigureProbe(t, b, storage, true)
	if resp := h.WriteProbeRole(t, b, storage); resp != nil && resp.IsError() {
		t.Fatalf("initial role write was rejected: %v", resp.Error())
	}

	denyMint(t, h)
	resp := h.RewriteSet(t, b, storage, h.ReplacementMinterID)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the minter-set rewrite to be rejected, got %v", resp)
	}
	ids := minterIDs(t, h, b, storage)
	if len(ids) != 1 || ids[0] != h.LiveMinterID {
		t.Fatalf("rejected rewrite changed the live set: got %v, want [%s]", ids, h.LiveMinterID)
	}
}

// capDisabledRoleNotProbed: a disabled role cannot issue, so an incapable minter
// cannot hurt it — and it must not be able to block a minter-set write either.
func capDisabledRoleNotProbed(t *testing.T, h Harness) {
	b, storage := newBackend(t, h)
	h.ConfigureProbe(t, b, storage, true)
	h.PlantDisabledProbeRole(t, storage)

	denyMint(t, h)
	if resp := h.RewriteSet(t, b, storage, h.LiveMinterID); resp != nil && resp.IsError() {
		t.Fatalf("a disabled role blocked a minter-set write: %v", resp.Error())
	}
}

// capVerificationDisabled: the escape hatch. An operator who cannot accept a
// probe mint sets verify_minter_capability=false and gets the pre-probe behaviour.
func capVerificationDisabled(t *testing.T, h Harness) {
	b, storage := newBackend(t, h)
	h.ConfigureProbe(t, b, storage, false)

	denyMint(t, h)
	if resp := h.WriteProbeRole(t, b, storage); resp != nil && resp.IsError() {
		t.Fatalf("verify_minter_capability=false still probed: %v", resp.Error())
	}
}

// minterIDs reads the default set and returns its minter ids. Every plugin's
// minter-set read returns "minter_ids"; the element type is normalized here
// because a storage round-trip can widen []string to []interface{}.
func minterIDs(t *testing.T, h Harness, b logical.Backend, storage logical.Storage) []string {
	t.Helper()
	resp := Read(t, b, storage, h.SetPath)
	if resp == nil || resp.IsError() {
		t.Fatalf("minter-set read failed: %v", resp)
	}
	switch v := resp.Data["minter_ids"].(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				t.Fatalf("minter_ids element is %T, want string", e)
			}
			out = append(out, s)
		}
		return out
	default:
		t.Fatalf("minter-set read returned minter_ids of type %T, want []string", resp.Data["minter_ids"])
		return nil
	}
}
