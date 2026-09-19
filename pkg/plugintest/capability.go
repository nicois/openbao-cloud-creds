package plugintest

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// capabilityFailureFragment is the operator-facing text every plugin's
// capability rejection carries (from pkg/capability). Asserting on it keeps the
// failure attributable to the probe rather than to some other validation.
const capabilityFailureFragment = "capability verification failed"

// rateLimitRefusalFragment is the text a probe refused by a cooldown carries (from
// capability.Throttled). It is asserted separately from capabilityFailureFragment
// because the two are different answers: "retry shortly" versus "this minter cannot
// mint what you asked for".
const rateLimitRefusalFragment = "rate-limit cooldown"

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
	// A successful probe mints and then deletes. On the clouds that can delete an issued
	// credential, nothing may be left upstream; the rest pin the probe's requested
	// lifetime to the cloud minimum instead and are excluded here.
	if h.DeletesIssuedCredentials {
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
	t.Run("RepeatedWriteReusesTheProbeVerdict", func(t *testing.T) {
		capRepeatedWriteIsCached(t, h)
	})
	t.Run("ProbeRefusedWhileTheCloudIsThrottlingUs", func(t *testing.T) {
		capProbeRespectsRateLimit(t, h)
	})
	t.Run("ProbeRefusedAfterOneRejectedLogin", func(t *testing.T) {
		capProbeRefusedAfterRejectedLogin(t, h)
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
	if resp := h.WriteProbeRole(t, b, storage); resp != nil && resp.IsError() {
		t.Fatalf("writing the role that is about to be disabled was rejected: %v", resp.Error())
	}
	// Disabled through its own endpoint rather than planted in storage, so this case
	// exercises the role a real operator would have: fully defined, then turned off.
	disable(t, b, storage, h.ProbeRolePath, true)

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

// capRepeatedWriteIsCached: an identical configuration write must not re-mint.
//
// A probe is a real mint against a real quota, and the fan-out is (active minters x
// bound roles), so an idempotent `terraform apply` used to re-mint all of it every
// time — and on the clouds with no revoke API each of those probes leaves a live
// credential behind (A29).
//
// Proved without a mint counter, by denying minting after the first write: if the
// second write still probes it is rejected, and if it reuses the verdict it
// succeeds. That also states the cache's contract exactly — it stands in for a
// mint the cloud would otherwise have to serve.
func capRepeatedWriteIsCached(t *testing.T, h Harness) {
	b, storage := newBackend(t, h)
	h.ConfigureProbe(t, b, storage, true)

	if resp := h.WriteProbeRole(t, b, storage); resp != nil && resp.IsError() {
		t.Fatalf("first role write was rejected: %v", resp.Error())
	}

	denyMint(t, h)
	if resp := h.WriteProbeRole(t, b, storage); resp != nil && resp.IsError() {
		t.Fatalf("re-writing an identical role probed the cloud again (and was rejected because "+
			"minting is now denied): %v. A repeated write must reuse the verdict inside "+
			"capability_cache_ttl, or every re-apply re-mints the whole fan-out", resp.Error())
	}
}

// capProbeRespectsRateLimit: probes are inside the circuit breaker, in both
// directions. A probe that earns a 429 must open the cooldown, and while that
// window is open the next write must be refused as throttled — with the wait —
// rather than sent to a cloud that has just refused us, and rather than reported as
// a verdict on the minter that nobody has established (A29).
func capProbeRespectsRateLimit(t *testing.T, h Harness) {
	if h.FailNextMintWithStatus == nil {
		t.Skipf("%s: FailNextMintWithStatus is not wired, so a 429 cannot be forced and the "+
			"probe's rate-limit behaviour is not asserted for this cloud", h.Cloud)
	}
	b, storage := newBackend(t, h)
	h.ConfigureProbe(t, b, storage, true)

	if reason := h.FailNextMintWithStatus(t, http.StatusTooManyRequests); reason != "" {
		t.Skipf("%s: %s", h.Cloud, reason)
	}
	first := h.WriteProbeRole(t, b, storage)
	if first == nil || !first.IsError() {
		t.Fatalf("a role write whose probe was rate-limited succeeded: %v", first)
	}

	// Only the FIRST mint was forced to fail, so a second probe would now succeed.
	// The write must still be refused — by the cooldown the first probe opened.
	second := h.WriteProbeRole(t, b, storage)
	if second == nil || !second.IsError() {
		t.Fatalf("the write immediately after a rate-limited probe was allowed to mint again: %v. "+
			"A probe outside the circuit breaker hammers a cloud that has just throttled the read "+
			"path sharing the same quota", second)
	}
	if got := second.Error().Error(); !strings.Contains(got, rateLimitRefusalFragment) {
		t.Fatalf("the second write was refused, but not as a rate limit: %q. A cooldown and an "+
			"incapable minter are different answers, and only one of them is worth retrying",
			got)
	}
}

// authRefusalFragment is the text a probe refused because the minter's credential has been rejected
// carries (from capability.LoginRejected). Asserted separately from the rate-limit fragment
// because the two call for opposite responses: a cooldown expires on its own, a rejected login does
// not.
const authRefusalFragment = "rejected login"

// capProbeRefusedAfterRejectedLogin covers the window BEFORE a minter reaches auth_failing.
//
// That state needs two rejections at least the plugin's AuthFailThreshold apart, so two inside that
// window leave it unset -- while two of the account's tries are already spent, and the probe would
// spend another. Several clouds lock an account out after a small number of consecutive rejected
// logins (DigitalOcean's console allows three), including the try the repair itself needs. So ONE
// rejection is the trigger, and this is the case that pins it: a gate keyed on the auth_failing state
// passes every other assertion in this suite and still permits that probe.
func capProbeRefusedAfterRejectedLogin(t *testing.T, h Harness) {
	if h.FailNextMintWithStatus == nil {
		t.Skipf("%s: FailNextMintWithStatus is not wired, so a rejected login cannot be forced and "+
			"this cloud's probe gate is not asserted", h.Cloud)
	}
	// newConfiguredBackend, not newBackend: this case needs an ISSUABLE role, because the login has to
	// be spent by an ordinary credential read. A probe's own refusal is deliberately never recorded
	// against the minter (it says the minter lacks a grant, not that its credential is wrong), so no
	// amount of failing probes could drive this counter.
	b, storage := newConfiguredBackend(t, h)
	h.ConfigureProbe(t, b, storage, true)

	if reason := h.FailNextMintWithStatus(t, http.StatusUnauthorized); reason != "" {
		t.Skipf("%s: %s", h.Cloud, reason)
	}
	// The setup has to PROVE it spent a rejected login, not merely that something went wrong: a
	// transport error, or a 404 from a role that is not there, would leave the counter at zero and turn
	// the assertion below into a confusing failure about the gate rather than about the setup.
	resp, err := issue(t, b, storage, h.IssuePath)
	if err != nil {
		t.Fatalf("reading %s failed at the transport, so no login was spent: %v", h.IssuePath, err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("a mint forced to 401 produced a credential: %v", resp)
	}
	assertCode(t, resp, credenvelope.ErrUpstreamAuthFailed,
		"a credential read whose mint was forced to 401")

	// FailNextMintWithStatus failed only that ONE mint, so the wire would now accept a probe. The
	// refusal therefore has to come from the gate, and "refused" has to mean no upstream call was made
	// at all -- an error response after spending the login would defeat the point.
	before := h.ProvisionedCount()
	refused := h.WriteProbeRole(t, b, storage)
	if after := h.ProvisionedCount(); after != before {
		t.Errorf("the refused write still minted upstream (%d -> %d). The gate exists to spend no "+
			"login against an account that is already refusing them", before, after)
	}
	if refused == nil || !refused.IsError() {
		t.Fatalf("a role write was allowed to probe a minter whose credential had just been "+
			"rejected: %v. Each probe is a real login, and this account has already refused one -- "+
			"further attempts spend the tries the repair needs", refused)
	}
	assertCode(t, refused, credenvelope.ErrUpstreamAuthFailed,
		"a role write whose bound minter had just had a login rejected")
	if got := refused.Error().Error(); !strings.Contains(got, authRefusalFragment) {
		t.Fatalf("the write was refused with the right code but not as a rejected login: %q. A "+
			"cooldown, an incapable minter and a rejected credential are three different answers, "+
			"and only one of them is fixed by waiting", got)
	}
}
