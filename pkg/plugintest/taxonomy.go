package plugintest

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The error-taxonomy category. Every error a client can be handed must carry a
// code from the published vocabulary, and the code must describe what the client
// should DO — because that is the only thing a code is for.
//
// This category exists because the old model failed that test in ways no
// per-plugin test noticed. `upstream_timeout` was unreachable outside its own unit
// test (a client-side timeout has no HTTP status, and nothing inspected the
// error), an unreachable cloud and a 500 both arrived as `internal` — "stop
// retrying, page an engineer" for the most retryable conditions there are — and a
// request the cloud rejected on its content was counted as a fault against the
// minter's credential (KI-010).
//
// Cloud-agnostic by construction: what each cloud's API says is per-cloud
// vocabulary and stays in the plugin, but the code a client ends up holding is a
// property of the contract and belongs here, asserted once for all ten.

// assertCode parses the code out of an error response and compares it. It fails
// on a response that is not an error at all, so a silent success cannot pass for
// a correctly-classified failure.
func assertCode(t *testing.T, resp *logical.Response, want credenvelope.ErrorCode, what string) {
	t.Helper()
	if resp == nil {
		t.Fatalf("%s: no response at all, expected an error response with code %q", what, want)
	}
	if !resp.IsError() {
		t.Fatalf("%s: expected an error response with code %q, got a SUCCESS response", what, want)
	}
	message := resp.Error().Error()
	got, known := credenvelope.CodeOf(message)
	if !known {
		t.Errorf("%s: error carries no recognised error_code: %q\nEvery error response must be "+
			"prefixed \"<code>: \" with a code from credenvelope.AllCodes() — a client switches on it, "+
			"and an unprefixed message is indistinguishable from `internal`.", what, message)
		return
	}
	if got != want {
		t.Errorf("%s: error_code is %q, want %q (message: %q)", what, got, want, message)
	}
}

// RunErrorTaxonomySuite asserts the error-code contract for one plugin.
func RunErrorTaxonomySuite(t *testing.T, h Harness) {
	t.Helper()

	t.Run("MissingRoleIsRoleNotFound", func(t *testing.T) {
		b, storage := newBackend(t, h)
		h.Configure(t, b, storage)
		resp := readOrFail(t, b, storage, siblingPath(h.IssuePath, "no-such-role-exists"))
		assertCode(t, resp, credenvelope.ErrRoleNotFound, "reading a role that was never written")
	})

	t.Run("MintRefusalIsUpstreamAuthFailed", func(t *testing.T) {
		if h.DenyMint == nil || h.AllowMint == nil {
			t.Skipf("%s: no mint-refusal knob, so a 403 on the mint path is not asserted here", h.Cloud)
		}
		b, storage := newBackend(t, h)
		h.Configure(t, b, storage)
		h.DenyMint()
		t.Cleanup(h.AllowMint)
		resp := readOrFail(t, b, storage, h.IssuePath)
		assertCode(t, resp, credenvelope.ErrUpstreamAuthFailed,
			"issuing while the upstream refuses the mint with a 403")
	})

	// The two cases the old model could not express. A 500 is the cloud's fault
	// and retryable; a 400 is the request's fault and permanent. Both used to
	// arrive as `internal`, which told a client the opposite of the truth in the
	// first case and blamed the plugin in the second.
	t.Run("UpstreamServerErrorIsNotInternal", func(t *testing.T) {
		runForcedStatusCase(t, h, http.StatusInternalServerError, credenvelope.ErrUpstreamUnavailable,
			"a cloud returning 500 is unavailable, not a bug in this plugin")
	})

	t.Run("UpstreamRejectionIsRequestInvalid", func(t *testing.T) {
		runForcedStatusCase(t, h, http.StatusBadRequest, credenvelope.ErrUpstreamRequestInvalid,
			"a cloud rejecting the request's content is permanent and is not the credential's fault")
	})

	// The case the category structurally could not reach before: a storage fault.
	// Handlers return a bare `return nil, err` at 229 sites, which OpenBao renders
	// as a code-less 500 — the same defect as the 166 code-less responses, at a
	// larger count, through a door forbidigo does not watch (A7).
	t.Run("StorageFailureStillCarriesACode", func(t *testing.T) {
		b, storage := newBackend(t, h)
		h.Configure(t, b, storage)

		// Fail reads only: the request has been accepted and the handler is now
		// trying to load the role it needs. This is raft quorum loss, or a stored
		// entry that will not parse.
		faulty := &FailingStorage{Storage: storage, FailReads: true}
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.ReadOperation, Path: h.IssuePath, Storage: faulty,
		})
		if err != nil {
			t.Fatalf("a storage failure produced a bare Go error, which core renders as a 500 with "+
				"NO error_code — a client cannot distinguish it from any other failure, and API-002 "+
				"promises a code on every path: %v", err)
		}
		assertCode(t, resp, credenvelope.ErrInternal, "issuing while storage reads fail")
	})

	t.Run("CapabilityRejectionIsConfigInvalid", func(t *testing.T) {
		if h.ConfigureProbe == nil || h.WriteProbeRole == nil || h.DenyMint == nil {
			t.Skipf("%s: capability probe not wired, so its rejection code cannot be asserted here; "+
				"the capability category declares that gap", h.Cloud)
		}
		b, storage := newBackend(t, h)
		h.ConfigureProbe(t, b, storage, true)
		h.DenyMint()
		t.Cleanup(h.AllowMint)
		resp := h.WriteProbeRole(t, b, storage)
		assertCode(t, resp, credenvelope.ErrConfigInvalid,
			"writing a role whose bound minter cannot mint for it")
	})
}

// runForcedStatusCase drives one forced upstream status through the issue path.
// A cloud that cannot produce the status through its fake declares a reason,
// which is printed rather than silently skipped — an unexercised case must be
// visible, the same discipline as Harness.Skips.
func runForcedStatusCase(t *testing.T, h Harness, status int, want credenvelope.ErrorCode, why string) {
	t.Helper()
	if h.FailNextMintWithStatus == nil {
		t.Skipf("%s: FailNextMintWithStatus is not wired, so %q is not asserted for this cloud (%s)",
			h.Cloud, want, why)
	}
	b, storage := newBackend(t, h)
	h.Configure(t, b, storage)
	if reason := h.FailNextMintWithStatus(t, status); reason != "" {
		t.Skipf("%s: a %d from the upstream is not reachable through this cloud's fake: %s",
			h.Cloud, status, reason)
	}
	resp := readOrFail(t, b, storage, h.IssuePath)
	assertCode(t, resp, want, why)
}

// readOrFail reads a path and fails on a transport-level error, so an error
// RESPONSE (which is what the taxonomy is about) reaches the assertion.
func readOrFail(t *testing.T, b logical.Backend, storage logical.Storage, path string) *logical.Response {
	t.Helper()
	resp, err := issue(t, b, storage, path)
	if err != nil {
		t.Fatalf("reading %s returned a transport error rather than an error response: %v", path, err)
	}
	return resp
}

// siblingPath swaps the last segment of a path, so the suite can name a role that
// was never written without knowing any cloud's path vocabulary.
func siblingPath(path, lastSegment string) string {
	cut := strings.LastIndex(path, "/")
	if cut < 0 {
		return lastSegment
	}
	return path[:cut+1] + lastSegment
}

// RunMinterVisibilitySuite asserts an operator can see what they need to act on.
//
// The read endpoint returned {name, minter_count, minter_ids} on all ten plugins
// while recovery state, last success, failure count and the rate-limit cooldown all
// sat in the same process. After a rotation an operator could not see which minter was
// retired or when the sweep would delete it; during an outage they could not see a
// minter was auth_failing. With metrics reaching nothing in the documented deployment
// (A12), that left log-grepping as the only channel (A27).
//
// It also asserts the negative that matters: no credential material in the response.
func RunMinterVisibilitySuite(t *testing.T, h Harness) {
	t.Helper()
	b, storage := newConfiguredBackend(t, h)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: h.SetPath, Storage: storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("reading %s failed: err=%v resp=%v", h.SetPath, err, resp)
	}

	minters, ok := resp.Data["minters"].([]map[string]interface{})
	if !ok || len(minters) == 0 {
		t.Fatalf("%s exposes no per-minter status (%T), so a minter's health is invisible to the "+
			"operator who has to act on it", h.SetPath, resp.Data["minters"])
	}
	for _, minter := range minters {
		if minter["id"] == nil || minter["id"] == "" {
			t.Error("a minter entry has no id, so it cannot be acted on")
		}
		if _, present := minter["health"]; !present {
			t.Errorf("minter %v carries no health snapshot: recovery state is in this process and "+
				"still unobservable", minter["id"])
		}
		if _, leaked := minter["token"]; leaked {
			t.Errorf("minter %v exposes its token; the read endpoint must never return credential "+
				"material", minter["id"])
		}
		if _, leaked := minter["rotation_params"]; leaked {
			t.Errorf("minter %v exposes rotation_params, which carry upstream credential ids",
				minter["id"])
		}
	}
}
