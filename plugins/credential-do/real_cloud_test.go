//go:build cloud_real

// Package credentialdo's real-cloud probe. This is the first file in the repo to
// carry the cloud_real build tag (see docs/openbao-integration-gaps.md G9).
//
// It existed to answer ONE question that no fake can answer: does
// POST /v2/tokens — absent from DigitalOcean's public OpenAPI spec, and the
// endpoint this whole plugin's mint path depends on — actually work when called
// with a personal access token?
//
// IT DOES NOT. Answered against a real account with a **full-access** PAT on
// 2026-08-21: every /v2/tokens* call is refused 403 by DO's edge gateway
// (`x-response-from: Edge-Gateway`) while ordinary endpoints are served by the
// backend (`x-response-from: service`) for the same token. The path is fenced off
// from API-token auth entirely, so no PAT — scoped or full-access — can mint, and
// `credential-do`'s mint path cannot work in production. See KI-009 in
// docs/known-issues.md and docs/do-api-verification-2026-08-21.md.
//
// So this file's job has changed from *asking* to *pinning*: it asserts the fence
// is still there. A PASS means "DO still refuses; the plugin's mint path is still
// dead". A FAILURE is GOOD NEWS — DO changed something and the JIT strategy may be
// revivable — which is why the unexpected-201 path is fully written out rather than
// left as a TODO, and why it cleans up after itself.
//
// It deliberately drives the plugin's own doClient rather than a fresh HTTP
// client: the point is to validate the code the fake stands in for, including its
// response decoding. A field name the plugin gets wrong would mint successfully
// and hand back an empty credential, which is exactly the class of bug a fake
// written from the same reading of the docs cannot catch.
//
//	export CLOUDREAL_DO_TOKEN=dop_v1_...
//	make test-cloud-real-do
package credentialdo

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
)

const (
	// envRealDOToken names the minter PAT. The tag is the opt-in, so a missing
	// token is a failure and not a skip: a real-cloud job that silently passes
	// without credentials is the exact shape of the gap this closes.
	envRealDOToken = "CLOUDREAL_DO_TOKEN"

	// envRealDOScopes overrides the scopes the probe asks for. DO scopes are
	// fine-grained <resource>:<verb> strings and role `scopes` is an unvalidated
	// pass-through, so making this an env var means the scope vocabulary can be
	// explored without editing code.
	envRealDOScopes = "CLOUDREAL_DO_SCOPES"

	// defaultProbeScopes is the least a probe can ask for and still prove the
	// minted credential works: reading the account is the same call the health
	// check makes.
	defaultProbeScopes = "account:read"

	// realDOBaseURL is the real API. Nothing here may point at a fake.
	realDOBaseURL = "https://api.digitalocean.com"

	// probeNamePrefix keeps every token this test creates inside the owner-tag
	// scheme, so a token left behind by a crashed run is recognisable rather than
	// mysterious. It uses a fixed pseudo-instance rather than a real mount's id
	// because this probe drives the cloud client directly and has no mount (A19).
	probeNamePrefix = ownertag.Base + "cirun-probe-"

	// revokeVisibilityTimeout bounds how long the probe waits for a deleted
	// token to stop working. Immediate is expected; a lag here would be a real
	// finding about how well DO revocation bounds a credential's life.
	revokeVisibilityTimeout = 15 * time.Second
	revokeVisibilityPoll    = time.Second

	// livenessPath is readable by any live PAT regardless of its scopes (verified
	// against a real scoped PAT on 2026-08-21: 200 here while /v2/account,
	// /v2/tags, /v2/projects and /v2/tokens all returned 403). It is what lets
	// this probe tell "the token is dead" from "the token is live but not
	// authorized" — a distinction that decides whether a 403 says anything at all
	// about the endpoint.
	livenessPath = "/v2/regions"

	// accountPath is what the plugin's health check calls, so a broad PAT reads it
	// and a granular one does not.
	accountPath = "/v2/account"

	// realTokensPath is the fenced endpoint itself. The responder constants this
	// file asserts on (headerResponder, responderEdge, …) live in the UNTAGGED
	// fake_parity_test.go, because the parity test reads them out of the recordings
	// and must compile without the cloud_real tag.
	realTokensPath = "/v2/tokens"
)

// TestRealDOTokenEndpoint is the whole probe: the minter credential works, and
// token management is nonetheless fenced off from it.
func TestRealDOTokenEndpoint(t *testing.T) {
	minterToken := requireRealDOToken(t)
	minter := realDOClient(t, minterToken, minterToken)
	ctx := t.Context()

	t.Run("MinterHealth", func(t *testing.T) {
		status, err := minter.CheckHealth(ctx)
		if err != nil {
			t.Fatalf("health check transport error: %v", scrubSecrets(err.Error(), minterToken))
		}
		switch status {
		case http.StatusOK:
			t.Logf("%s: 200 — the PAT is live and broad enough for the plugin's health check", accountPath)
		case http.StatusForbidden:
			liveness, _ := rawGet(t, minterToken, livenessPath)
			t.Fatalf("%s returned 403 while %s returns %d.\n\n"+
				"The PAT is LIVE but not authorized to read the account, i.e. it is a granular "+
				"(scoped) token without account:read. Two consequences worth recording:\n"+
				"  1. This plugin's health check IS GET %s, so a scoped minter would be driven to "+
				"AuthFailing by the recovery state machine even though it is perfectly alive.\n"+
				"  2. A 403 further down would then be ambiguous. Use a full-access PAT: the fence "+
				"assertions below are only meaningful for a token that is otherwise privileged.",
				accountPath, livenessPath, liveness, accountPath)
		case http.StatusUnauthorized:
			liveness, _ := rawGet(t, minterToken, livenessPath)
			t.Fatalf("%s returned 401: the PAT in %s is invalid or revoked (%s also returns %d)",
				accountPath, envRealDOToken, livenessPath, liveness)
		default:
			t.Fatalf("%s returned %d, want 200: the minter PAT in %s is not usable, so nothing "+
				"below would mean anything", accountPath, status, envRealDOToken)
		}
	})

	t.Run("TokenManagementIsFencedFromAPITokens", func(t *testing.T) {
		// Establish the contrast on this exact token: the account endpoint is
		// answered by DO's backend, so the credential is not the problem.
		accountStatus, accountResponder := rawGet(t, minterToken, accountPath)
		if accountStatus != http.StatusOK {
			t.Fatalf("%s returned %d; run this with a full-access PAT (see MinterHealth)",
				accountPath, accountStatus)
		}
		if accountResponder != responderService {
			t.Fatalf("GET %s -> 200 but %s is %q, not %q. The control below compares WHO answered, "+
				"so if a plain successful call no longer reports %[4]q the header's meaning has "+
				"changed and the fence conclusion cannot be drawn from it.",
				accountPath, headerResponder, accountResponder, responderService)
		}
		t.Logf("control: GET %s -> %d answered by %q", accountPath, accountStatus, accountResponder)

		listStatus, listResponder := rawGet(t, minterToken, realTokensPath)
		assertFenced(t, http.MethodGet, realTokensPath, listStatus, listResponder,
			"GET is what the DO reconciler uses to find orphaned tokens, so the reconciler cannot "+
				"work against real DO either")

		mintStatus := attemptMint(t, minter, minterToken)
		mintResponder := responderSeen(minter, http.MethodPost, realTokensPath)
		assertFenced(t, http.MethodPost, realTokensPath, mintStatus, mintResponder,
			"POST is the plugin's entire mint path (do_client.go CreateToken)")
	})
}

// attemptMint tries the mint the plugin would perform and returns the status. If
// DO unexpectedly ALLOWS it, this is the good-news path: prove the credential is
// real, revoke it, and fail loudly so the finding gets revisited rather than a
// live PAT being left on the account.
func attemptMint(t *testing.T, minter *doClient, minterToken string) int {
	t.Helper()
	ctx := t.Context()
	sweepProbeTokens(t, minter, minterToken)

	name := probeNamePrefix + time.Now().UTC().Format("20060102T150405Z")
	scopes := probeScopes()
	t.Logf("attempting POST %s as %q with scopes %v", realTokensPath, name, scopes)

	minted, status, err := minter.CreateToken(ctx, name, scopes)
	if err != nil {
		t.Logf("POST %s -> %d: %v", realTokensPath, status, scrubSecrets(err.Error(), minterToken))
		return status
	}

	// Everything from here is the path that has never executed against real DO.
	defer func() {
		delStatus, delErr := minter.DeleteToken(context.WithoutCancel(ctx), minted.Token.ID)
		if delErr != nil && delStatus != http.StatusNotFound {
			t.Errorf("CLEANUP FAILED — token id=%q may still exist upstream: %v",
				minted.Token.ID, scrubSecrets(delErr.Error(), minterToken))
		}
	}()

	if minted.Token.ID == "" {
		t.Errorf("mint response has no token.id: revoke and lease tracking key off this, so the " +
			"credential would be unrevocable. Check the recorded response for the real field name.")
	}
	if minted.Token.AccessToken == "" {
		t.Errorf("mint response has no token.access_token: THIS IS THE CREDENTIAL. The plugin would " +
			"return an empty secret and report success. Check the recorded response in " +
			"testdata/cloud-real/ for the field DO actually uses.")
	}
	if minted.Token.ID == "" || minted.Token.AccessToken == "" {
		return status
	}
	t.Logf("minted token id=%q name=%q access_token=%d chars",
		minted.Token.ID, minted.Token.Name, len(minted.Token.AccessToken))

	assertMintedTokenWorks(t, minted.Token.AccessToken, minterToken)
	if delStatus, err := minter.DeleteToken(ctx, minted.Token.ID); err != nil {
		t.Errorf("DELETE %s/%s returned %d: %v\nDO credentials have NO upstream expiry, so hard "+
			"revoke plus the reconciler is the only thing bounding a credential's life "+
			"(docs/ttl-semantics.md).",
			realTokensPath, minted.Token.ID, delStatus, scrubSecrets(err.Error(), minterToken))
	} else {
		assertRevokedTokenStopsWorking(t, minted.Token.AccessToken, minterToken)
	}
	return status
}

// assertFenced pins the finding: this method+path is refused, and refused by the
// EDGE rather than by a service. A failure here means DO changed, which is the one
// outcome worth interrupting someone for.
func assertFenced(t *testing.T, method, path string, status int, responder, consequence string) {
	t.Helper()
	switch status {
	case http.StatusForbidden:
		if responder != responderEdge {
			t.Errorf("%s %s is still 403, but %s is now %q rather than %q. The refusal has moved "+
				"from DO's edge to a service, which would mean it is a PRIVILEGE decision after all "+
				"and a differently-privileged credential might pass. Re-verify D1 in "+
				"docs/do-api-verification-2026-08-21.md.",
				method, path, headerResponder, responder, responderEdge)
			return
		}
		t.Logf("%s %s -> 403 from %q (fence intact). %s", method, path, responder, consequence)
	case http.StatusCreated, http.StatusOK:
		t.Errorf("GOOD NEWS, AND A SPEC CHANGE: %s %s now returns %d for an API token (answered by "+
			"%q). The fence documented in KI-009 is gone, so DO JIT minting may be viable again — "+
			"re-verify D1/D5 in docs/do-api-verification-2026-08-21.md, re-check whether the mint "+
			"request accepts an expiry field (that would give DO a native TTL), and revisit the "+
			"decision to treat credential-do as shape-only.",
			method, path, status, responder)
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		t.Errorf("%s %s now returns %d rather than 403: the endpoint has been withdrawn outright "+
			"rather than fenced. Same conclusion for the plugin, different reason — update "+
			"docs/do-api-verification-2026-08-21.md (D1).", method, path, status)
	default:
		t.Errorf("%s %s returned an unexpected %d (answered by %q); check the recorded response",
			method, path, status, responder)
	}
}

// rawGet reports the status and the answering layer of a bare authenticated GET.
// This deliberately does not use doClient: it is diagnostic scaffolding, not part
// of what is under test, and doClient exposes neither a generic reader nor
// response headers.
//
// It is also deliberately NOT recorded. testdata/cloud-real/ is a fixture set of
// the plugin's own client surface — every file in it is something the fake is
// answerable for (fake_parity_test.go) — and a 34 KB dump of /v2/regions would be
// neither that nor evidence of anything the failure message does not already say.
func rawGet(t *testing.T, token, path string) (status int, responder string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, realDOBaseURL+path, http.NoBody)
	if err != nil {
		t.Logf("diagnostic GET %s could not be built: %v", path, err)
		return 0, responderUnobserved
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		t.Logf("diagnostic GET %s errored: %v", path, scrubSecrets(err.Error(), token))
		return 0, responderUnobserved
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	responder = resp.Header.Get(headerResponder)
	if responder == "" {
		responder = responderUnobserved
	}
	return resp.StatusCode, responder
}

// requireRealDOToken fails loudly rather than skipping: see envRealDOToken.
func requireRealDOToken(t *testing.T) string {
	t.Helper()
	token := strings.TrimSpace(os.Getenv(envRealDOToken))
	if token == "" {
		t.Fatalf("%s is not set. The cloud_real build tag is the opt-in, so this is a failure and "+
			"not a skip — a real-cloud run that passes without credentials proves nothing.",
			envRealDOToken)
	}
	return token
}

// probeScopes reads the requested scopes, comma-separated.
func probeScopes() []string {
	raw := strings.TrimSpace(os.Getenv(envRealDOScopes))
	if raw == "" {
		raw = defaultProbeScopes
	}
	parts := strings.Split(raw, ",")
	scopes := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}
	return scopes
}

// realDOClient builds the plugin's own client against real DO, with response
// recording wired into its transport. secrets are the values that must never
// reach a recording on disk.
func realDOClient(t *testing.T, token string, secrets ...string) *doClient {
	t.Helper()
	client := newDOClient(realDOBaseURL, token)
	client.httpClient.Transport = newRecordingTransport(t, secrets...)
	return client
}

// assertMintedTokenWorks proves the minted string is a usable credential and not
// just a well-shaped response — the difference between "DO accepted the call" and
// "the plugin issued something a caller can use". Unreachable while the fence
// holds; kept because it is exactly what must run the day it lifts.
func assertMintedTokenWorks(t *testing.T, mintedToken, minterToken string) {
	t.Helper()
	minted := realDOClient(t, mintedToken, minterToken, mintedToken)
	status, err := minted.CheckHealth(t.Context())
	if err != nil {
		t.Fatalf("using the minted token errored: %v", scrubSecrets(err.Error(), minterToken, mintedToken))
	}
	switch status {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		t.Errorf("the minted token was rejected (%d) by GET %s. Either the token is not live yet, or "+
			"the requested scopes (%v) do not include account read — try %s=<scope> to explore the "+
			"vocabulary. Note the plugin passes role `scopes` through unvalidated, so an unusable "+
			"scope set surfaces only here.",
			status, accountPath, probeScopes(), envRealDOScopes)
	default:
		t.Errorf("using the minted token returned %d", status)
	}
}

// assertRevokedTokenStopsWorking is the assertion that matters most for DO: with
// no upstream expiry, revoke is the only thing that bounds an issued credential.
func assertRevokedTokenStopsWorking(t *testing.T, revokedToken, minterToken string) {
	t.Helper()
	revoked := realDOClient(t, revokedToken, minterToken, revokedToken)
	deadline := time.Now().Add(revokeVisibilityTimeout)
	for attempt := 1; ; attempt++ {
		status, err := revoked.CheckHealth(t.Context())
		if err != nil {
			t.Fatalf("post-revoke check errored: %v", scrubSecrets(err.Error(), minterToken, revokedToken))
		}
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			if attempt > 1 {
				t.Logf("revoked token stopped working after %d attempts — revocation is not "+
					"instantaneous, which widens the window in docs/ttl-semantics.md", attempt)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("a DELETEd token still authenticates (%d) after %s. DO credentials have no "+
				"upstream expiry, so if revoke does not actually revoke, nothing bounds an issued "+
				"credential's life.", status, revokeVisibilityTimeout)
			return
		}
		time.Sleep(revokeVisibilityPoll)
	}
}

// sweepProbeTokens deletes tokens left behind by an earlier failed run. Scoped
// strictly to the probe prefix — the same owner-tag discipline the reconciler
// uses, and the reason this is safe to run unattended.
func sweepProbeTokens(t *testing.T, minter *doClient, minterToken string) {
	t.Helper()
	tokens, err := minter.ListTokens(t.Context())
	if err != nil {
		t.Logf("pre-run sweep could not list tokens (continuing): %v",
			scrubSecrets(err.Error(), minterToken))
		return
	}
	for _, tok := range tokens {
		if !strings.HasPrefix(tok.Name, probeNamePrefix) {
			continue
		}
		t.Logf("sweeping leftover probe token id=%q name=%q", tok.ID, tok.Name)
		if _, err := minter.DeleteToken(t.Context(), tok.ID); err != nil {
			t.Logf("sweep delete failed for id=%q: %v", tok.ID, scrubSecrets(err.Error(), minterToken))
		}
	}
}
