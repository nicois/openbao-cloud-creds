//go:build cloud_real

package credentialdo

import (
	"context"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
)

// The real-cloud probe for Spaces access keys — the credential type this plugin can
// actually issue, and therefore the one whose shape must be verified rather than assumed.
//
// Everything about `/v2/tokens` was settled by real_cloud_test.go: fenced at DO's edge
// gateway for every PAT (KI-009), so that mint path is dead. `/v2/spaces/keys` is a
// different proposition, and a CONTESTED one: it is in DigitalOcean's public OpenAPI spec
// with full CRUD, while DO's own product docs say three times that Spaces keys "cannot
// currently be created, edited, or deleted using the DigitalOcean API or CLI", and an
// earlier probe of that path answered 404. The plugin is built on the spec being right.
// This file is what makes that claim answerable instead of asserted.
//
// It exists because the fake and the plugin were written from ONE reading of the same
// spec, so every shape they agree on is unverified by construction. Four such assumptions
// are load-bearing, and each has a consequence if wrong:
//
//	POST answers a bearer PAT with 201   -> if not, the credential type cannot be issued
//	                                        at all and the premise this plugin was built
//	                                        on is wrong
//	`key.access_key` / `key.secret_key`  -> a wrong field name mints successfully and
//	                                        hands the caller an EMPTY credential, while
//	                                        the access key the lease records for revoke is
//	                                        blank, so the key becomes unrevocable
//	the list envelope is {"keys": [...]}  -> a wrong envelope makes every listing look
//	                                        empty, which silently disables owner-tag
//	                                        orphan reclamation for a credential with no
//	                                        upstream expiry and a per-account cap
//	DELETE answers exactly 204            -> DeleteSpacesKey treats anything else as an
//	                                        error, so a 200 would make every revoke look
//	                                        failed and wedge leases (the KI-002 class)
//
// Like the token probe it drives the plugin's OWN client, not a fresh HTTP client: what
// is under test is the code the fake stands in for, decoding included.
//
// One thing it deliberately does NOT prove: that the minted key works against the S3
// endpoint. That needs a SigV4 signer, which this repository has no dependency for and
// which would be a substantial hand-rolled surface answering a question about Amazon's
// signing algorithm rather than about this plugin. So the credential's USABILITY is a
// declared gap (unlike AWS, where the probe does authenticate with what it minted); what
// is checked here is that the endpoint the plugin derives for the region is a real host.
//
//	export CLOUDREAL_DO_TOKEN=dop_v1_...
//	make test-cloud-real-do-spaces
//
// Recordings land in testdata/cloud-real/ scrubbed fail-closed, and the mint's are
// WITHHELD until the secret is known (real_cloud_record_test.go: withhold/release). Use a
// disposable account: a listing recording carries the account's other Spaces keys by name.

const (
	// envRealDOSpacesBucket names the bucket the probe asks for a grant on. DO's grants
	// are per-bucket, so a probe has to name one, and whether DO validates that it exists
	// is itself unverified — hence an override rather than a hard-coded name.
	envRealDOSpacesBucket = "CLOUDREAL_DO_SPACES_BUCKET"

	// defaultProbeBucket deliberately need not exist. The plugin accepts any bucket name
	// in a role's grants and cannot check existence (checkGrantPrivilege checks the privilege
	// shape, nothing else), so if DO refuses a grant on an absent bucket that is a real
	// finding about role writes — a role that passes every gate and fails every issuance.
	defaultProbeBucket = "cloud-creds-probe-bucket"

	// envRealDOSpacesRegion overrides the Spaces region, which decides the endpoint the
	// plugin hands to a client.
	envRealDOSpacesRegion = "CLOUDREAL_DO_SPACES_REGION"
	defaultProbeRegion    = "nyc3"

	// probeGrantPermission is the narrowest grant that is still a grant. fullaccess is
	// avoided on purpose: this probe runs against a real account, and an account-wide key,
	// however briefly it lives, is not what a test should create.
	probeGrantPermission = permissionRead
)

func TestRealDOSpacesKeys(t *testing.T) {
	// parent is the enclosing test, and the cleanup below MUST hang off it rather than off
	// the mint subtest: a subtest's Cleanup runs when that subtest ends, which would delete
	// the key before the listing and delete subtests ever saw it.
	parent := t
	minterToken := requireRealDOToken(t)
	minter := realDOClient(t, minterToken, minterToken)
	recorder := recorderOf(t, minter)
	ctx := t.Context()

	sweepProbeSpacesKeys(t, minter, minterToken)

	name := probeNamePrefix + time.Now().UTC().Format("20060102T150405Z")
	grants := []spacesGrant{{Bucket: probeBucket(), Permission: probeGrantPermission}}

	// minted is assigned by the first subtest and read by the rest. Subtests run in order,
	// so this is sequencing rather than shared mutable state — and each later subtest says
	// so rather than panicking on a nil.
	var minted *spacesKeyInfo

	t.Run("MintAnswersABearerPAT", func(t *testing.T) {
		t.Logf("attempting POST %s as %q with grants %v", spacesKeysPath, name, grants)

		// Hold the recordings: the response carries key material under field names that are
		// only ASSUMED, and an unanticipated one would be written to a public repository
		// before anything could notice.
		recorder.withhold()
		created, status, err := minter.CreateSpacesKey(ctx, name, grants)
		if err != nil {
			// Nothing was decoded, so nothing can be registered as a secret; the gates in
			// emit() still apply to whatever the error body was.
			if releaseErr := recorder.release(); releaseErr != nil {
				t.Errorf("the failed mint's response could not be recorded: %v", releaseErr)
			}
			reportMintRefusal(t, minter, status, scrubSecrets(err.Error(), minterToken))
			return
		}

		// The secret is known now, so register it (and the access key, which is half a
		// credential and travels in the DELETE path) before any of it reaches disk.
		if releaseErr := recorder.release(created.Key.SecretKey, created.Key.AccessKey); releaseErr != nil {
			t.Errorf("REFUSED to record the mint response: %v\nThe response is safe in memory, but "+
				"the recorder's redaction rules do not cover a field DigitalOcean used — extend "+
				"redactKeys before the next run so this run's evidence can be kept.", releaseErr)
		}
		if status != http.StatusCreated {
			t.Errorf("POST %s succeeded with status %d, not %d: CreateSpacesKey only accepts 201, so "+
				"a different success code would be reported to callers as a mint failure",
				spacesKeysPath, status, http.StatusCreated)
		}
		key := created.Key
		minted = &key
		parent.Cleanup(func() {
			// Always, even if the delete subtest never ran: an undeleted Spaces key has no
			// upstream expiry and counts against the account's cap forever. A 404 here is the
			// expected case — it means the delete subtest already did the work.
			if status, err := minter.DeleteSpacesKey(context.WithoutCancel(ctx), key.AccessKey); err != nil &&
				status != http.StatusNotFound {
				parent.Errorf("CLEANUP FAILED — a real Spaces key may still exist upstream under "+
					"name %q: %v", name, scrubSecrets(err.Error(), minterToken, key.SecretKey))
			}
		})
	})

	t.Run("MintReturnsKeyMaterialALeaseCanUse", func(t *testing.T) {
		key := requireMinted(t, minted)
		if key.AccessKey == "" {
			t.Errorf("the mint response has no key.access_key. THIS IS HALF THE CREDENTIAL, and it "+
				"is also what the lease records for revoke — so the plugin would return an "+
				"unusable credential AND be unable to revoke it. Check the recorded "+
				"POST%s_201 for the field DigitalOcean actually uses.", strings.ReplaceAll(spacesKeysPath, "/", "_"))
		}
		if key.SecretKey == "" {
			t.Errorf("the mint response has no key.secret_key. THIS IS THE SECRET, and DigitalOcean " +
				"returns it only once — there is no read-back — so a wrong field name here means an " +
				"empty credential handed out with a success response and no way to recover it.")
		}
		if key.Name != name {
			t.Errorf("DigitalOcean echoed the name as %q, not %q. The name IS the owner tag: the "+
				"reconciler recognises its own credentials by it (ownertag.Owns), so a normalised or "+
				"truncated name makes this mount's keys unreclaimable orphans.", key.Name, name)
		}
		if created := reconciler.ParseCreatedAt(key.CreatedAt); created.IsZero() {
			t.Errorf("key.created_at (%q) does not parse as a timestamp the reconciler understands. "+
				"An orphan with no creation time cannot clear the confirmation hold, so orphan "+
				"reclamation would never delete anything.", key.CreatedAt)
		}
		t.Logf("minted access_key=%d chars secret_key=%d chars created_at=%q",
			len(key.AccessKey), len(key.SecretKey), key.CreatedAt)
	})

	t.Run("GrantsAreHonouredAsWritten", func(t *testing.T) {
		key := requireMinted(t, minted)
		if reflect.DeepEqual(key.Grants, grants) {
			return
		}
		// Not merely cosmetic: DigitalOcean is known to PRIORITISE fullaccess over scoped
		// grants rather than refusing the mix (which is why parseGrants refuses it locally).
		// If a scoped request comes back widened, a role that reads as least-privilege is
		// issuing more than it says.
		for _, grant := range key.Grants {
			if grant.Permission == permissionFullAccess {
				t.Errorf("a %s grant was requested and DigitalOcean returned %s: the key is "+
					"ACCOUNT-WIDE while the role reads as least-privilege. parseGrants refuses the "+
					"fullaccess/scoped MIX locally, but this would be a silent widening of a single "+
					"scoped grant, which nothing local can prevent.",
					probeGrantPermission, permissionFullAccess)
				return
			}
		}
		t.Errorf("grants came back as %+v, not %+v. If the difference is normalisation, "+
			"metadata.scope will disagree with the credential's real privilege (renderGrants "+
			"reports what was WRITTEN); if the grant was dropped, the key is broader than the role.",
			key.Grants, grants)
	})

	t.Run("ListingUsesTheKeysEnvelopeAndWithholdsTheSecret", func(t *testing.T) {
		key := requireMinted(t, minted)
		listed := findSpacesKey(t, minter, minterToken, key.AccessKey)
		if listed == nil {
			t.Fatalf("the minted key is not in GET %s. Either the envelope is not {\"keys\": [...]} "+
				"— in which case every listing decodes as empty and owner-tag reclamation silently "+
				"reclaims nothing — or listing is not immediately consistent with create, which "+
				"would need a settle delay in the reconciler.", spacesKeysPath)
		}
		if listed.SecretKey != "" {
			t.Errorf("the LISTING returned a secret (%d chars). That contradicts secret-once-on-"+
				"create, and it means a recording of a listing carries live key material — check "+
				"the recorded GET before committing it.", len(listed.SecretKey))
		}
		if listed.Name != key.Name {
			t.Errorf("the listing reports name %q for this key while create reported %q; the "+
				"reconciler filters on the listed name, so it is the one that must carry the owner tag",
				listed.Name, key.Name)
		}
	})

	t.Run("TheEndpointTheRoleWouldHandOutIsARealHost", func(t *testing.T) {
		endpoint := spacesEndpointForRegion(probeRegion())
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, http.NoBody)
		if err != nil {
			t.Fatalf("building a request for %s failed: %v", endpoint, err)
		}
		resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
		if err != nil {
			// Not a failure: this host is outside the API domain, so a sandboxed or
			// egress-restricted runner cannot reach it, and that says nothing about DO.
			t.Logf("could not reach %s (%v). The endpoint could not be checked from here — an "+
				"egress allowlist or proxy would explain it; the credential's usability against "+
				"S3 is a declared gap either way.", endpoint, err)
			return
		}
		defer resp.Body.Close()
		t.Logf("%s answered %d unauthenticated, so the endpoint derived from region %q is a real "+
			"host (spacesEndpointForRegion)", endpoint, resp.StatusCode, probeRegion())
	})

	t.Run("DeleteAnswers204AndTheKeyStopsExisting", func(t *testing.T) {
		key := requireMinted(t, minted)
		status, err := minter.DeleteSpacesKey(ctx, key.AccessKey)
		if err != nil {
			t.Fatalf("DELETE %s/<access key> returned %d: %v\n"+
				"DeleteSpacesKey accepts ONLY 204, and a Spaces key has no upstream expiry — so if "+
				"this is a 200 or 202 the plugin reports every revoke as failed, retries it forever "+
				"(KI-002) and nothing bounds an issued credential's life "+
				"(docs/ttl-semantics.md).", spacesKeysPath, status, scrubSecrets(err.Error(), minterToken))
		}
		if status != http.StatusNoContent {
			t.Errorf("delete succeeded with %d, want %d", status, http.StatusNoContent)
		}
		if listed := findSpacesKey(t, minter, minterToken, key.AccessKey); listed != nil {
			t.Errorf("the key is still listed after a successful DELETE. Revoke plus the owner-tag " +
				"reconciler is the ONLY bound on this credential type, so a delete that reports " +
				"success without deleting means an unbounded credential and a quota that fills up.")
		}
	})
}

// reportMintRefusal turns a refused mint into the finding it actually is. The distinction
// that matters is WHO refused: DigitalOcean's edge gateway refusing the path is KI-009's
// shape repeating on this endpoint (no PAT would work, and the plugin's Spaces type is as
// dead as its token type), while a service refusing it is a privilege verdict about this
// PAT's scopes, which an operator can fix.
func reportMintRefusal(t *testing.T, minter *doClient, status int, scrubbedErr string) {
	t.Helper()
	responder := responderSeen(minter, http.MethodPost, spacesKeysPath)
	switch status {
	case http.StatusForbidden, http.StatusUnauthorized:
		if responder == responderEdge {
			t.Fatalf("POST %s -> %d answered by %q: the path is fenced off from API-token auth, "+
				"exactly as /v2/tokens is (KI-009). DigitalOcean's product docs would then be right "+
				"and its OpenAPI spec wrong, and credential-do has NOTHING it can mint — revisit "+
				"docs/cloud-credential-research.md and docs/object-storage-credential-audit.md, and "+
				"say so in known-issues.md.\n%s", spacesKeysPath, status, responder, scrubbedErr)
		}
		t.Fatalf("POST %s -> %d answered by %q: a privilege verdict, not a fence. The minter PAT "+
			"needs the Spaces-key scopes (spaces_key:create_credentials, and spaces_key:read for the "+
			"reconciler's listing) — a full-access PAT holds them. Re-run with one before drawing any "+
			"conclusion about the endpoint.\n%s", spacesKeysPath, status, responder, scrubbedErr)
	case http.StatusNotFound:
		t.Fatalf("POST %s -> 404 (answered by %q). This is the answer an earlier probe got, and it "+
			"is the one that settles the contest AGAINST the OpenAPI spec: DigitalOcean's product "+
			"docs say Spaces keys are control-panel-only, and a 404 on the documented path agrees "+
			"with them. The whole Spaces credential type rests on this call, so treat it as "+
			"unbuildable until DO's spec and its API agree.\n%s", spacesKeysPath, responder, scrubbedErr)
	case http.StatusUnprocessableEntity, http.StatusBadRequest:
		t.Fatalf("POST %s -> %d: the endpoint exists and REFUSED THIS REQUEST. The likeliest cause "+
			"is the grant naming bucket %q, which need not exist — set %s to a bucket the account "+
			"really has and re-run. If it passes then, role writes accept grants DigitalOcean will "+
			"reject at issuance, which checkGrantPrivilege cannot check and which therefore belongs in "+
			"the role's documentation.\n%s",
			spacesKeysPath, status, probeBucket(), envRealDOSpacesBucket, scrubbedErr)
	default:
		t.Fatalf("POST %s -> %d (answered by %q); check the recorded response\n%s",
			spacesKeysPath, status, responder, scrubbedErr)
	}
}

// requireMinted stops a dependent subtest with a pointer to the cause rather than a nil
// dereference: the mint is the premise of everything after it.
func requireMinted(t *testing.T, minted *spacesKeyInfo) spacesKeyInfo {
	t.Helper()
	if minted == nil {
		t.Skip("no key was minted; see MintAnswersABearerPAT for why")
	}
	return *minted
}

func findSpacesKey(t *testing.T, minter *doClient, minterToken, accessKey string) *spacesKeyInfo {
	t.Helper()
	keys, err := minter.ListSpacesKeys(t.Context())
	if err != nil {
		t.Fatalf("GET %s failed: %v\nThis is the reconciler's own call, so its failure means orphan "+
			"reclamation cannot work either.", spacesKeysPath, scrubSecrets(err.Error(), minterToken))
	}
	for i := range keys {
		if keys[i].AccessKey == accessKey {
			return &keys[i]
		}
	}
	return nil
}

// sweepProbeSpacesKeys removes keys left by a crashed earlier run. Scoped strictly to the
// probe prefix, the same owner-tag discipline the reconciler uses — and it matters more
// here than for tokens, because a leaked Spaces key never expires and the account's cap is
// what eventually breaks.
func sweepProbeSpacesKeys(t *testing.T, minter *doClient, minterToken string) {
	t.Helper()
	keys, err := minter.ListSpacesKeys(t.Context())
	if err != nil {
		t.Logf("pre-run sweep could not list Spaces keys (continuing): %v",
			scrubSecrets(err.Error(), minterToken))
		return
	}
	for _, key := range keys {
		if !strings.HasPrefix(key.Name, probeNamePrefix) {
			continue
		}
		t.Logf("sweeping leftover probe Spaces key name=%q", key.Name)
		if _, err := minter.DeleteSpacesKey(t.Context(), key.AccessKey); err != nil {
			t.Logf("sweep delete failed for %q: %v", key.Name, scrubSecrets(err.Error(), minterToken))
		}
	}
}

// recorderOf reaches the transport behind the plugin's client, so a caller can withhold a
// recording until it knows what in the response is secret.
func recorderOf(t *testing.T, client *doClient) *recordingTransport {
	t.Helper()
	rt, ok := client.httpClient.Transport.(*recordingTransport)
	if !ok {
		t.Fatalf("the client is not recording (%T): a real-cloud run that leaves no evidence is "+
			"most of its value spent for nothing", client.httpClient.Transport)
	}
	return rt
}

func probeBucket() string { return envOrDefault(envRealDOSpacesBucket, defaultProbeBucket) }
func probeRegion() string { return envOrDefault(envRealDOSpacesRegion, defaultProbeRegion) }

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
