package credentialdo_test

import (
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// setupSpacesBackend returns a backend configured against srv with a `spaces` role that
// mints Spaces keys, alongside the token role setupConfiguredBackend already creates —
// so every test here also proves the two credential types coexist on one mount.
func setupSpacesBackend(t *testing.T, srv *fakes.DOServer) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := setupConfiguredBackend(t, srv.URL)
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/spaces", Storage: storage,
		Data: map[string]any{
			"default_ttl":     900,
			"max_ttl":         3600,
			"credential_type": "spaces_key",
			"grants":          "backups:read",
			"region":          "nyc3",
			"minter_set":      "default",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("spaces role write failed: err=%v resp=%v", err, resp)
	}
	return b, storage
}

func issueFrom(t *testing.T, b logical.Backend, storage logical.Storage, role string,
	data map[string]any,
) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + role,
		Storage:   storage,
		Data:      data,
	})
	if err != nil {
		t.Fatalf("creds read on %q returned a hard error: %v", role, err)
	}
	return resp
}

func TestSpacesCreds_IssuesAnS3Credential(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupSpacesBackend(t, srv)

	resp := issueFrom(t, b, storage, "spaces", nil)
	if resp == nil || resp.IsError() {
		t.Fatalf("issuing a Spaces key failed: %v", resp)
	}

	cred, ok := resp.Data["credential"].(map[string]any)
	if !ok {
		t.Fatalf("expected a credential object, got %T", resp.Data["credential"])
	}
	// Exactly the S3 shape: everything an S3 client needs and nothing else. The endpoint
	// and region are in the credential block, not metadata, because a session cannot be
	// constructed without them — see credenvelope.KindS3Credentials.
	for _, key := range []string{"access_key_id", "secret_access_key", "endpoint", "region"} {
		if v, _ := cred[key].(string); v == "" {
			t.Errorf("credential has no %q; an S3 client cannot be constructed without it. Got: %v",
				key, cred)
		}
	}
	if cred["endpoint"] != "https://nyc3.digitaloceanspaces.com" {
		t.Errorf("unexpected endpoint: %v", cred["endpoint"])
	}
	if cred["region"] != "nyc3" {
		t.Errorf("unexpected region: %v", cred["region"])
	}
	// A Spaces key is long-lived, not an STS session: a session_token here would mean the
	// plugin had confused the two SigV4 shapes.
	if _, present := cred["session_token"]; present {
		t.Error("the credential carries a session_token, which a Spaces key does not have")
	}

	meta := resp.Data["metadata"].(map[string]any)
	if meta["credential_kind"] != string(credenvelope.KindS3Credentials) {
		t.Errorf("expected credential_kind %q, got %v",
			credenvelope.KindS3Credentials, meta["credential_kind"])
	}
	if meta["scope_kind"] != string(credenvelope.ScopeKindGrants) {
		t.Errorf("expected scope_kind %q — a per-bucket grant list is not a permission-scope "+
			"list — got %v", credenvelope.ScopeKindGrants, meta["scope_kind"])
	}
	if meta["scope"] != "backups:read" {
		t.Errorf("expected the grants rendered into scope, got %v", meta["scope"])
	}

	// credential_id is what an auditor and the reconciler correlate on, and for this
	// credential type DO's only identifier is the access key.
	if resp.Data["credential_id"] != cred["access_key_id"] {
		t.Errorf("credential_id %v is not the access key %v; DO has no other identifier for a "+
			"Spaces key, so a revoke could not find it", resp.Data["credential_id"], cred["access_key_id"])
	}

	if srv.ProvisionedSpacesKeyCount() != 1 {
		t.Errorf("expected exactly one key upstream, got %d", srv.ProvisionedSpacesKeyCount())
	}
	// A Spaces key has no upstream expiry, so the lease stays renewable: renewal merely
	// defers the revoke that is the only thing bounding it.
	if resp.Secret == nil || !resp.Secret.Renewable {
		t.Error("expected a renewable lease: hard revoke is the only bound on this credential, " +
			"so deferring it is exactly what renewal means")
	}
	if resp.Secret.InternalData["upstream_access_key"] != cred["access_key_id"] {
		t.Errorf("the lease does not record the access key, so revoke has nothing to delete: %v",
			resp.Secret.InternalData)
	}
}

// Both directions of the pin, on one mount that serves both shapes. This is the case the
// credential_kind field was added for, and until this plugin gained a second type it
// could not be exercised anywhere: a client pinning the shape it can parse must be
// refused rather than handed the other one.
func TestSpacesCreds_PinningTheWrongShapeIsRefusedWithoutMinting(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupSpacesBackend(t, srv)

	t.Run("s3 pin against the token role", func(t *testing.T) {
		before := srv.ProvisionedCount()
		resp := issueFrom(t, b, storage, "test-role", map[string]any{
			"credential_kind": string(credenvelope.KindS3Credentials),
		})
		requireKindRefusal(t, resp, string(credenvelope.KindScopedToken))
		if srv.ProvisionedCount() != before {
			t.Error("a token was minted for a caller that pinned a shape it could not be given")
		}
	})

	t.Run("scoped_token pin against the spaces role", func(t *testing.T) {
		before := srv.ProvisionedSpacesKeyCount()
		resp := issueFrom(t, b, storage, "spaces", map[string]any{
			"credential_kind": string(credenvelope.KindScopedToken),
		})
		requireKindRefusal(t, resp, string(credenvelope.KindS3Credentials))
		if srv.ProvisionedSpacesKeyCount() != before {
			t.Error("a Spaces key was minted for a caller that pinned a shape it could not be given")
		}
	})

	t.Run("matching pins are served", func(t *testing.T) {
		resp := issueFrom(t, b, storage, "spaces", map[string]any{
			"credential_kind": string(credenvelope.KindS3Credentials),
		})
		if resp == nil || resp.IsError() {
			t.Fatalf("a matching pin was refused: %v", resp)
		}
	})
}

func requireKindRefusal(t *testing.T, resp *logical.Response, servedKind string) {
	t.Helper()
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the pin to be refused, got %v", resp)
	}
	msg := resp.Error().Error()
	if !strings.Contains(msg, string(credenvelope.ErrCredentialKindUnsupported)) {
		t.Errorf("expected error_code %q, got: %v", credenvelope.ErrCredentialKindUnsupported, msg)
	}
	// The refusal has to name what this role DOES serve, or a client cannot correct itself.
	if !strings.Contains(msg, servedKind) {
		t.Errorf("the refusal does not name the shape actually served (%q): %v", servedKind, msg)
	}
}

// A Spaces key has no upstream expiry whatsoever, so if revoke does not delete it the
// credential outlives its lease indefinitely — this is the only thing enforcing the TTL.
func TestSpacesCreds_RevokeDeletesTheKeyUpstream(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupSpacesBackend(t, srv)

	resp := issueFrom(t, b, storage, "spaces", nil)
	if resp == nil || resp.IsError() {
		t.Fatalf("issue failed: %v", resp)
	}
	accessKey := resp.Data["credential"].(map[string]any)["access_key_id"].(string)
	if !srv.HasSpacesKey(accessKey) {
		t.Fatal("the key was not created upstream")
	}

	revoke, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/spaces",
		Storage:   storage,
		Secret:    resp.Secret,
	})
	if err != nil || (revoke != nil && revoke.IsError()) {
		t.Fatalf("revoke failed: err=%v resp=%v", err, revoke)
	}
	if srv.HasSpacesKey(accessKey) {
		t.Error("the Spaces key survived its lease; it has no upstream expiry, so it is now " +
			"permanent")
	}
}

// The two credential types are tracked under separate prefixes because they draw on
// separate upstream quotas — DO caps Spaces keys at 200 per account — and pkg/mintercapacity
// counts one prefix at a time. Sharing a prefix would count a token against the Spaces cap.
func TestSpacesCreds_TracksUnderItsOwnPrefix(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupSpacesBackend(t, srv)

	if resp := issueFrom(t, b, storage, "spaces", nil); resp == nil || resp.IsError() {
		t.Fatalf("issue failed: %v", resp)
	}

	spacesKeys, err := storage.List(t.Context(), "active-spaces-keys/")
	if err != nil {
		t.Fatalf("listing the Spaces tracking prefix failed: %v", err)
	}
	if len(spacesKeys) != 1 {
		t.Errorf("expected one tracking record under active-spaces-keys/, got %v", spacesKeys)
	}

	tokens, err := storage.List(t.Context(), "active-tokens/")
	if err != nil {
		t.Fatalf("listing the token tracking prefix failed: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("a Spaces key was tracked as a token, so it would be counted against the wrong "+
			"quota and revoked by the wrong path: %v", tokens)
	}
}

// The distinct secret type is what makes the two revokes dispatchable: OpenBao routes a
// revoke on the secret type, so one type for both would send every revoke down one path.
func TestSpacesCreds_UsesItsOwnSecretType(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupSpacesBackend(t, srv)

	spaces := issueFrom(t, b, storage, "spaces", nil)
	if spaces == nil || spaces.IsError() {
		t.Fatalf("issue failed: %v", spaces)
	}
	token := issueFrom(t, b, storage, "test-role", nil)
	if token == nil || token.IsError() {
		t.Fatalf("issue failed: %v", token)
	}

	if spaces.Secret.TTL == 0 {
		t.Error("no TTL on the Spaces lease")
	}
	// framework.Secret dispatch is by type name, which the framework stamps into the
	// response's internal data as "secret_type".
	if got := spaces.Secret.InternalData["secret_type"]; got != "do_spaces_key" {
		t.Errorf("expected the Spaces lease to carry its own secret type, got %v", got)
	}
	if got := token.Secret.InternalData["secret_type"]; got != "do_token" {
		t.Errorf("the token lease's secret type changed to %v, which would break every lease "+
			"already outstanding across an upgrade", got)
	}
}

// A minter that may mint one credential type but not the other is the configuration that
// actually occurs on this cloud: /v2/tokens is fenced for every PAT while spaces_key:* is
// grantable. So a Spaces role must not be failed by a token refusal, nor vice versa.
func TestSpacesCreds_IssuanceIsUnaffectedByTheOtherTypeBeingRefused(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupSpacesBackend(t, srv)

	// This is real DigitalOcean: token minting refused, Spaces minting fine.
	srv.SetForbidCreate(true)

	resp := issueFrom(t, b, storage, "spaces", nil)
	if resp == nil || resp.IsError() {
		t.Fatalf("a Spaces key could not be issued while token minting was refused, which is "+
			"exactly the configuration real DigitalOcean presents: %v", resp)
	}
}
