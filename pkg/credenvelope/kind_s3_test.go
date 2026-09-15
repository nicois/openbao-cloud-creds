package credenvelope_test

import (
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
)

// The S3 credential shape is a de-facto standard rather than one cloud's invention, so
// it is named in the vocabulary and expected to be served by more than one plugin. This
// pins the two things a second implementor would otherwise have to guess.
func TestS3CredentialsKindIsInTheVocabulary(t *testing.T) {
	if !credenvelope.ValidCredentialKind(credenvelope.KindS3Credentials) {
		t.Fatalf("%q does not validate, so no plugin can declare it", credenvelope.KindS3Credentials)
	}
	var found bool
	for _, k := range credenvelope.AllCredentialKinds() {
		if k == credenvelope.KindS3Credentials {
			found = true
		}
	}
	if !found {
		t.Fatalf("%q is not in AllCredentialKinds(), so the lease conformance category would reject "+
			"an envelope carrying it", credenvelope.KindS3Credentials)
	}
}

// The distinction that earns this kind its place. An S3 credential and an STS session
// are both signed with SigV4, so a client could reasonably assume one can stand in for
// the other — but a long-lived object-storage key has no session_token and names its own
// endpoint, and an STS session has a token and no endpoint. Pinning must therefore
// distinguish them, or a client configured for one silently misreads the other.
func TestS3CredentialsIsNotInterchangeableWithASigV4Session(t *testing.T) {
	if credenvelope.KindS3Credentials == credenvelope.KindSigV4Session {
		t.Fatal("the two SigV4-signed shapes collapsed into one kind, so a client pinning a session " +
			"can be handed a credential with no session_token")
	}

	resp := credenvelope.RequireCredentialKind(
		string(credenvelope.KindSigV4Session), credenvelope.KindS3Credentials)
	if resp == nil || !resp.IsError() {
		t.Fatal("a client pinning sigv4_session was served an s3_credentials payload")
	}
	if got := resp.Error().Error(); !strings.Contains(got, string(credenvelope.ErrCredentialKindUnsupported)) {
		t.Errorf("the refusal should carry %q, got: %v", credenvelope.ErrCredentialKindUnsupported, got)
	}
}

// A per-resource grant list is not a permission-scope list, an ACL, a role name, an
// identity or "no scoping at all", so it needs its own way of being read: `scope` is
// `<resource>:<permission>` pairs. Without a distinct kind it would have to borrow
// `scopes`, and a client would read bucket grants as API permissions.
func TestGrantsScopeKindIsInTheVocabulary(t *testing.T) {
	if !credenvelope.ValidScopeKind(credenvelope.ScopeKindGrants) {
		t.Fatalf("%q does not validate, so no plugin can declare it", credenvelope.ScopeKindGrants)
	}
	var found bool
	for _, k := range credenvelope.AllScopeKinds() {
		if k == credenvelope.ScopeKindGrants {
			found = true
		}
	}
	if !found {
		t.Fatalf("%q is not in AllScopeKinds()", credenvelope.ScopeKindGrants)
	}
	if credenvelope.ScopeKindGrants == credenvelope.ScopeKindScopes {
		t.Fatal("a per-resource grant list and a permission-scope list are the same kind, so a " +
			"client cannot tell a bucket grant from an API scope")
	}
}
