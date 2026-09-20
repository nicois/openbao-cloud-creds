package credenvelope_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
)

// The vocabulary is a contract a client pins against, so it has to be closed and
// self-consistent: an unknown kind must not validate, and every declared kind must.
func TestCredentialKindVocabularyIsClosed(t *testing.T) {
	kinds := credenvelope.AllCredentialKinds()
	if len(kinds) == 0 {
		t.Fatal("the vocabulary is empty")
	}
	seen := map[credenvelope.CredentialKind]bool{}
	for _, k := range kinds {
		if seen[k] {
			t.Errorf("kind %q appears twice", k)
		}
		seen[k] = true
		if !credenvelope.ValidCredentialKind(k) {
			t.Errorf("declared kind %q does not validate", k)
		}
	}
	for _, bad := range []credenvelope.CredentialKind{"", "smtp", "SIGV4_SESSION", "sigv4-session"} {
		if credenvelope.ValidCredentialKind(bad) {
			t.Errorf("%q validated but is not in the vocabulary", bad)
		}
	}
}

// RequireCredentialKind is the whole mechanism: an unpinned read is served, a matching
// pin is served, and a mismatch is refused with a code a client can act on.
func TestRequireCredentialKind(t *testing.T) {
	served := credenvelope.KindSigV4Session

	t.Run("an unpinned read is served", func(t *testing.T) {
		// Omitting the pin must keep working: it is how a human explores with `bao read`,
		// and the response still TELLS them the shape in metadata.credential_kind.
		if resp := credenvelope.RequireCredentialKind("", served); resp != nil {
			t.Fatalf("an unpinned read was refused: %v", resp)
		}
	})

	t.Run("a matching pin is served", func(t *testing.T) {
		if resp := credenvelope.RequireCredentialKind(string(served), served); resp != nil {
			t.Fatalf("a pin matching what this role serves was refused: %v", resp)
		}
	})

	t.Run("a mismatched pin is refused, and says both shapes", func(t *testing.T) {
		resp := credenvelope.RequireCredentialKind(string(credenvelope.KindBasicAuth), served)
		if resp == nil || !resp.IsError() {
			t.Fatal("a client asking for a shape this role does not serve was served anyway — which " +
				"means it parses a payload it did not ask for")
		}
		got := resp.Error().Error()
		for _, want := range []string{
			string(credenvelope.ErrCredentialKindUnsupported),
			string(credenvelope.KindBasicAuth),
			string(served),
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the refusal does not mention %q: %v", want, got)
			}
		}
	})

	t.Run("an unknown pin is refused as unsupported, not as internal", func(t *testing.T) {
		// A client from a future version asking for a shape this binary has never heard
		// of is the ordinary case in a rolling upgrade, and it must get the code that
		// tells it to fall back — not one that says "page a human".
		resp := credenvelope.RequireCredentialKind("smtp", served)
		if resp == nil || !resp.IsError() {
			t.Fatal("an unknown credential_kind was accepted")
		}
		if got := resp.Error().Error(); !strings.Contains(got, string(credenvelope.ErrCredentialKindUnsupported)) {
			t.Errorf("an unknown kind should be credential_kind_unsupported, got: %v", got)
		}
	})
}

// The code has to be in AllCodes, or the error-taxonomy conformance suite — which
// requires every client-visible code to be in that list — would reject it.
func TestCredentialKindCodeIsInTheVocabulary(t *testing.T) {
	if slices.Contains(credenvelope.AllCodes(), credenvelope.ErrCredentialKindUnsupported) {
		return
	}
	t.Fatal("ErrCredentialKindUnsupported is not in AllCodes(), so the error-taxonomy suite would " +
		"reject a response carrying it")
}
