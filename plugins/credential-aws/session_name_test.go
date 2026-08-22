package credentialaws

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
)

// A RoleSessionName is the only per-lease identifier AWS records. It is what
// CloudTrail shows, so it is how an operator answers "which lease made this call"
// — and, since A19, it also carries the mount identity the reconciler matches on.
// Both facts used to be destroyed by a tail truncation.

const (
	testInstanceID = "abcdef0123456789"
	testRequestID  = "0f1e2d3c-4b5a-6978-8f0e-1d2c3b4a5968"
)

func TestSessionNameKeepsMountAndRequestIdentity(t *testing.T) {
	prefix := ownertag.Prefix(testInstanceID)

	cases := []struct {
		name string
		role string
	}{
		{"ordinary role name", "backup-reader"},
		{"role name at the old truncation boundary", strings.Repeat("r", 44)},
		{"role name longer than the whole cap", strings.Repeat("r", 120)},
		{"one-character role name", "r"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sessionNameFor(prefix, tc.role, testRequestID)

			if len(got) > maxSessionNameLen {
				t.Fatalf("session name is %d chars, over AWS's %d cap — STS rejects the AssumeRole "+
					"outright: %q", len(got), maxSessionNameLen, got)
			}
			if !ownertag.Owns(testInstanceID, got) {
				t.Errorf("session name %q does not carry this mount's owner prefix, so this mount's "+
					"own sessions are no longer attributable to it (A19)", got)
			}
			// The discriminator must survive, or every lease of this role shares one
			// session name and CloudTrail can no longer tell them apart (A29).
			disc := testRequestID[:sessionRequestIDKeepLen]
			if !strings.Contains(got, disc) && !strings.Contains(got, testRequestID) {
				t.Errorf("session name %q contains no part of request id %q, so no CloudTrail entry "+
					"can be traced back to the request that caused it", got, testRequestID)
			}
			if strings.Contains(disc, "-") && !strings.Contains(testRequestID, disc) {
				t.Errorf("the shortened request id %q is not a substring of the full id %q, so it "+
					"cannot be grepped in the audit device", disc, testRequestID)
			}
		})
	}
}

// TestSessionNamesDifferPerRequest is the property the truncation destroyed,
// stated directly: two issuances of the same long-named role must not collide.
func TestSessionNamesDifferPerRequest(t *testing.T) {
	prefix := ownertag.Prefix(testInstanceID)
	role := strings.Repeat("long-role-name-", 4)

	first := sessionNameFor(prefix, role, "11111111-2222-3333-4444-555555555555")
	second := sessionNameFor(prefix, role, "99999999-8888-7777-6666-555555555555")
	if first == second {
		t.Fatalf("two requests for the same role produced the identical session name %q; per-lease "+
			"attribution in CloudTrail is gone", first)
	}
}

// TestSessionNameRejectsNothingAWSWouldReject: AWS validates the session name
// against [\w+=,.@-] and fails the whole AssumeRole on a violation. A role name
// the cloud-agnostic API accepted must not be able to make issuance impossible.
func TestSessionNameSanitisesIllegalCharacters(t *testing.T) {
	prefix := ownertag.Prefix(testInstanceID)
	got := sessionNameFor(prefix, "role/with spaces:and*stars", testRequestID)
	for _, r := range got {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(sessionNameExtraChars, r):
		default:
			t.Fatalf("session name %q contains %q, which AWS rejects", got, r)
		}
	}
}

// TestIsNoSuchEntityMatchesTheCodeNotTheMessage is the guard for a
// deletion-confirmation bug: the retired-sweep treats NoSuchEntity as "already
// gone" and drops its tracking, so a FAILED delete misread as NoSuchEntity leaves
// a live long-lived access key upstream with nothing recording it.
func TestIsNoSuchEntityMatchesTheCodeNotTheMessage(t *testing.T) {
	if !isNoSuchEntity(&iamAPIError{Action: "DeleteAccessKey", Code: errNoSuchEntity, Message: "no such key"}) {
		t.Error("a genuine NoSuchEntity was not recognised, so an idempotent re-delete now fails")
	}

	// AWS echoes the request in its Message, and the message text is
	// upstream-controlled. This is the case the old strings.Contains match got wrong.
	impostor := &iamAPIError{
		Action:  "DeleteAccessKey",
		Code:    "AccessDenied",
		Message: `User is not authorized to perform iam:DeleteAccessKey on resource NoSuchEntity`,
	}
	if isNoSuchEntity(impostor) {
		t.Error("an AccessDenied whose message merely mentions NoSuchEntity was read as success: " +
			"the sweep would drop its tracking and leave a live minter key upstream")
	}

	if isNoSuchEntity(nil) {
		t.Error("a nil error must not be reported as NoSuchEntity")
	}
	if isNoSuchEntity(errors.New("connection reset")) {
		t.Error("a transport error must not be reported as NoSuchEntity")
	}
	// And it must still see through a wrapping, since callers wrap.
	wrapped := fmt.Errorf("sweeping retired minter: %w",
		&iamAPIError{Action: "DeleteAccessKey", Code: errNoSuchEntity})
	if !isNoSuchEntity(wrapped) {
		t.Error("a wrapped NoSuchEntity was not recognised")
	}
}
