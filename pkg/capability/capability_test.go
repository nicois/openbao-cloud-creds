package capability

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func okCheck(key, minter, role string, ran *[]string) Check {
	return Check{
		Key: key, Minter: minter, Roles: []string{role},
		Run: func(context.Context) (int, error) {
			*ran = append(*ran, key)
			return http.StatusOK, nil
		},
	}
}

func TestVerify_RunsEachDistinctCheckOnce(t *testing.T) {
	var ran []string
	checks := []Check{
		okCheck("a", "m1", "role-a", &ran),
		okCheck("a", "m1", "role-b", &ran),
		okCheck("b", "m1", "role-c", &ran),
	}
	result, err := Verify(t.Context(), checks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ran) != 2 {
		t.Fatalf("expected 2 probes for 2 distinct keys, ran %v", ran)
	}
	if result.Ran != 2 || result.Skipped != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

// A failure must name the minter and every role that shares the failing shape,
// so the operator knows what is broken and for whom.
func TestVerify_FailureNamesMinterAndAllSharingRoles(t *testing.T) {
	fail := func(context.Context) (int, error) { return http.StatusForbidden, errors.New("403 forbidden") }
	checks := []Check{
		{Key: "a", Minter: "minter-1", Roles: []string{"role-a"}, Run: fail},
		{Key: "a", Minter: "minter-1", Roles: []string{"role-b"}, Run: fail},
	}
	_, err := Verify(t.Context(), checks)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, want := range []string{"minter-1", "role-a", "role-b", "403 forbidden"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not mention %q", msg, want)
		}
	}
}

func TestVerify_UnsupportedIsSkippedNotFailed(t *testing.T) {
	checks := []Check{{
		Key: "a", Minter: "m1", Roles: []string{"role-a"},
		Run: func(context.Context) (int, error) { return 0, ErrUnsupported },
	}}
	result, err := Verify(t.Context(), checks)
	if err != nil {
		t.Fatalf("ErrUnsupported must not fail verification: %v", err)
	}
	if result.Skipped != 1 || result.Ran != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestDedupe_IsDeterministicallyOrdered(t *testing.T) {
	var ran []string
	got := Dedupe([]Check{
		okCheck("c", "m", "r", &ran),
		okCheck("a", "m", "r", &ran),
		okCheck("b", "m", "r", &ran),
	})
	keys := make([]string, 0, len(got))
	for _, c := range got {
		keys = append(keys, c.Key)
	}
	if strings.Join(keys, ",") != "a,b,c" {
		t.Fatalf("expected key-sorted order, got %v", keys)
	}
}

func putRole(t *testing.T, storage logical.Storage, name string, role map[string]any) {
	t.Helper()
	entry, err := logical.StorageEntryJSON("roles/"+name, role)
	if err != nil {
		t.Fatalf("entry build failed: %v", err)
	}
	if err := storage.Put(t.Context(), entry); err != nil {
		t.Fatalf("put failed: %v", err)
	}
}

func TestRolesBoundTo_FiltersBySetAndSkipsDisabled(t *testing.T) {
	storage := &logical.InmemStorage{}
	putRole(t, storage, "in-set", map[string]any{"name": "in-set", "minter_set": "alpha"})
	putRole(t, storage, "other-set", map[string]any{"name": "other-set", "minter_set": "beta"})
	putRole(t, storage, "off", map[string]any{"name": "off", "minter_set": "alpha", "disabled": true})

	bound, err := RolesBoundTo(t.Context(), storage, "alpha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bound) != 1 || bound[0].Name != "in-set" {
		t.Fatalf("unexpected bound roles: %+v", bound)
	}
	if len(bound[0].Raw) == 0 {
		t.Fatal("bound role carried no raw JSON for the caller to decode")
	}
}

// Probe credentials must carry THIS MOUNT's owner prefix: if the probe's own delete
// fails, the reconciler is what reclaims them — and only the mount that created it may
// (A19).
func TestProbeName_IsOwnerTaggedAndUnique(t *testing.T) {
	first, second := ProbeName("cloud-creds-testinstance-", "my-role"), ProbeName("cloud-creds-testinstance-", "my-role")
	for _, name := range []string{first, second} {
		if !strings.HasPrefix(name, "cloud-creds-testinstance-my-role-") {
			t.Fatalf("probe name %q lacks the owner prefix", name)
		}
	}
	if first == second {
		t.Fatalf("probe names collided: %q", first)
	}
}

// TestAnOperatorHintSurvivesRedaction pins the exception to the redaction rule. The rule is
// load-bearing — a probe's upstream text can name another tenant's resources and the same probe
// runs on a credential read (A4) — but it was also swallowing the plugin's OWN conclusion, which
// is the only actionable thing in some failures.
//
// The case that proved it: DigitalOcean answers a fenced mint with "You are not authorized to
// perform this operation", which sends an operator hunting for a privilege that does not exist.
// credential-do has said so in a hint since 2026-08-21 and every word was being dropped.
func TestAnOperatorHintSurvivesRedaction(t *testing.T) {
	const hint = "no privilege changes this; the endpoint is fenced"
	const upstreamText = "secret-bearing upstream body naming another tenant"

	failure := &Failure{
		Minter: "minter-1",
		Roles:  []string{"reader"},
		Err:    WithHint(hint, errors.New(upstreamText)),
	}

	message := failure.ClientMessage()
	if !strings.Contains(message, hint) {
		t.Errorf("the operator hint was redacted along with the upstream text, leaving the "+
			"caller nothing to act on: %s", message)
	}
	// The exception must not become a hole: upstream text still must not reach a client.
	if strings.Contains(message, upstreamText) {
		t.Errorf("the upstream's own error text reached the client response: %s", message)
	}
	// And the full error — the one that goes to the log — keeps both.
	if !strings.Contains(failure.Error(), upstreamText) {
		t.Errorf("the log rendering lost the upstream text, which is the only place it belongs: %s",
			failure.Error())
	}
}

// TestAFailureWithoutAHintIsUnchanged: the vast majority of probe failures carry no hint, and
// their message must not grow a stray separator or an empty clause.
func TestAFailureWithoutAHintIsUnchanged(t *testing.T) {
	failure := &Failure{
		Minter: "minter-1", Roles: []string{"reader"}, Err: errors.New("403 Forbidden"),
	}
	if got := failure.ClientMessage(); strings.HasSuffix(got, ". ") || strings.Contains(got, "..") {
		t.Errorf("a hintless failure rendered with a dangling separator: %q", got)
	}
	if HintFor(failure.Err) != "" {
		t.Error("HintFor invented a hint for an error that carries none")
	}
}
