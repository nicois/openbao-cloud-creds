package credentialdo_test

import (
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// writeSpacesRole writes a spaces_key role against a backend already configured for srv.
func writeSpacesRole(t *testing.T, b logical.Backend, storage logical.Storage, name string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/" + name, Storage: storage,
		Data: map[string]any{
			"default_ttl": 900, "max_ttl": 3600,
			"credential_type": "spaces_key",
			"grants":          "backups:read",
			"region":          "nyc3",
			"minter_set":      "default",
		},
	})
	if err != nil {
		t.Fatalf("role write returned a hard error: %v", err)
	}
	return resp
}

// The probe must mint the shape the ROLE asks for, not the shape the plugin used to serve.
// A probe that kept minting tokens would prove nothing about a Spaces role — and on real
// DigitalOcean it would prove the opposite of the truth, refusing every Spaces role because
// token minting is fenced.
func TestSpacesCapability_ProbesTheCredentialTypeTheRoleIssues(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL)

	// Exactly real DigitalOcean: /v2/tokens refused for every PAT (KI-009), Spaces keys fine.
	srv.SetForbidCreate(true)

	resp := writeSpacesRole(t, b, storage, "spaces")
	if resp != nil && resp.IsError() {
		t.Fatalf("a Spaces role was refused because TOKEN minting is fenced, which is the one "+
			"configuration this credential type exists to serve: %v", resp.Error())
	}
}

// The converse: a minter that cannot mint a Spaces key must be caught at role write, not
// at first issuance. Without this, an operator learns their PAT lacks
// spaces_key:create_credentials only when a client asks for a credential.
func TestSpacesCapability_RoleWriteIsRefusedWhenTheMinterCannotMintASpacesKey(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL)

	srv.SetForbidSpacesKeyCreate(true)

	resp := writeSpacesRole(t, b, storage, "spaces")
	if resp == nil || !resp.IsError() {
		t.Fatalf("a role bound to a minter that cannot mint a Spaces key was accepted: %v", resp)
	}
	msg := resp.Error().Error()
	if !strings.Contains(msg, string(credenvelope.ErrConfigInvalid)) {
		t.Errorf("expected error_code %q, got: %v", credenvelope.ErrConfigInvalid, msg)
	}
	// Every capability rejection carries the escape hatch, so an operator who knows better
	// than the probe is not stuck.
	if !strings.Contains(msg, "verify_minter_capability") {
		t.Errorf("the refusal does not mention the override: %v", msg)
	}
	// And it must NOT repeat the KI-009 hint, which is about token management and would send
	// an operator to read that this cloud can never mint — when in fact it can, and the real
	// fault is a missing spaces_key scope on their PAT.
	if strings.Contains(msg, "edge gateway") {
		t.Errorf("a Spaces probe failure was explained with the token-fence hint (KI-009), which "+
			"is about a different endpoint and a different remedy: %v", msg)
	}
}

// A probe is a real mint against a real quota — and this credential type's quota is the
// documented one (200 keys per account), so a probe that failed to clean up would consume it.
func TestSpacesCapability_ProbeCleansUpAfterItself(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL)

	if resp := writeSpacesRole(t, b, storage, "spaces"); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}

	if left := srv.ProvisionedSpacesKeyCount(); left != 0 {
		t.Errorf("the capability probe left %d Spaces key(s) upstream; each one counts against "+
			"the account's 200-key cap for as long as the reconciler takes to notice", left)
	}
}

// Probes must dedupe on the mint SHAPE, and a role's grants are part of that shape: two
// Spaces roles with different grants are different questions to the cloud, so a cached
// verdict for one must not answer for the other.
func TestSpacesCapability_GrantsArePartOfTheProbeIdentity(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL)

	if resp := writeSpacesRole(t, b, storage, "reader"); resp != nil && resp.IsError() {
		t.Fatalf("first role write failed: %v", resp.Error())
	}

	// A second role differing only in its grants. If the probe identity ignored grants,
	// this would be served from the cache and the refusal below would never happen.
	srv.SetForbidSpacesKeyCreate(true)
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/writer", Storage: storage,
		Data: map[string]any{
			"default_ttl": 900, "max_ttl": 3600,
			"credential_type": "spaces_key",
			"grants":          "archive:readwrite",
			"region":          "nyc3",
			"minter_set":      "default",
		},
	})
	if err != nil {
		t.Fatalf("role write returned a hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("a role asking for grants that had never been probed was accepted on a cached " +
			"verdict for different grants")
	}
}
