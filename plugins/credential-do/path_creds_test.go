package credentialdo_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func setupConfiguredBackend(t *testing.T, doURL string, opts ...backendOption) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t, opts...)

	// config: operational settings only
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]any{"do_api_url": doURL},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// minter set
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/default", Storage: storage,
		Data: map[string]any{
			"minters": []any{
				map[string]any{"id": "minter-1", "token": "dop_v1_test", "never_expires": true},
			},
		},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write failed: err=%v resp=%v", err, resp)
	}

	// role bound to the set
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/test-role", Storage: storage,
		Data: map[string]any{
			"default_ttl": 900, "max_ttl": 3600, "scopes": "read,write", "minter_set": "default",
		},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}
	return b, storage
}

func TestCredsIssue(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("creds read failed: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("creds read error: %v", resp)
	}

	if resp.Data["cloud"] != "do" {
		t.Fatalf("expected cloud=do, got %v", resp.Data["cloud"])
	}
	if resp.Data["role"] != "test-role" {
		t.Fatalf("expected role=test-role, got %v", resp.Data["role"])
	}
	if resp.Data["credential_id"] == nil || resp.Data["credential_id"] == "" {
		t.Fatal("expected credential_id")
	}

	cred, ok := resp.Data["credential"].(map[string]any)
	if !ok {
		t.Fatalf("expected credential map, got %T", resp.Data["credential"])
	}
	if cred["token"] == nil {
		t.Fatal("expected credential.token")
	}

	// Verify lease internal data has upstream ID for revoke
	if resp.Secret == nil {
		t.Fatal("expected secret/lease")
	}
	if resp.Secret.InternalData["upstream_token_id"] == nil {
		t.Fatal("expected upstream_token_id in internal_data")
	}

	meta := resp.Data["metadata"].(map[string]any)
	if meta["minter_set"] != "default" {
		t.Fatalf("expected minter_set=default, got %v", meta["minter_set"])
	}
	if meta["minter_id"] != "minter-1" {
		t.Fatalf("expected minter_id=minter-1, got %v", meta["minter_id"])
	}
	if meta["api_version"] != credenvelope.APIVersion {
		t.Fatalf("expected api_version=%s, got %v", credenvelope.APIVersion, meta["api_version"])
	}
}

func TestMinterSetIsolation(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL) // has set "default" + role "test-role"

	// Add a second, independent set "secondary" and a role bound to it.
	req := &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/secondary", Storage: storage,
		Data: map[string]any{"minters": []any{
			map[string]any{"id": "minter-2", "token": "dop_v1_other", "never_expires": true},
		}},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("secondary set write: err=%v resp=%v", err, resp)
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/role2", Storage: storage,
		Data: map[string]any{"default_ttl": 900, "max_ttl": 3600, "scopes": "read", "minter_set": "secondary"},
	}
	if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role2 write: err=%v resp=%v", err, resp)
	}

	// role2 must mint via minter-2.
	req = &logical.Request{Operation: logical.ReadOperation, Path: "creds/role2", Storage: storage}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("role2 issue failed: err=%v resp=%v", err, resp)
	}
	meta := resp.Data["metadata"].(map[string]any)
	if meta["minter_set"] != "secondary" || meta["minter_id"] != "minter-2" {
		t.Fatalf("role2 used wrong minter: set=%v id=%v", meta["minter_set"], meta["minter_id"])
	}
}

// Scope names used by TestPerRoleScopesFromSharedMinterSet. Hoisted to consts
// because goconst counts test literals against production files in the package.
const (
	scopeDropletRead   = "droplet:read"
	scopeDropletDelete = "droplet:delete"
	sharedMinterSet    = "default"
	sharedMinterID     = "minter-1"
)

// TestPerRoleScopesFromSharedMinterSet covers the two-role least-privilege shape:
// one role may only read Droplets, another may only delete them, and BOTH mint
// from the same minter set (one upstream minter PAT). Each issued credential must
// carry only its own role's scopes — the minter's privilege is not inherited by
// the credentials it mints.
func TestPerRoleScopesFromSharedMinterSet(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL) // set "default" (minter-1) + role "test-role"

	for roleName, scope := range map[string]string{
		"droplet-reader":  scopeDropletRead,
		"droplet-deleter": scopeDropletDelete,
	} {
		req := &logical.Request{
			Operation: logical.UpdateOperation, Path: "roles/" + roleName, Storage: storage,
			Data: map[string]any{
				"default_ttl": 900, "max_ttl": 3600,
				"scopes": scope, "minter_set": sharedMinterSet,
			},
		}
		if resp, err := b.HandleRequest(t.Context(), req); err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("%s role write: err=%v resp=%v", roleName, err, resp)
		}
	}

	issue := func(roleName string) *logical.Response {
		t.Helper()
		req := &logical.Request{Operation: logical.ReadOperation, Path: "creds/" + roleName, Storage: storage}
		resp, err := b.HandleRequest(t.Context(), req)
		if err != nil || resp == nil || resp.IsError() {
			t.Fatalf("%s issue failed: err=%v resp=%v", roleName, err, resp)
		}
		return resp
	}

	readerResp, deleterResp := issue("droplet-reader"), issue("droplet-deleter")

	for _, tc := range []struct {
		role  string
		resp  *logical.Response
		scope string
	}{
		{"droplet-reader", readerResp, scopeDropletRead},
		{"droplet-deleter", deleterResp, scopeDropletDelete},
	} {
		cred := tc.resp.Data["credential"].(map[string]any)
		scopes, ok := cred["scopes"].([]string)
		if !ok {
			t.Fatalf("%s: expected credential.scopes []string, got %T", tc.role, cred["scopes"])
		}
		if len(scopes) != 1 || scopes[0] != tc.scope {
			t.Fatalf("%s: expected credential.scopes=[%s], got %v", tc.role, tc.scope, scopes)
		}

		meta := tc.resp.Data["metadata"].(map[string]any)
		if meta["scope"] != tc.scope {
			t.Fatalf("%s: expected metadata.scope=%s, got %v", tc.role, tc.scope, meta["scope"])
		}
		// Both roles share one minter set and one minter within it.
		if meta["minter_set"] != sharedMinterSet || meta["minter_id"] != sharedMinterID {
			t.Fatalf("%s: expected set=%s minter=%s, got set=%v minter=%v",
				tc.role, sharedMinterSet, sharedMinterID, meta["minter_set"], meta["minter_id"])
		}
	}

	// Distinct upstream credentials, so revoking one cannot affect the other.
	readerID := readerResp.Data["credential_id"]
	deleterID := deleterResp.Data["credential_id"]
	if readerID == nil || readerID == deleterID {
		t.Fatalf("expected distinct credential_ids, got %v and %v", readerID, deleterID)
	}
}

func TestCredsRevoke(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// Issue
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	// Revoke
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    resp.Secret,
	}
	resp, err = b.HandleRequest(t.Context(), revokeReq)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("revoke error: %v", resp)
	}
}

func TestCredsIssue_RoleNotFound_HasErrorCode(t *testing.T) {
	b, storage := getTestBackend(t)
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/nope", Storage: storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response")
	}
	// error_code rides in the client-visible message string: "<code>: <msg>"
	got := resp.Error().Error()
	if !strings.HasPrefix(got, "role_not_found: ") {
		t.Fatalf("expected role_not_found: prefix, got %q", got)
	}
}

func TestCredsIssue_RoleNotFound(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/nonexistent",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing role")
	}
}

func TestCredsIssue_ClassifiesQuotaError(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupConfiguredBackend(t, srv.URL)
	srv.SetNextStatus(http.StatusTooManyRequests) // next create returns 429

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response, got %v", resp)
	}
	msg := resp.Error().Error()
	if !strings.HasPrefix(msg, string(credenvelope.ErrUpstreamQuotaExceeded)+":") {
		t.Fatalf("expected upstream_quota_exceeded code, got %q", msg)
	}
	// #5: the raw upstream body must NOT leak to the client.
	if strings.Contains(msg, "server_error") {
		t.Fatalf("client message leaked upstream detail: %q", msg)
	}
}

// issueCreds mints one credential and fails on anything but success.
func issueCreds(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	})
	if err != nil {
		t.Fatalf("creds read failed: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("creds read error: %v", resp)
	}
	return resp
}

// reportedScopes reads the permission list the envelope publishes, from both places it appears: the
// credential block's typed list and metadata.scope's flat string. Two renderings of one value, so a
// test checking only one would not notice them diverging.
func reportedScopes(t *testing.T, resp *logical.Response) (typed []string, flat string) {
	t.Helper()
	cred, ok := resp.Data["credential"].(map[string]any)
	if !ok {
		t.Fatalf("expected credential map, got %T", resp.Data["credential"])
	}
	list, ok := cred["scopes"].([]string)
	if !ok {
		t.Fatalf("credential.scopes is %T, not a string list", cred["scopes"])
	}
	meta, ok := resp.Data["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata map, got %T", resp.Data["metadata"])
	}
	flat, _ = meta["scope"].(string)
	return list, flat
}

// TestCredsReportAGrantWiderThanTheRoleAskedFor: the reason a credential carries a scope list is so
// a client can CHECK it is scoped the way it expected. A list derived from the role cannot disagree
// with the role, so publishing the role's own request answered that check from the question — and a
// client verifying a subset concludes "correctly scoped" about a token that can do more.
func TestCredsReportAGrantWiderThanTheRoleAskedFor(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	// Sticky, like every knob on these fakes: restored so nothing later inherits it.
	srv.SetForcedExtraScopes([]string{"actions:read"})
	t.Cleanup(func() { srv.SetForcedExtraScopes(nil) })

	b, storage := setupConfiguredBackend(t, srv.URL)
	list, flat := reportedScopes(t, issueCreds(t, b, storage))

	if !slices.Contains(list, "actions:read") {
		t.Errorf("the credential reports %v, omitting a permission the token actually carries", list)
	}
	if !strings.Contains(flat, "actions:read") {
		t.Errorf("metadata.scope is %q and disagrees with the credential block %v", flat, list)
	}
}

// TestCredsDoNotClaimAScopeTheUpstreamWithheld is the direction that costs a caller something: told
// the credential carries `write` when it does not, it is refused by DigitalOcean at some later call,
// far from the role that promised it.
func TestCredsDoNotClaimAScopeTheUpstreamWithheld(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	srv.SetWithheldScopes([]string{"write"})
	t.Cleanup(func() { srv.SetWithheldScopes(nil) })

	b, storage := setupConfiguredBackend(t, srv.URL)
	list, flat := reportedScopes(t, issueCreds(t, b, storage))

	if slices.Contains(list, "write") {
		t.Errorf("the credential claims %v, but the upstream withheld `write`; publishing the "+
			"request tells a client the credential is correctly scoped when it is not", list)
	}
	if strings.Contains(flat, "write") {
		t.Errorf("metadata.scope is %q and still claims a withheld permission", flat)
	}
	if !slices.Contains(list, "read") {
		t.Errorf("the permission that WAS granted is missing from %v", list)
	}
}
