package credentialgcp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Local literals for the capability tests.
const (
	capRolePath   = "roles/probe-role"
	capTargetSA   = "target-sa@my-project.iam.gserviceaccount.com"
	capScope      = "https://www.googleapis.com/auth/devstorage.read_only"
	capRoleTTL    = 3600
	capMinterJSON = "{\"k\":\"minter-1\"}"
)

// capMintRecorder records the generateAccessToken calls a fake impersonation
// client sees and can refuse them, either wholesale or for one minter's SA JSON.
// Refusing by minter is how the successor-cannot-mint case is expressed: a rotated
// key authenticates as the same service account, so only an impersonation attempt
// distinguishes it.
type capMintRecorder struct {
	mu           sync.Mutex
	calls        []capMintCall
	denyAll      bool
	denyJSONPart string
}

// capMintCall is one recorded probe/issuance mint request.
type capMintCall struct {
	serviceAccount string
	scopes         []string
	lifetime       time.Duration
}

func (r *capMintRecorder) generate(credentialsJSON string) GenerateAccessTokenFunc {
	return func(_ context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (string, time.Time, error) {
		r.mu.Lock()
		r.calls = append(r.calls, capMintCall{serviceAccount: serviceAccount, scopes: scopes, lifetime: lifetime})
		deny := r.denyAll || (r.denyJSONPart != "" && strings.Contains(credentialsJSON, r.denyJSONPart))
		r.mu.Unlock()
		if deny {
			return "", time.Time{}, fmt.Errorf(
				"PERMISSION_DENIED: the caller does not have permission to impersonate %s", serviceAccount)
		}
		return "ya29.probe-token", time.Now().Add(lifetime), nil
	}
}

func (r *capMintRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *capMintRecorder) last() (capMintCall, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		return capMintCall{}, false
	}
	return r.calls[len(r.calls)-1], true
}

func (r *capMintRecorder) setDenyAll(deny bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.denyAll = deny
}

func (r *capMintRecorder) setDenyJSONPart(part string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.denyJSONPart = part
}

// capBackend builds a rotation-capable backend whose impersonation client records
// (and can refuse) generateAccessToken while TestConnection keeps succeeding —
// the "healthy but cannot mint" shape.
func capBackend(t *testing.T, store *fakeSAKeyStore, minters []interface{}) (*backend, *capMintRecorder, logical.Storage) {
	t.Helper()
	bk, storage := newRotationBackend(t, store, minters)
	rec := &capMintRecorder{}
	SetIAMClientFactory(bk, func(credentialsJSON string) IAMCredentialsClient {
		return NewFakeIAMClient(rec.generate(credentialsJSON), nil)
	})
	return bk, rec, storage
}

// capWriteRole writes a role bound to the default set and returns the response.
func capWriteRole(t *testing.T, bk *backend, storage logical.Storage) *logical.Response {
	t.Helper()
	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: capRolePath, Storage: storage,
		Data: map[string]interface{}{
			fieldDefaultTTL: capRoleTTL, fieldMaxTTL: capRoleTTL,
			"service_account_email": capTargetSA,
			"scopes":                []string{capScope},
			fieldMinterSet:          defaultSetName,
		},
	})
	if err != nil {
		t.Fatalf("role write errored: %v", err)
	}
	return resp
}

// TestConnection proves the minter's own key is live; impersonation needs
// roles/iam.serviceAccountTokenCreator on the TARGET service account, per target.
// A minter without it is healthy forever, so the role must not bind to it.
func TestCapability_RoleWriteRejectedWhenImpersonationDenied(t *testing.T) {
	bk, rec, storage := capBackend(t, newFakeSAKeyStore(), []interface{}{
		neverExpiresMinter(rotMinter1ID, capMinterJSON),
	})
	rec.setDenyAll(true)

	resp := capWriteRole(t, bk, storage)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the role write to be rejected, got %v", resp)
	}
	if rec.count() == 0 {
		t.Fatal("the role write did not attempt a probe generateAccessToken")
	}
	read, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: capRolePath, Storage: storage,
	})
	if err != nil {
		t.Fatalf("role read errored: %v", err)
	}
	if read != nil {
		t.Fatalf("rejected role write persisted the role: %v", read.Data)
	}
}

// The probe must ask for the role's own target SA and scopes (either can be
// refused on its own) but only a token-shaped minimum lifetime: GCP access tokens
// cannot be revoked, so the lifetime asked for is the only bound on what the probe
// leaves behind.
func TestCapability_ProbeUsesRoleTargetAndShortLifetime(t *testing.T) {
	bk, rec, storage := capBackend(t, newFakeSAKeyStore(), []interface{}{
		neverExpiresMinter(rotMinter1ID, capMinterJSON),
	})

	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	call, ok := rec.last()
	if !ok {
		t.Fatal("no probe generateAccessToken was recorded")
	}
	if call.serviceAccount != capTargetSA {
		t.Fatalf("probe impersonated %q, want the role's target %q", call.serviceAccount, capTargetSA)
	}
	if len(call.scopes) != 1 || call.scopes[0] != capScope {
		t.Fatalf("probe did not use the role's scopes: %v", call.scopes)
	}
	if call.lifetime != probeTokenLifetime {
		t.Fatalf("probe lifetime is %v, want %v", call.lifetime, probeTokenLifetime)
	}
}

// A rotated SA key authenticates as the same service account, so TestConnection
// cannot see that a tokenCreator binding on a bound role's target SA is gone. The
// pre-commit probe must, leaving neither the set nor the SA's key set changed.
func TestCapability_RotationRejectedWhenSuccessorCannotImpersonate(t *testing.T) {
	store := newFakeSAKeyStore()
	bk, rec, storage := capBackend(t, store, []interface{}{
		neverExpiresMinter(rotMinter1ID, capMinterJSON),
		neverExpiresMinter(rotMinter2ID, "{\"k\":\"minter-2\"}"),
	})
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	// Refuse only the successor's key (created key JSON carries successorJSONPrefix),
	// so the rotation's own mint and health check still pass.
	rec.setDenyJSONPart(successorJSONPrefix)

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: rotMinter1ID},
	})
	if err != nil {
		t.Fatalf("rotate errored: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the rotation to be rejected, got %v", resp)
	}

	set := loadSetFromStorage(t, storage)
	if len(set.Minters) != 2 {
		t.Fatalf(noStateChangeMsgFmt, len(set.Minters))
	}
	for i := range set.Minters {
		if set.Minters[i].Retired {
			t.Fatalf("rejected rotation retired minter %q", set.Minters[i].ID)
		}
	}
	if store.keyCount() != 0 {
		t.Fatalf("rejected rotation left %d SA key(s) behind, want 0", store.keyCount())
	}
}

// verify_minter_capability=false skips the probe: no generateAccessToken is
// attempted at role write. Operators who cannot accept a probe token (GCP has no
// revoke) have this escape hatch.
func TestCapability_DisabledSkipsProbe(t *testing.T) {
	bk, rec, storage := capBackend(t, newFakeSAKeyStore(), []interface{}{
		neverExpiresMinter(rotMinter1ID, capMinterJSON),
	})
	if resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]interface{}{fieldVerifyCapability: false},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}
	rec.setDenyAll(true)

	before := rec.count()
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("probe ran despite verify_minter_capability=false: %v", resp.Error())
	}
	if rec.count() != before {
		t.Fatalf("expected no probe generateAccessToken, saw %d", rec.count()-before)
	}
}
