package credentialaws

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Local literals for the capability tests.
const (
	capRolePath   = "roles/probe-role"
	capRoleName   = "probe-role"
	capRoleARN    = "arn:aws:iam::123456789012:role/probe"
	capExternalID = "ext-42"
	capTagKey     = "team"
	capTagValue   = "sre"
	capRoleTTL    = 900
	capRoleMaxTTL = 3600
)

// capSTSRecorder records the AssumeRole calls a fake STS client sees and can deny
// them, either wholesale or for one access key. Denying by access key is how the
// successor-cannot-mint case is expressed: a rotated key is a different principal
// credential on the same IAM user, and only AssumeRole can tell the difference.
type capSTSRecorder struct {
	mu          sync.Mutex
	inputs      []*sts.AssumeRoleInput
	denyAll     bool
	denyKeyPart string
}

func (r *capSTSRecorder) assumeRole(keyID string) AssumeRoleFunc {
	return func(ctx context.Context, params *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
		r.mu.Lock()
		r.inputs = append(r.inputs, params)
		deny := r.denyAll || (r.denyKeyPart != "" && strings.Contains(keyID, r.denyKeyPart))
		r.mu.Unlock()
		if deny {
			return nil, fmt.Errorf("AccessDenied: User: %s is not authorized to perform: sts:AssumeRole", keyID)
		}
		return NewFakeSTSClient(nil, nil).AssumeRole(ctx, params)
	}
}

func (r *capSTSRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.inputs)
}

func (r *capSTSRecorder) last() *sts.AssumeRoleInput {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.inputs) == 0 {
		return nil
	}
	return r.inputs[len(r.inputs)-1]
}

func (r *capSTSRecorder) setDenyAll(deny bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.denyAll = deny
}

func (r *capSTSRecorder) setDenyKeyPart(part string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.denyKeyPart = part
}

// capBackend builds a rotation-capable backend whose STS AssumeRole is recorded
// (and deniable) while GetCallerIdentity keeps succeeding — the "healthy but
// cannot mint" shape.
func capBackend(t *testing.T, store *fakeIAMStore, minters []any) (*backend, *capSTSRecorder, logical.Storage) {
	t.Helper()
	bk, storage := newRotationBackend(t, store, minters)
	rec := &capSTSRecorder{}
	SetSTSClientFactory(bk, func(accessKeyID, _, _, _ string) STSClient {
		return NewFakeSTSClient(rec.assumeRole(accessKeyID), nil)
	})
	return bk, rec, storage
}

// capWriteRole writes a role bound to the default set and returns the response.
func capWriteRole(t *testing.T, bk *backend, storage logical.Storage) *logical.Response {
	t.Helper()
	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: capRolePath, Storage: storage,
		Data: map[string]any{
			fieldDefaultTTL: capRoleTTL, fieldMaxTTL: capRoleMaxTTL,
			"iam_role_arn": capRoleARN, "external_id": capExternalID,
			"session_tags": map[string]any{capTagKey: capTagValue},
			fieldMinterSet: defaultSetName,
		},
	})
	if err != nil {
		t.Fatalf("role write errored: %v", err)
	}
	return resp
}

// GetCallerIdentity succeeds for any valid signature — AWS does not require a
// policy to allow it — so a minter denied sts:AssumeRole on a role's ARN is
// reported healthy forever. The role must not bind to it.
func TestCapability_RoleWriteRejectedWhenAssumeRoleDenied(t *testing.T) {
	bk, rec, storage := capBackend(t, newFakeIAMStore("AKIA1"), []any{
		neverExpiresMinter(rotMinter1ID, "AKIA1", "secret1"),
	})
	rec.setDenyAll(true)

	resp := capWriteRole(t, bk, storage)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the role write to be rejected, got %v", resp)
	}
	if rec.count() == 0 {
		t.Fatal("the role write did not attempt a probe AssumeRole")
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

// The probe must exercise the role's real request shape (ARN, external ID,
// session tags — each independently able to turn an allowed AssumeRole into
// AccessDenied) while pinning the session it leaves behind to AWS's 900s floor:
// STS credentials cannot be revoked, so the probe's duration is the only bound.
func TestCapability_ProbeUsesRoleShapeAndMinimumDuration(t *testing.T) {
	bk, rec, storage := capBackend(t, newFakeIAMStore("AKIA1"), []any{
		neverExpiresMinter(rotMinter1ID, "AKIA1", "secret1"),
	})

	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	input := rec.last()
	if input == nil {
		t.Fatal("no probe AssumeRole was recorded")
	}
	if *input.RoleArn != capRoleARN {
		t.Fatalf("probe assumed %q, want the role's own %q", *input.RoleArn, capRoleARN)
	}
	if input.ExternalId == nil || *input.ExternalId != capExternalID {
		t.Fatalf("probe did not carry the role's external id: %v", input.ExternalId)
	}
	if len(input.Tags) != 1 || *input.Tags[0].Key != capTagKey || *input.Tags[0].Value != capTagValue {
		t.Fatalf("probe did not carry the role's session tags: %v", input.Tags)
	}
	if input.DurationSeconds == nil || *input.DurationSeconds != probeDurationSeconds {
		t.Fatalf("probe duration is %v, want the %ds floor", input.DurationSeconds, probeDurationSeconds)
	}
	if !strings.Contains(*input.RoleSessionName, capRoleName+"-probe-") ||
		!strings.HasPrefix(*input.RoleSessionName, ownertag.Base) {
		t.Fatalf("probe session name %q does not carry this mount's owner prefix and role", *input.RoleSessionName)
	}
}

// A rotated access key is a new credential for the same IAM user, so it usually
// inherits the user's permissions — but not when a policy or trust policy names
// the key. GetCallerIdentity cannot see that; the pre-commit probe must, and must
// leave neither the set nor the IAM user's key set changed.
func TestCapability_RotationRejectedWhenSuccessorCannotAssume(t *testing.T) {
	store := newFakeIAMStore("AKIA1")
	bk, rec, storage := capBackend(t, store, []any{
		neverExpiresMinter(rotMinter1ID, "AKIA1", "secret1"),
		neverExpiresMinter(rotMinter2ID, "AKIA2", "secret2"),
	})
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("role write failed: %v", resp.Error())
	}
	// Deny only the successor's key (created keys carry successorKeyPrefix), so the
	// rotation's own mint and health check still pass.
	rec.setDenyKeyPart(successorKeyPrefix)

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]any{fieldMinterID: rotMinter1ID},
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
	if store.keyCount() != 1 {
		t.Fatalf("rejected rotation left %d access keys on the IAM user, want 1", store.keyCount())
	}
}

// verify_minter_capability=false skips the probe: no AssumeRole is attempted at
// role write. Operators who cannot accept a probe session (STS has no revoke)
// have this escape hatch.
func TestCapability_DisabledSkipsProbe(t *testing.T) {
	bk, rec, storage := capBackend(t, newFakeIAMStore("AKIA1"), []any{
		neverExpiresMinter(rotMinter1ID, "AKIA1", "secret1"),
	})
	if resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]any{
			configRegionKey: defaultRegion, fieldVerifyCapability: false,
		},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}
	rec.setDenyAll(true)

	before := rec.count()
	if resp := capWriteRole(t, bk, storage); resp != nil && resp.IsError() {
		t.Fatalf("probe ran despite verify_minter_capability=false: %v", resp.Error())
	}
	if rec.count() != before {
		t.Fatalf("expected no probe AssumeRole, saw %d", rec.count()-before)
	}
}
