package capability

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	setAlpha  = "alpha"
	shapeRead = "read"
)

// probeRecorder builds a ChecksFunc that records which (minter, role) pairs were
// probed and optionally fails.
func probeRecorder(probed *[]string, fail error) ChecksFunc {
	return func(set *cloudconfig.MinterSet, roleJSON []byte) []Check {
		role := struct {
			Name  string `json:"name"`
			Shape string `json:"shape"`
		}{}
		if err := json.Unmarshal(roleJSON, &role); err != nil {
			return nil
		}
		if role.Shape == "" {
			role.Shape = shapeRead
		}
		return ChecksPerMinter(set, role.Name, role.Shape, func(minter cloudconfig.Minter) func(context.Context) error {
			return func(context.Context) error {
				*probed = append(*probed, minter.ID+"/"+role.Name)
				return fail
			}
		})
	}
}

func putMinterSet(t *testing.T, storage logical.Storage, set *cloudconfig.MinterSet) {
	t.Helper()
	entry, err := logical.StorageEntryJSON(minterSetPrefix+set.Name, set)
	if err != nil {
		t.Fatalf("entry build failed: %v", err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatalf("put failed: %v", err)
	}
}

func twoMinterSet() *cloudconfig.MinterSet {
	return &cloudconfig.MinterSet{Name: setAlpha, Minters: []cloudconfig.Minter{
		{ID: "minter-1", NeverExpires: true},
		{ID: "minter-2", NeverExpires: true},
	}}
}

// A set write must probe every active minter against every bound role: minter
// selection picks arbitrarily, so one incapable minter breaks issuance
// intermittently rather than not at all.
func TestGate_VerifySetProbesEveryMinterForEveryBoundRole(t *testing.T) {
	storage := &logical.InmemStorage{}
	putRole(t, storage, "role-a", map[string]interface{}{"name": "role-a", "minter_set": setAlpha, "shape": "read"})
	putRole(t, storage, "role-b", map[string]interface{}{"name": "role-b", "minter_set": setAlpha, "shape": "write"})
	putRole(t, storage, "elsewhere", map[string]interface{}{"name": "elsewhere", "minter_set": "beta"})

	var probed []string
	gate := Gate{Cloud: "test", Enabled: true}
	if resp := gate.VerifySet(context.Background(), storage, twoMinterSet(), probeRecorder(&probed, nil)); resp != nil {
		t.Fatalf("expected success, got %v", resp.Error())
	}
	if len(probed) != 4 {
		t.Fatalf("expected 2 minters x 2 bound roles = 4 probes, got %v", probed)
	}
	for _, p := range probed {
		if strings.Contains(p, "elsewhere") {
			t.Fatalf("probed a role bound to another set: %v", probed)
		}
	}
}

// A rotation successor is probed alone: the question is whether the replacement
// inherited what its predecessor could do, so the incumbent's continued success
// must not mask the successor's failure.
func TestGate_VerifySuccessorProbesOnlyTheSuccessor(t *testing.T) {
	storage := &logical.InmemStorage{}
	putRole(t, storage, "role-a", map[string]interface{}{"name": "role-a", "minter_set": setAlpha})
	putMinterSet(t, storage, twoMinterSet())

	var probed []string
	gate := Gate{Cloud: "test", Enabled: true}
	successor := cloudconfig.Minter{ID: "successor", NeverExpires: true}
	if resp := gate.VerifySuccessor(context.Background(), storage, setAlpha, successor, probeRecorder(&probed, nil)); resp != nil {
		t.Fatalf("expected success, got %v", resp.Error())
	}
	if len(probed) != 1 || probed[0] != "successor/role-a" {
		t.Fatalf("expected only the successor probed, got %v", probed)
	}
}

func TestGate_VerifyRoleRejectsMissingSet(t *testing.T) {
	var probed []string
	gate := Gate{Cloud: "test", Enabled: true}
	resp := gate.VerifyRole(context.Background(), &logical.InmemStorage{}, "nope",
		[]byte(`{"name":"role-a"}`), probeRecorder(&probed, nil))
	if resp == nil || !resp.IsError() {
		t.Fatalf("binding a role to a nonexistent set must be rejected, got %v", resp)
	}
	if !strings.Contains(resp.Error().Error(), "does not exist") {
		t.Fatalf("unhelpful error: %v", resp.Error())
	}
}

// The failure response must both explain what failed and how to proceed without
// the check, so an environment where a probe mint is unacceptable is not stuck.
func TestGate_FailureExplainsAndOffersTheEscapeHatch(t *testing.T) {
	storage := &logical.InmemStorage{}
	putMinterSet(t, storage, twoMinterSet())

	var probed []string
	gate := Gate{Cloud: "test", Enabled: true}
	resp := gate.VerifyRole(context.Background(), storage, setAlpha,
		[]byte(`{"name":"role-a"}`), probeRecorder(&probed, errors.New("403 forbidden")))
	if resp == nil || !resp.IsError() {
		t.Fatal("expected rejection")
	}
	for _, want := range []string{"403 forbidden", "role-a", "verify_minter_capability=false"} {
		if !strings.Contains(resp.Error().Error(), want) {
			t.Fatalf("error %q does not mention %q", resp.Error(), want)
		}
	}
}

func TestGate_DisabledRunsNoProbes(t *testing.T) {
	storage := &logical.InmemStorage{}
	putRole(t, storage, "role-a", map[string]interface{}{"name": "role-a", "minter_set": setAlpha})
	putMinterSet(t, storage, twoMinterSet())

	var probed []string
	gate := Gate{Cloud: "test", Enabled: false}
	fail := probeRecorder(&probed, errors.New("would fail"))
	if resp := gate.VerifySet(context.Background(), storage, twoMinterSet(), fail); resp != nil {
		t.Fatalf("disabled gate rejected a set write: %v", resp.Error())
	}
	if resp := gate.VerifyRole(context.Background(), storage, setAlpha, []byte(`{"name":"role-a"}`), fail); resp != nil {
		t.Fatalf("disabled gate rejected a role write: %v", resp.Error())
	}
	if len(probed) != 0 {
		t.Fatalf("disabled gate ran probes: %v", probed)
	}
}

func TestLoadMinterSet_MissingIsNotAnError(t *testing.T) {
	set, err := LoadMinterSet(context.Background(), &logical.InmemStorage{}, "nope")
	if err != nil || set != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", set, err)
	}
}

// Retired minters are not probed: they are no longer selectable for issuance, and
// on the clouds that rotate they may already have had their upstream credential
// swept.
func TestChecksPerMinter_SkipsRetiredMinters(t *testing.T) {
	set := &cloudconfig.MinterSet{Name: setAlpha, Minters: []cloudconfig.Minter{
		{ID: "live", NeverExpires: true},
		{ID: "gone", NeverExpires: true, Retired: true},
	}}
	checks := ChecksPerMinter(set, "role-a", shapeRead, func(cloudconfig.Minter) func(context.Context) error {
		return func(context.Context) error { return nil }
	})
	if len(checks) != 1 || checks[0].Minter != "live" {
		t.Fatalf("expected only the active minter probed, got %+v", checks)
	}
}

// Two roles asking the cloud for the same thing are one probe, not two: the mint
// request is identical, so proving it once proves it for both — and the failure
// message still names both roles (see TestVerify_FailureNamesMinterAndAllSharingRoles).
func TestGate_RolesWithTheSameMintShapeProbeOnce(t *testing.T) {
	storage := &logical.InmemStorage{}
	putRole(t, storage, "role-a", map[string]interface{}{"name": "role-a", "minter_set": setAlpha, "shape": "read"})
	putRole(t, storage, "role-b", map[string]interface{}{"name": "role-b", "minter_set": setAlpha, "shape": "read"})

	var probed []string
	gate := Gate{Cloud: "test", Enabled: true}
	set := &cloudconfig.MinterSet{Name: setAlpha, Minters: []cloudconfig.Minter{{ID: "minter-1", NeverExpires: true}}}
	if resp := gate.VerifySet(context.Background(), storage, set, probeRecorder(&probed, nil)); resp != nil {
		t.Fatalf("expected success, got %v", resp.Error())
	}
	if len(probed) != 1 {
		t.Fatalf("expected one probe for two identically-shaped roles, got %v", probed)
	}
}
