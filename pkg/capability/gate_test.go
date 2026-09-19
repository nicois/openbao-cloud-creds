package capability

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
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
		return ChecksPerMinter(set, role.Name, role.Shape, func(minter cloudconfig.Minter) func(context.Context) (int, error) {
			return func(context.Context) (int, error) {
				*probed = append(*probed, minter.ID+"/"+role.Name)
				return http.StatusForbidden, fail
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
	if err := storage.Put(t.Context(), entry); err != nil {
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
	if resp := gate.VerifySet(t.Context(), storage, twoMinterSet(), probeRecorder(&probed, nil)); resp != nil {
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
	if resp := gate.VerifySuccessor(t.Context(), storage, setAlpha, successor, probeRecorder(&probed, nil)); resp != nil {
		t.Fatalf("expected success, got %v", resp.Error())
	}
	if len(probed) != 1 || probed[0] != "successor/role-a" {
		t.Fatalf("expected only the successor probed, got %v", probed)
	}
}

func TestGate_VerifyRoleRejectsMissingSet(t *testing.T) {
	var probed []string
	gate := Gate{Cloud: "test", Enabled: true}
	resp := gate.VerifyRole(t.Context(), &logical.InmemStorage{}, "nope",
		[]byte(`{"name":"role-a"}`), probeRecorder(&probed, nil))
	if resp == nil || !resp.IsError() {
		t.Fatalf("binding a role to a nonexistent set must be rejected, got %v", resp)
	}
	if !strings.Contains(resp.Error().Error(), "does not exist") {
		t.Fatalf("unhelpful error: %v", resp.Error())
	}
}

// The failure response must explain what failed and how to proceed without the
// check, so an environment where a probe mint is unacceptable is not stuck — and it
// must do so WITHOUT the upstream's own words.
//
// This test previously required the upstream text to be present, which encoded the
// A4 leak as desired behaviour: a probe error chains down to the cloud's raw
// response body, so a caller holding only `create` on roles/* received the cloud's
// verbatim diagnostics. The identities below are things that caller supplied; the
// upstream body is not.
func TestGate_FailureExplainsWithoutLeakingTheUpstreamBody(t *testing.T) {
	storage := &logical.InmemStorage{}
	putMinterSet(t, storage, twoMinterSet())

	const upstreamBody = `403 {"id":"forbidden","message":"tenant 8f3c-... is not authorized"}`
	var probed []string
	gate := Gate{Cloud: "test", Enabled: true}
	resp := gate.VerifyRole(t.Context(), storage, setAlpha,
		[]byte(`{"name":"role-a"}`), probeRecorder(&probed, errors.New(upstreamBody)))
	if resp == nil || !resp.IsError() {
		t.Fatal("expected rejection")
	}
	message := resp.Error().Error()

	// Actionable: which minter, which role, and how to proceed.
	for _, want := range []string{"minter-1", "role-a", "verify_minter_capability=false"} {
		if !strings.Contains(message, want) {
			t.Errorf("error %q does not mention %q, so the operator cannot act on it", message, want)
		}
	}
	// But not the cloud's own response.
	for _, leaked := range []string{upstreamBody, "tenant 8f3c", "forbidden"} {
		if strings.Contains(message, leaked) {
			t.Errorf("error response leaks upstream detail %q. Role-write privilege is less than "+
				"minter-secret privilege, so cloud diagnostics must go to the operator log only (A4). "+
				"Full message: %q", leaked, message)
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
	if resp := gate.VerifySet(t.Context(), storage, twoMinterSet(), fail); resp != nil {
		t.Fatalf("disabled gate rejected a set write: %v", resp.Error())
	}
	if resp := gate.VerifyRole(t.Context(), storage, setAlpha, []byte(`{"name":"role-a"}`), fail); resp != nil {
		t.Fatalf("disabled gate rejected a role write: %v", resp.Error())
	}
	if len(probed) != 0 {
		t.Fatalf("disabled gate ran probes: %v", probed)
	}
}

func TestLoadMinterSet_MissingIsNotAnError(t *testing.T) {
	set, err := LoadMinterSet(t.Context(), &logical.InmemStorage{}, "nope")
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
	checks := ChecksPerMinter(set, "role-a", shapeRead, func(cloudconfig.Minter) func(context.Context) (int, error) {
		return func(context.Context) (int, error) { return http.StatusOK, nil }
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
	if resp := gate.VerifySet(t.Context(), storage, set, probeRecorder(&probed, nil)); resp != nil {
		t.Fatalf("expected success, got %v", resp.Error())
	}
	if len(probed) != 1 {
		t.Fatalf("expected one probe for two identically-shaped roles, got %v", probed)
	}
}

// A role write that DISABLES a role must not depend on a probe succeeding. The write
// is most likely to be made while the cloud is refusing us — a compromised minter, a
// revoked key, an account locked out — and a role that cannot issue asks nothing of a
// minter, so there is nothing to prove. A set write already excludes disabled roles
// for the same reason (RolesBoundTo).
func TestGate_VerifyRoleSkipsADisabledRole(t *testing.T) {
	storage := &logical.InmemStorage{}
	putMinterSet(t, storage, twoMinterSet())

	var probed []string
	gate := Gate{Cloud: "test", Enabled: true}
	resp := gate.VerifyRole(t.Context(), storage, setAlpha,
		[]byte(`{"name":"role-a","disabled":true}`),
		probeRecorder(&probed, errors.New("403 the minter is exactly what we are containing")))
	if resp != nil {
		t.Fatalf("disabling a role was refused because a probe failed: %v", resp.Error())
	}
	if len(probed) != 0 {
		t.Fatalf("a disabled role was probed: %v", probed)
	}
}

// loginRejectedLimiter returns a limiter whose named minter has had ONE rejected login.
//
// One, deliberately: that is the whole point of the gate. The minter is still in TransientFailing --
// reaching AuthFailing needs a second rejection at least AuthFailThreshold later -- and yet one of the
// account's three tries is already spent, so the next probe is not free. Driving the real state machine
// rather than faking a state is what makes this agree with what issuance sees.
func loginRejectedLimiter(t *testing.T, minterID string) *Limiter {
	t.Helper()
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	sm := newSM()
	sm.RecordUpstream(http.StatusUnauthorized, nil, now)
	if got := sm.State(); got == recovery.AuthFailing {
		t.Fatalf("fixture reached auth_failing on one rejection; the gate would then prove nothing "+
			"about the window before that state, which is the window it exists for (state=%q)", got)
	}
	if got := sm.ConsecutiveAuthFailures(); got != 1 {
		t.Fatalf("fixture has %d rejected logins since its last success, want 1", got)
	}
	return &Limiter{
		States: func(id string) *recovery.StateMachine {
			if id == minterID {
				return sm
			}
			return nil
		},
		Now: func() time.Time { return now.Add(time.Minute) },
	}
}

// Enabling a role must not spend a login on an account that is already refusing us.
// DigitalOcean's console locks out after three consecutive rejected logins, so an operator
// enabling roles one at a time can burn the attempts that the repair itself needs —
// and a probe cannot tell them anything a failing minter has not already said.
func TestGate_RoleWriteRefusedAfterOneRejectedLogin(t *testing.T) {
	storage := &logical.InmemStorage{}
	putMinterSet(t, storage, twoMinterSet())

	var probed []string
	gate := Gate{Cloud: "test", Enabled: true, Limiter: loginRejectedLimiter(t, "minter-2")}
	resp := gate.VerifyRole(t.Context(), storage, setAlpha,
		[]byte(`{"name":"role-a"}`), probeRecorder(&probed, nil))

	if resp == nil || !resp.IsError() {
		t.Fatalf("a role write was allowed to probe a minter whose login had just been rejected: %v", resp)
	}
	if len(probed) != 0 {
		t.Fatalf("the write was refused but probes ran anyway (%v); the refusal exists to spend "+
			"no login at all", probed)
	}
	message := resp.Error().Error()
	if code, _ := credenvelope.CodeOf(message); code != credenvelope.ErrUpstreamAuthFailed {
		t.Errorf("refusal carries %q, want %q: a client must be able to tell a wrong credential "+
			"from a cooldown, because only one of them is worth retrying (message: %q)",
			code, credenvelope.ErrUpstreamAuthFailed, message)
	}
	if !strings.Contains(message, "minter-2") {
		t.Errorf("the refusal does not name which minter is failing: %q. A set can hold several, "+
			"and the operator has to know which one to repair", message)
	}
}

// A healthy minter with a state machine must still be probed. Without this the
// previous test passes just as well for a check that refuses everything.
func TestGate_RoleWriteProbesAHealthyMinter(t *testing.T) {
	storage := &logical.InmemStorage{}
	putMinterSet(t, storage, twoMinterSet())

	var probed []string
	sm := newSM()
	gate := Gate{Cloud: "test", Enabled: true, Limiter: &Limiter{
		States: func(string) *recovery.StateMachine { return sm },
	}}
	if resp := gate.VerifyRole(t.Context(), storage, setAlpha,
		[]byte(`{"name":"role-a"}`), probeRecorder(&probed, nil)); resp != nil {
		t.Fatalf("a healthy minter's role write was refused: %v", resp.Error())
	}
	if len(probed) == 0 {
		t.Fatal("a healthy minter was not probed, so the write committed on no evidence")
	}
}

// The repair for a rejected credential is writing a working one under the same minter
// id, and the rejected-login count clears only on a success. Gating the SET write on
// the same state would therefore refuse the only write that can end it, leaving the
// set permanently unfixable.
func TestGate_SetWriteIsNotRefusedAfterARejectedLogin(t *testing.T) {
	storage := &logical.InmemStorage{}
	putRole(t, storage, "role-a", map[string]interface{}{"name": "role-a", "minter_set": setAlpha, "shape": "read"})

	var probed []string
	gate := Gate{Cloud: "test", Enabled: true, Limiter: loginRejectedLimiter(t, "minter-1")}
	if resp := gate.VerifySet(t.Context(), storage, twoMinterSet(), probeRecorder(&probed, nil)); resp != nil {
		t.Fatalf("the write that repairs a failed minter was refused: %v", resp.Error())
	}
	if len(probed) == 0 {
		t.Fatal("the replacement credential was accepted without being probed, so a minter that " +
			"authenticates but cannot mint would silently become the set every bound role draws from")
	}
}

// Containment must survive the incident it exists for. A rejected credential is one
// of the reasons an operator reaches for disabled=true, so that write must land while
// the account is refusing us.
func TestGate_DisablingARoleStillWorksAfterARejectedLogin(t *testing.T) {
	storage := &logical.InmemStorage{}
	putMinterSet(t, storage, twoMinterSet())

	var probed []string
	gate := Gate{Cloud: "test", Enabled: true, Limiter: loginRejectedLimiter(t, "minter-1")}
	if resp := gate.VerifyRole(t.Context(), storage, setAlpha,
		[]byte(`{"name":"role-a","disabled":true}`), probeRecorder(&probed, nil)); resp != nil {
		t.Fatalf("the containment lever was refused after a minter's login was rejected: %v", resp.Error())
	}
	if len(probed) != 0 {
		t.Fatalf("a disabled role was probed: %v", probed)
	}
}

// A throttle is not a rejected credential, and the two must not collapse into one answer. 429 and 503
// both walk a minter through the same generic failure bookkeeping, so a gate keyed on "any consecutive
// failure" would refuse a role write because the cloud was briefly busy -- and tell the operator to
// repair a credential that is fine. The auth counter exists to keep those apart.
func TestGate_RoleWriteIsNotRefusedForANonAuthFailure(t *testing.T) {
	storage := &logical.InmemStorage{}
	putMinterSet(t, storage, twoMinterSet())

	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	sm := newSM()
	sm.RecordUpstream(http.StatusInternalServerError, nil, now)
	sm.RecordUpstream(http.StatusBadGateway, nil, now.Add(time.Second))
	if got := sm.ConsecutiveFailures(); got < 2 {
		t.Fatalf("fixture recorded %d generic failures, want at least 2", got)
	}
	if got := sm.ConsecutiveAuthFailures(); got != 0 {
		t.Fatalf("fixture has %d rejected logins after two 5xx, want 0", got)
	}

	var probed []string
	gate := Gate{Cloud: "test", Enabled: true, Limiter: &Limiter{
		States: func(string) *recovery.StateMachine { return sm },
		Now:    func() time.Time { return now.Add(time.Minute) },
	}}
	if resp := gate.VerifyRole(t.Context(), storage, setAlpha,
		[]byte(`{"name":"role-a"}`), probeRecorder(&probed, nil)); resp != nil {
		t.Fatalf("a role write was refused because the upstream had returned 5xx: %v. That is not a "+
			"rejected credential, and refusing here would send an operator to repair a working "+
			"minter", resp.Error())
	}
	if len(probed) == 0 {
		t.Fatal("the write committed without probing, so the 5xx suppressed verification instead")
	}
}
