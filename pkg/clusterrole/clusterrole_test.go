package clusterrole_test

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/clusterrole"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func viewWith(state consts.ReplicationState) logical.SystemView {
	return &logical.StaticSystemView{ReplicationStateVal: state}
}

// TestAStandbyDoesNotRunBackgroundWork is the whole point: InitializeFunc runs on every node, so
// without this check a cluster runs one worker loop per node.
func TestAStandbyDoesNotRunBackgroundWork(t *testing.T) {
	// The exact value core stores for a standby (vault/ha.go:520).
	standby := viewWith(consts.ReplicationDRDisabled | consts.ReplicationPerformanceStandby)
	if clusterrole.ShouldRunBackgroundWork(standby) {
		t.Error("a performance standby was told to run background work; a cluster would run one " +
			"health-check loop and one reconciler per node, multiplying upstream logins and " +
			"turning a stale credential into a lockout")
	}
	if got := clusterrole.Describe(standby); got != "standby" {
		t.Errorf("Describe = %q, want \"standby\"", got)
	}
}

// TestTheActiveNodeRunsBackgroundWork: the other direction, which is the one that matters for the
// feature working at all.
func TestTheActiveNodeRunsBackgroundWork(t *testing.T) {
	for name, state := range map[string]consts.ReplicationState{
		"no replication":       consts.ReplicationUnknown,
		"DR disabled only":     consts.ReplicationDRDisabled,
		"performance disabled": consts.ReplicationPerformanceDisabled,
		"DR primary":           consts.ReplicationDRPrimary,
	} {
		t.Run(name, func(t *testing.T) {
			if !clusterrole.ShouldRunBackgroundWork(viewWith(state)) {
				t.Errorf("state %v was treated as a standby, so this node would run no health "+
					"checks and no reconciler — a silently broken mount", state)
			}
		})
	}
}

// TestAnUnknownableStateRunsTheWork pins the direction of the failure. Not running is SILENT (no
// health checks, no orphan reclamation, nothing to notice); running unnecessarily costs duplicated
// work. So an indeterminate answer must mean "run".
func TestAnUnknownableStateRunsTheWork(t *testing.T) {
	if !clusterrole.ShouldRunBackgroundWork(nil) {
		t.Error("a nil system view suppressed background work; unit tests construct backends " +
			"without one, and a silently worker-less mount is worse than a duplicated one")
	}
	if got := clusterrole.Describe(nil); got == "" {
		t.Error("Describe returned nothing for a nil view, so a log line would say nothing")
	}
}
