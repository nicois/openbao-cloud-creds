package credentialoci

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/capability"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

// OCI is the one cloud whose capability cannot be probed: a probe mint would
// consume one of the two auth tokens a user is allowed, which is the quota the
// phased-rotation strategy exists to work within. Every check must therefore
// report ErrUnsupported, which Verify counts as skipped — never as a failure that
// would block a set or role write.
func TestCapability_OCIProbesAreSkippedNotFailed(t *testing.T) {
	set := &cloudconfig.MinterSet{Name: "default", Minters: []cloudconfig.Minter{
		{ID: "minter-1", NeverExpires: true},
		{ID: "minter-2", NeverExpires: true},
		{ID: "minter-retired", NeverExpires: true, Retired: true},
	}}
	roleJSON, err := json.Marshal(&ociRole{Name: "db-rw", MinterSet: "default", UserOCID: "ocid1.user.oc1..aaa"})
	if err != nil {
		t.Fatalf("marshal role: %v", err)
	}

	b := &backend{}
	checks := b.capabilityChecks(set, roleJSON)
	if len(checks) != 2 {
		t.Fatalf("expected one check per active minter, got %d", len(checks))
	}
	for i := range checks {
		if _, runErr := checks[i].Run(t.Context()); !errors.Is(runErr, capability.ErrUnsupported) {
			t.Fatalf("check for %q returned %v, want ErrUnsupported", checks[i].Minter, runErr)
		}
	}

	result, verifyErr := capability.Verify(t.Context(), checks)
	if verifyErr != nil {
		t.Fatalf("unsupported checks must not fail verification: %v", verifyErr)
	}
	if result.Ran != 0 || result.Skipped != 2 {
		t.Fatalf("expected 0 ran / 2 skipped, got %+v", result)
	}
}
