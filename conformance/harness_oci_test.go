package conformance

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialoci "github.com/nicois/openbao-cloud-creds/plugins/credential-oci"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// OCI is the phased-rotation outlier. Credentials are pre-provisioned when the
// role is written (no per-read cloud call), revoke is soft (the slot lives until
// its scheduled rotation), and the cloud client is an in-process fake injected
// per backend instance.
const (
	ociRegionField    = "region"
	ociRotationCheck  = "rotation_check_interval"
	ociUserOCIDField  = "user_ocid"
	ociSlotCountField = "slot_count"
	ociRotationPeriod = "rotation_period"
	ociRegion         = "us-ashburn-1"
	ociUserOCID       = "ocid1.user.oc1..testuser"
	ociMinterToken    = "tenancy:user:fingerprint:key"
	ociOtherToken     = "reseeded-tenancy:user:fingerprint:key"
	ociCheckSeconds   = 60
	ociSlots          = 2
	ociPeriodSeconds  = 604800
	ociDefaultTTLSecs = 302400
	ociMaxTTLSeconds  = 604800
)

// tokenCounter is satisfied by the in-memory fake OCI client, whose TokenCount
// method is exported even though the concrete type is not.
type tokenCounter interface {
	TokenCount() int
}

func ociHarness(t *testing.T) plugintest.Harness {
	fake := credentialoci.NewTestFakeClient()

	return plugintest.Harness{
		Cloud:   "oci",
		Factory: credentialoci.Factory,
		Inject:  func(b logical.Backend) { credentialoci.TestSetClient(b, fake) },
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				ociRegionField: ociRegion, ociRotationCheck: ociCheckSeconds,
			})
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, ociMinterToken)))
			// Writing the role provisions slot_count credentials through the bound
			// set's minter, so a creds read has something to return.
			plugintest.Write(t, b, storage, rolePath, map[string]interface{}{
				ociUserOCIDField: ociUserOCID, ociSlotCountField: ociSlots,
				ociRotationPeriod: ociPeriodSeconds,
				fieldDefaultTTL:   ociDefaultTTLSecs, fieldMaxTTL: ociMaxTTLSeconds,
				fieldMinterSet: defaultSet,
			})
		},
		IssuePath:      issuePath,
		RolePath:       rolePath,
		WorkersRunning: credentialoci.WorkersRunning,
		SetPath:        setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(replacementMinterID, ociOtherToken)))
		},
		ProvisionedCount: func() int {
			if c, ok := fake.(tokenCounter); ok {
				return c.TokenCount()
			}
			return 0
		},
		ExpectsHardRevoke: false,
		// Phased rotation: a read returns the freshest pre-provisioned slot and selects
		// no minter, so a minter-level fault shows up at the next rotation.
		IssuesFromPreprovisionedSlots: true,

		Skips: map[plugintest.Category]string{
			plugintest.CategoryCapability: "OCI returns capability.ErrUnsupported for every check: a " +
				"probe mint would consume one of the two auth tokens a user is allowed, which is the " +
				"quota phased rotation exists to work within (docs/minter-capability-verification.md). " +
				"The per-plugin capability_test.go asserts the checks are skipped, not failed",
			plugintest.CategoryReconcilerSafety: "the in-process OCI fake exposes no way to plant an " +
				"upstream token the plugin did not create, so a foreign-entity assertion cannot be " +
				"expressed against it",
		},
	}
}
