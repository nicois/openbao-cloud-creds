package conformance

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialovh "github.com/nicois/openbao-cloud-creds/plugins/credential-ovh"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// OVH mints a fixed 1h OAuth2 token and cannot revoke it, so the role TTL is
// pinned to exactly 3600s (docs/ttl-semantics.md) and the probe's mint is the
// only bound on what it leaves behind. Minting IS the health check here — the
// same endpoint answers both — so SetForbidMint denies capability and health
// together; that is the cloud's shape, not the fake's.
const (
	ovhRegionField        = "region"
	ovhTokenEndpointField = "token_endpoint"
	ovhClientIDField      = "client_id"
	ovhClientSecretField  = "client_secret"
	ovhRegion             = "eu"
	ovhClientID           = "test-client-id"
	ovhClientSecret       = "test-client-secret"
	// ovhTrackingPrefix is where the plugin records each credential it mints. Stated here because
	// a wrong prefix yields a green test that asserts nothing.
	ovhTrackingPrefix = "active-tokens/"
)

func ovhMinter(id string) map[string]interface{} {
	return map[string]interface{}{
		fieldID: id, ovhClientIDField: ovhClientID, ovhClientSecretField: ovhClientSecret,
		fieldNeverExpires: true,
	}
}

func ovhRoleFields() map[string]interface{} {
	return map[string]interface{}{
		fieldDefaultTTL: hourTTL, fieldMaxTTL: hourTTL, fieldMinterSet: defaultSet,
	}
}

func ovhHarness(t *testing.T) plugintest.Harness {
	srv := fakes.NewOVHServer()
	t.Cleanup(srv.Close)

	return plugintest.Harness{
		Cloud:   "ovh",
		Factory: credentialovh.Factory,
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				ovhRegionField: ovhRegion, ovhTokenEndpointField: srv.TokenEndpointURL(),
			})
			plugintest.Write(t, b, storage, setPath, minterSet(ovhMinter(liveMinterID)))
			plugintest.Write(t, b, storage, rolePath, ovhRoleFields())
		},
		IssuePath:             issuePath,
		CredentialKeys:        []string{"access_token", "token_type"},
		CredentialKind:        "oauth2_bearer",
		ScopeKind:             "account",
		SecretType:            "ovh_access_token",
		LeaseInternalDataKeys: []string{"credential_id", "role", "minter_set", "minter_id"},
		RolePath:              rolePath,
		WorkersRunning:        credentialovh.WorkersRunning,
		SetPath:               setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath, minterSet(ovhMinter(replacementMinterID)))
		},
		ProvisionedCount:         srv.ProvisionedCount,
		ExpectsHardRevoke:        false,
		DeletesIssuedCredentials: false,
		// Declared for the `provenance` category. The revoke case that also reads it stays
		// skipped on ExpectsHardRevoke=false: an OAuth2 token cannot be deleted.
		TrackingPrefix: ovhTrackingPrefix,

		ConfigureProbe: func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				ovhRegionField: ovhRegion, ovhTokenEndpointField: srv.TokenEndpointURL(),
				fieldVerifyCapability: verify,
			})
			plugintest.Write(t, b, storage, setPath, minterSet(ovhMinter(liveMinterID)))
		},
		ProbeRolePath: probeRolePath,
		WriteProbeRole: func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
			return plugintest.TryWrite(t, b, storage, probeRolePath, ovhRoleFields())
		},
		RewriteSet: func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response {
			return plugintest.TryWrite(t, b, storage, setPath, minterSet(ovhMinter(minterID)))
		},
		DenyMint:  func() { srv.SetForbidMint(true) },
		AllowMint: func() { srv.SetForbidMint(false) },
		FailNextMintWithStatus: func(_ *testing.T, status int) string {
			srv.SetNextStatus(status)
			return ""
		},
		LiveMinterID:        liveMinterID,
		ReplacementMinterID: replacementMinterID,

		Skips: map[plugintest.Category]string{
			plugintest.CategoryReconcilerSafety: "OVH reconcile prunes local tracking entries only " +
				"(pkg/localexpiry): an OAuth2 token is not a listable upstream entity, so there is " +
				"nothing the reconciler could delete",
			plugintest.CategoryRotation: noSharedCredential,
		},
	}
}
