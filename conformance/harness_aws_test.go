package conformance

import (
	"sync/atomic"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialaws "github.com/nicois/openbao-cloud-creds/plugins/credential-aws"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// AWS has no HTTP fake: the double is an in-process STSClient injected per
// backend instance. Harness.Inject re-applies it to a reloaded backend too,
// which is what lets AWS run the reload category (previously skipped, because
// re-running Factory left the backend pointing at the real STS endpoint).
//
// Revoke is a no-op — STS credentials expire and have no upstream entity — so
// ProvisionedCount is a cumulative mint count, not a live-entity count.
const (
	awsRegionField    = "region"
	awsRegion         = "us-east-1"
	awsRoleARNField   = "iam_role_arn"
	awsRoleARN        = "arn:aws:iam::123456789012:role/test"
	awsAccessKeyField = "access_key_id"
	awsSecretKeyField = "secret_access_key"
	awsLiveKeyID      = "AKIAIOSFODNN7EXAMPLE"
	awsLiveSecret     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	awsOtherKeyID     = "AKIARESEEDEDKEY00000"
	awsOtherSecret    = "reseededSecretAccessKey1234567890abcdef"
)

func awsMinter(id, keyID, secret string) map[string]interface{} {
	return map[string]interface{}{
		fieldID: id, awsAccessKeyField: keyID, awsSecretKeyField: secret,
		fieldNeverExpires: true,
	}
}

// awsRoleFields is the mint shape: an ARN to assume, inside the 900s–43200s
// window AWS can enforce with DurationSeconds.
func awsRoleFields() map[string]interface{} {
	return map[string]interface{}{
		fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
		awsRoleARNField: awsRoleARN, fieldMinterSet: defaultSet,
	}
}

func awsHarness(t *testing.T) plugintest.Harness {
	var denied atomic.Bool
	var minted atomic.Int64

	return plugintest.Harness{
		Cloud:   "aws",
		Factory: credentialaws.Factory,
		Inject: func(b logical.Backend) {
			credentialaws.SetSTSClientFactory(b,
				func(_, _, _, _ string) credentialaws.STSClient {
					return credentialaws.NewSwitchableSTSClient(denied.Load, func() { minted.Add(1) })
				})
		},
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{awsRegionField: awsRegion})
			plugintest.Write(t, b, storage, setPath,
				minterSet(awsMinter(liveMinterID, awsLiveKeyID, awsLiveSecret)))
			plugintest.Write(t, b, storage, rolePath, awsRoleFields())
		},
		IssuePath:             issuePath,
		CredentialKeys:        []string{"access_key_id", "secret_access_key", "session_token"},
		CredentialKind:        "sigv4_session",
		ScopeKind:             "role",
		SecretType:            "aws_sts_credentials",
		LeaseInternalDataKeys: []string{"access_key_id", "role", "minter_set", "minter_id"},
		RolePath:              rolePath,
		WorkersRunning:        credentialaws.WorkersRunning,
		SetPath:               setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath,
				minterSet(awsMinter(replacementMinterID, awsOtherKeyID, awsOtherSecret)))
		},
		ProvisionedCount:         func() int { return int(minted.Load()) },
		ExpectsHardRevoke:        false,
		DeletesIssuedCredentials: false,

		ConfigureProbe: func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{
				awsRegionField: awsRegion, fieldVerifyCapability: verify,
			})
			plugintest.Write(t, b, storage, setPath,
				minterSet(awsMinter(liveMinterID, awsLiveKeyID, awsLiveSecret)))
		},
		ProbeRolePath: probeRolePath,
		WriteProbeRole: func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
			return plugintest.TryWrite(t, b, storage, probeRolePath, awsRoleFields())
		},
		RewriteSet: func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response {
			return plugintest.TryWrite(t, b, storage, setPath,
				minterSet(awsMinter(minterID, awsLiveKeyID, awsLiveSecret)))
		},
		DenyMint:            func() { denied.Store(true) },
		AllowMint:           func() { denied.Store(false) },
		LiveMinterID:        liveMinterID,
		ReplacementMinterID: replacementMinterID,

		Skips: map[plugintest.Category]string{
			plugintest.CategoryReconcilerSafety: "AWS reconcile prunes local tracking entries only " +
				"(pkg/localexpiry on active-tokens/): STS sessions are not upstream entities, so there " +
				"is nothing to list and nothing the reconciler could delete",
			plugintest.CategoryRotation: noSharedCredential,
		},
	}
}
