package conformance

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// DigitalOcean Spaces keys are the SECOND conformance subject drawn from one plugin, and the
// reason the registry has variants at all.
//
// `credential-do` issues two credential types, selected per role: a personal access token, and an
// S3-compatible Spaces access key. They share a plugin and nothing else that this module asserts —
// different endpoint, different credential kind, different scope kind, different secret type,
// different tracking prefix, different revoke, different mint-refusal knob. A single harness
// declares one of each, so covering only one type left the other exercised by nothing shared: the
// lease contract, the owner-tag invariant and the error taxonomy would all have been asserted for
// the type that CANNOT be minted against real DigitalOcean (KI-009) and not for the type that can.
const (
	doSpacesCredentialType = "spaces_key"
	// One named bucket with a narrow permission, rather than account-wide fullaccess: it is the
	// shape an operator should actually write, and it keeps the grants a real part of the probe's
	// mint shape.
	doSpacesGrants = "backups:read"
	doSpacesRegion = "nyc3"
)

func doSpacesRoleFields() map[string]interface{} {
	return map[string]interface{}{
		fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
		fieldCredentialType: doSpacesCredentialType,
		fieldGrants:         doSpacesGrants,
		fieldRegion:         doSpacesRegion,
		fieldMinterSet:      defaultSet,
	}
}

func doSpacesHarness(t *testing.T) plugintest.Harness {
	srv := fakes.NewDOServer()
	t.Cleanup(srv.Close)

	config := func(verify bool) map[string]interface{} {
		return map[string]interface{}{doAPIURLField: srv.URL, fieldVerifyCapability: verify}
	}

	return plugintest.Harness{
		Cloud:   "do (spaces_key)",
		Factory: credentialdo.Factory,
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath, map[string]interface{}{doAPIURLField: srv.URL})
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, doMinterToken)))
			plugintest.Write(t, b, storage, rolePath, doSpacesRoleFields())
		},
		IssuePath: issuePath,
		// endpoint and region are REQUIRED keys, not decoration: an S3 client cannot be
		// constructed without them, and neither is derivable from the key material.
		CredentialKeys:        []string{"access_key_id", "secret_access_key", "endpoint", "region"},
		CredentialKind:        "s3_credentials",
		ScopeKind:             "grants",
		SecretType:            "do_spaces_key",
		LeaseInternalDataKeys: []string{"upstream_access_key", "role", "minter_set", "minter_id"},
		RolePath:              rolePath,
		WorkersRunning:        credentialdo.WorkersRunning,
		SetPath:               setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath,
				minterSet(tokenMinter(replacementMinterID, "dop_v1_reseeded")))
		},
		// Spaces keys are counted on their own, not summed with tokens: the two classes draw on
		// separate upstream quotas, and a summed count would let a revoke assertion pass because
		// the OTHER class's count happened to move.
		ProvisionedCount:         srv.ProvisionedSpacesKeyCount,
		ExpectsHardRevoke:        true,
		DeletesIssuedCredentials: true,
		TrackingPrefix:           "active-spaces-keys/",

		ConfigureProbe: func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool) {
			plugintest.Write(t, b, storage, configPath, config(verify))
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, doMinterToken)))
		},
		ProbeRolePath: probeRolePath,
		WriteProbeRole: func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
			return plugintest.TryWrite(t, b, storage, probeRolePath, doSpacesRoleFields())
		},
		RewriteSet: func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response {
			return plugintest.TryWrite(t, b, storage, setPath,
				minterSet(tokenMinter(minterID, doMinterToken)))
		},
		WriteSetWithMinters: func(t *testing.T, b logical.Backend, storage logical.Storage, ids ...string) *logical.Response {
			minters := make([]map[string]interface{}, 0, len(ids))
			for _, id := range ids {
				minters = append(minters, tokenMinter(id, doMinterToken))
			}
			return plugintest.TryWrite(t, b, storage, setPath, minterSet(minters...))
		},
		// The Spaces-specific refusal. Using the token knob here would deny a mint this role
		// never makes, and the capability suite would then assert that an ALLOWED minter is
		// rejected — passing or failing for reasons unrelated to what it means to test.
		DenyMint:  func() { srv.SetForbidSpacesKeyCreate(true) },
		AllowMint: func() { srv.SetForbidSpacesKeyCreate(false) },
		FailNextMintWithStatus: func(_ *testing.T, status int) string {
			srv.SetNextStatus(status)
			return ""
		},
		LiveMinterID:        liveMinterID,
		ReplacementMinterID: replacementMinterID,

		SeedForeignEntity: func() string {
			srv.AddRawSpacesKey(foreignEntityID, foreignEntityName)
			return foreignEntityID
		},
		SeedAgedOrphans: func(t *testing.T, storage logical.Storage) (string, string) {
			srv.AddRawSpacesKeyWithCreatedAt(agedForeignID, agedForeignName, agedTimestamp)
			srv.AddRawSpacesKeyWithCreatedAt(agedOwnedID, agedOwnedName(t, storage), agedTimestamp)
			return agedForeignID, agedOwnedID
		},
		HasEntity: srv.HasSpacesKey,

		Skips: map[plugintest.Category]string{
			plugintest.CategoryRotation: noSharedCredential,
		},
	}
}
