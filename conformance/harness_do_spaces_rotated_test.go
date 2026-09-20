package conformance

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/plugintest"
	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The rotated Spaces key is the THIRD subject drawn from `credential-do`, and the first whose
// credential is not owned by the lease that read it.
//
// It shares the payload shape, the endpoint and the tracking prefix with the per-lease Spaces
// subject beside it, and differs in the one dimension no other subject varies: WHO the
// credential belongs to. One key per role, re-served to every reader, replaced on the role's
// own schedule, and kept alive for `overlap_ttl` after it is replaced so the clients holding it
// keep working until they next read. So the two subjects disagree about renewability, about
// what a revoke does, about how many credentials N reads leave upstream, and about what bounds
// a credential's life — which is why the lifecycle needs a subject of its own rather than a
// second role on the existing one.
const (
	doSpacesRotatedCredentialType = "spaces_key_rotated"

	// 90 days with 48 hours of overlap: the lifecycle this type was specified against, kept
	// here rather than shortened, because the periods are what make the seams necessary — a
	// suite that could wait for a rotation would not need them, and one written against a
	// 2-second period would prove nothing about the numbers an operator writes.
	doSpacesRotationPeriod = 90 * 24 * time.Hour
	// Jitter is SUBTRACTED from the period, so this schedules a rotation somewhere in days
	// 89–90. Declared rather than defaulted, so the field is exercised on the write path.
	doSpacesRotationJitter  = 24 * time.Hour
	doSpacesRotationOverlap = 48 * time.Hour
)

func doSpacesRotatedRoleFields() map[string]any {
	return map[string]any{
		// max_ttl is inside the overlap, which the role write requires: a lease longer than the
		// grace a replaced key gets would name a credential that had been deleted.
		fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
		fieldCredentialType: doSpacesRotatedCredentialType,
		fieldGrants:         doSpacesGrants,
		fieldRegion:         doSpacesRegion,
		fieldMinterSet:      defaultSet,
		fieldRotationPeriod: int(doSpacesRotationPeriod.Seconds()),
		fieldRotationJitter: int(doSpacesRotationJitter.Seconds()),
		fieldOverlapTTL:     int(doSpacesRotationOverlap.Seconds()),
	}
}

func doSpacesRotatedHarness(t *testing.T) plugintest.Harness {
	srv := fakes.NewDOServer()
	t.Cleanup(srv.Close)

	config := func(verify bool) map[string]any {
		return map[string]any{doAPIURLField: srv.URL, fieldVerifyCapability: verify}
	}

	return plugintest.Harness{
		Cloud:   "do (spaces_key_rotated)",
		Factory: credentialdo.Factory,
		Configure: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, configPath, map[string]any{doAPIURLField: srv.URL})
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, doMinterToken)))
			plugintest.Write(t, b, storage, rolePath, doSpacesRotatedRoleFields())
		},
		IssuePath:             issuePath,
		CredentialKeys:        []string{"access_key_id", "secret_access_key", "endpoint", "region"},
		CredentialKind:        "s3_credentials",
		ScopeKind:             "grants",
		SecretType:            "do_spaces_key_rotated",
		LeaseInternalDataKeys: []string{"upstream_access_key", "role", "minter_set", "minter_id"},
		RolePath:              rolePath,
		WorkersRunning:        credentialdo.WorkersRunning,
		SetPath:               setPath,
		RewriteDefaultSetWithout: func(t *testing.T, b logical.Backend, storage logical.Storage) {
			plugintest.Write(t, b, storage, setPath,
				minterSet(tokenMinter(replacementMinterID, "dop_v1_reseeded")))
		},
		// The same prefix and the same counter as the per-lease Spaces subject: a rotated role's
		// key is one live Spaces key like any other, so it is counted against the account cap and
		// reclaimed by the same reconciler class. What differs is how many of them N reads make.
		ProvisionedCount:  srv.ProvisionedSpacesKeyCount,
		ExpectsHardRevoke: false,
		// Both facts, and they point in opposite directions on purpose. A lease ending deletes
		// nothing, because the credential is not the lease's to delete; but the cloud can still
		// destroy it on demand, which is what makes the capability probe cleanable and
		// roles/<name>/revoke-upstream a real lever here.
		DeletesIssuedCredentials: true,
		SharesOneCredential:      true,
		TrackingPrefix:           "active-spaces-keys/",

		ForceRotationDue: func(t *testing.T, b logical.Backend, storage logical.Storage) error {
			return credentialdo.ForceRotationDue(t.Context(), b, storage, roleName)
		},
		ForceOverlapExpired: func(t *testing.T, b logical.Backend, storage logical.Storage) error {
			return credentialdo.ForceOverlapExpired(t.Context(), b, storage, roleName)
		},
		SweepRetiredCredentials: func(t *testing.T, b logical.Backend, storage logical.Storage) error {
			return credentialdo.SweepSharedSpacesKeys(t.Context(), b, storage)
		},
		RotationOverlapTTL: doSpacesRotationOverlap,

		ConfigureProbe: func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool) {
			plugintest.Write(t, b, storage, configPath, config(verify))
			plugintest.Write(t, b, storage, setPath, minterSet(tokenMinter(liveMinterID, doMinterToken)))
		},
		ProbeRolePath: probeRolePath,
		WriteProbeRole: func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response {
			return plugintest.TryWrite(t, b, storage, probeRolePath, doSpacesRotatedRoleFields())
		},
		RewriteSet: func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response {
			return plugintest.TryWrite(t, b, storage, setPath,
				minterSet(tokenMinter(minterID, doMinterToken)))
		},
		WriteSetWithMinters: func(t *testing.T, b logical.Backend, storage logical.Storage, ids ...string) *logical.Response {
			minters := make([]map[string]any, 0, len(ids))
			for _, id := range ids {
				minters = append(minters, tokenMinter(id, doMinterToken))
			}
			return plugintest.TryWrite(t, b, storage, setPath, minterSet(minters...))
		},
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
	}
}
