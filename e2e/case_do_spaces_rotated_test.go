//go:build e2e

package e2e

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// The rotated Spaces key over the wire: the same binary and the same payload as doSpacesCase,
// driven through a role whose credential belongs to the ROLE rather than to the lease that read
// it.
//
// What this layer adds is the part the client sees and an in-process test cannot produce. A
// third framework.Secret with no Renew callback has to reach core's expiration manager as a
// genuinely non-renewable lease, so `bao lease renew` is refused rather than silently
// destroying a credential every other reader is using — and it has to be reached through the
// serialized secret type, where dispatching a revoke to the per-lease callback beside it would
// delete the shared key. Re-serving is asserted across a `plugin reload` too, which is where
// the state stops being a struct in memory and has to come back out of storage.
//
// Its own role name, so all three DO roles can exist on one mount: an operator adding this
// lifecycle to a mount already issuing per-lease keys is the deployment shape, and neither
// role's writes may disturb the other's.
const (
	doSpacesRotatedRoleName = "spaces-rotated-role"

	// 90 days, 24 hours of jitter subtracted from it, 48 hours of overlap: the lifecycle the
	// type was specified for, and the scenario never waits for any of it. What is asserted here
	// is the steady state — re-serve, don't mint, don't renew — which is where a client spends
	// all but a few seconds of those 90 days.
	doSpacesRotationPeriodSeconds = 90 * 24 * 3600
	doSpacesRotationJitterSeconds = 24 * 3600
	doSpacesOverlapTTLSeconds     = 48 * 3600
)

func doSpacesRotatedCase(t *testing.T) e2eCase {
	srv := fakes.NewDOServer()
	t.Cleanup(srv.Close)

	return e2eCase{
		Cloud:     "do",
		Config:    map[string]any{doAPIURLField: srv.URL},
		MinterSet: minterSet(tokenMinter(doMinterToken)),
		RoleName:  doSpacesRotatedRoleName,
		Role: map[string]any{
			// max_ttl within the overlap, which the role write requires: a lease outliving the
			// grace a replaced key gets would name a credential that had been deleted.
			fieldDefaultTTL: shortTTL, fieldMaxTTL: hourTTL,
			fieldCredentialType: doSpacesRotatedCredentialType,
			fieldGrants:         doSpacesGrants,
			fieldRegion:         doSpacesRegion,
			fieldMinterSet:      defaultSet,
			fieldRotationPeriod: doSpacesRotationPeriodSeconds,
			fieldRotationJitter: doSpacesRotationJitterSeconds,
			fieldOverlapTTL:     doSpacesOverlapTTLSeconds,
		},
		TTLSeconds: shortTTL,
		// Not renewable, and this is the row that proves it: the credential's life is the role's
		// rotation schedule, so a renewal would push a lease past the moment it is deleted. The
		// client's contract is to re-read instead, which is what makes a rotation invisible to it.
		Renewable: false,
		// A lease ending deletes nothing — the credential is not the lease's — while the cloud
		// will still delete it on demand, so the purge lever works here. The two facts about
		// deletion come apart on exactly this row.
		HardRevoke:               false,
		TracksIssuedCredentials:  true,
		DeletesIssuedCredentials: true,
		SharesOneCredential:      true,
		Upstream:                 srv.ProvisionedSpacesKeyCount,
		CredentialKind:           credenvelope.KindS3Credentials,
	}
}
