package conformance

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Paths and names every harness uses. They are uniform across the plugins by
// design (mount path is always cloud-creds/<cloud>/..., see CLAUDE.md), so a
// harness that needed a different one would be saying something about its cloud.
const (
	configPath    = "config"
	setPath       = "minter-sets/default"
	defaultSet    = "default"
	roleName      = "test-role"
	rolePath      = "roles/" + roleName
	issuePath     = "creds/" + roleName
	probeRoleName = "probe-role"
	probeRolePath = "roles/" + probeRoleName
)

// Minter ids the capability suite drives: the set is written holding liveMinterID
// and a rewrite is attempted with replacementMinterID.
const (
	liveMinterID        = "minter-1"
	replacementMinterID = "minter-2"
)

// The foreign entity the reconciler-safety suite plants. Its name deliberately
// does NOT match the owner-tag scheme (cloud-creds-<role>-), which is the only
// thing that makes an upstream entity eligible for deletion.
const (
	foreignEntityID   = "foreign-1"
	foreignEntityName = "someone-elses-entity"
)

// Field names shared by more than one plugin's API.
const (
	fieldMinters          = "minters"
	fieldID               = "id"
	fieldToken            = "token"
	fieldNeverExpires     = "never_expires"
	fieldName             = "name"
	fieldDefaultTTL       = "default_ttl"
	fieldMaxTTL           = "max_ttl"
	fieldScopes           = "scopes"
	fieldMinterSet        = "minter_set"
	fieldDisabled         = "disabled"
	fieldVerifyCapability = "verify_minter_capability"
	fieldCredentialType   = "credential_type"
	fieldGrants           = "grants"
	fieldRegion           = "region"
	fieldRotationPeriod   = "rotation_period"
	fieldRotationJitter   = "rotation_jitter"
	fieldOverlapTTL       = "overlap_ttl"
)

// TTLs used by the harness roles. Each is inside the cloud's enforceable range
// (docs/ttl-semantics.md); the clouds with narrower bounds override them.
const (
	shortTTL = 900
	hourTTL  = 3600
	dayTTL   = 86400
)

// noSharedCredential is why every subject but one declares no rotation category.
//
// One reason shared by ten of them rather than ten paraphrases of it, because the fact is a
// property of the LIFECYCLE and not of any cloud: where each read mints, the lease that read
// it owns it outright, so there is no credential held in common to replace on a schedule and no
// window in which a replaced one has to keep working. OCI shares a credential and still cannot
// exercise the category, for a reason of its own, and says so itself.
const noSharedCredential = "every credential read mints one credential for the lease that read " +
	"it, so nothing is shared between readers: there is no credential to replace on a schedule, " +
	"and a lease's own end is what bounds what it holds"

// minterSet wraps minter maps in the "minters" field every minter-set write takes.
func minterSet(m ...map[string]any) map[string]any {
	list := make([]any, 0, len(m))
	for _, one := range m {
		list = append(list, one)
	}
	return map[string]any{fieldMinters: list}
}

// tokenMinter builds the id/token/never_expires minter the token-style clouds
// take (DO, UpCloud, Azure, Vultr, Akamai, OCI).
func tokenMinter(id, token string) map[string]any {
	return map[string]any{fieldID: id, fieldToken: token, fieldNeverExpires: true}
}

// Aged seeding constants for the reconciler-safety suite's reclamation case.
//
// The timestamp is far enough in the past to clear any confirmation hold the
// plugins configure (1h worker, 5m manual floor). It is a fixed date rather than
// a relative one so a failure is reproducible and the fixture is not
// time-dependent.
const (
	agedTimestamp = "2020-01-01T00:00:00Z"

	// Outside the owner-tag scheme: must survive every pass.
	agedForeignID   = "aged-foreign-1"
	agedForeignName = "operator-created-do-not-touch"

	// Inside the owner-tag scheme and referenced by no lease: must be reclaimed,
	// which is what stops the invariant assertion above being vacuous. Its NAME is
	// computed per mount by agedOwnedName, because the scheme is instance-scoped
	// now — a hardcoded name would be foreign by construction and the case would
	// prove nothing (A19).
	agedOwnedID = "aged-owned-orphan-1"
)

// agedLedgerTime is when the mint-ledger-backed clouds pretend their owned orphan was
// minted: far enough back to clear any confirmation hold, and well inside
// mintledger.Retention so the entry has not been pruned.
func agedLedgerTime() time.Time {
	return time.Now().Add(-48 * time.Hour)
}

// agedOwnedName names the planted orphan with the MOUNT's own owner prefix, read from
// the same storage the plugin reads it from. Hardcoding it would make the entity
// foreign, and "the reconciler did not delete a foreign entity" is the assertion the
// other case already makes.
func agedOwnedName(t *testing.T, storage logical.Storage) string {
	t.Helper()
	id, err := ownertag.InstanceID(t.Context(), storage)
	if err != nil {
		t.Fatalf("resolving the owner instance id: %v", err)
	}
	return ownertag.CredentialName(id, "test-role", "stale-req")
}
