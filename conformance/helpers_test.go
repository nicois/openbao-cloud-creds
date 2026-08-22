package conformance

import (
	"testing"
	"time"

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
)

// TTLs used by the harness roles. Each is inside the cloud's enforceable range
// (docs/ttl-semantics.md); the clouds with narrower bounds override them.
const (
	shortTTL = 900
	hourTTL  = 3600
	dayTTL   = 86400
)

// minterSet wraps minter maps in the "minters" field every minter-set write takes.
func minterSet(m ...map[string]interface{}) map[string]interface{} {
	list := make([]interface{}, 0, len(m))
	for _, one := range m {
		list = append(list, one)
	}
	return map[string]interface{}{fieldMinters: list}
}

// tokenMinter builds the id/token/never_expires minter the token-style clouds
// take (DO, UpCloud, Azure, Vultr, Akamai, OCI).
func tokenMinter(id, token string) map[string]interface{} {
	return map[string]interface{}{fieldID: id, fieldToken: token, fieldNeverExpires: true}
}

// plantDisabledRole writes a DISABLED role straight to storage. There is no
// disable endpoint — Disabled is set out of band — so the capability suite's
// "a disabled role must not block a minter-set write" case needs this. Only the
// fields the set-write path reads are planted; a disabled role is never probed,
// so its mint-shape fields are irrelevant.
func plantDisabledRole(t *testing.T, storage logical.Storage) {
	t.Helper()
	entry, err := logical.StorageEntryJSON(probeRolePath, map[string]interface{}{
		fieldName: probeRoleName, fieldMinterSet: defaultSet, fieldDisabled: true,
	})
	if err != nil {
		t.Fatalf("building the disabled role entry failed: %v", err)
	}
	if err := storage.Put(t.Context(), entry); err != nil {
		t.Fatalf("planting the disabled role failed: %v", err)
	}
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
	// which is what stops the invariant assertion above being vacuous.
	agedOwnedID   = "aged-owned-orphan-1"
	agedOwnedName = "cloud-creds-test-role-stale-req"
)

// agedLedgerTime is when the mint-ledger-backed clouds pretend their owned orphan was
// minted: far enough back to clear any confirmation hold, and well inside
// mintledger.Retention so the entry has not been pruned.
func agedLedgerTime() time.Time {
	return time.Now().Add(-48 * time.Hour)
}
