// Package plugintest provides the shared, cloud-agnostic conformance suites for
// the cloud credential plugins. It is parameterized by a Harness so it never
// imports a specific plugin (which would create an import cycle).
//
// The rule this package exists to enforce: an invariant that holds for every
// cloud is asserted ONCE here and driven for all plugins from the conformance
// table (see the conformance/ module), so a plugin cannot quietly lack it. Only
// assertions phrased in a single cloud's vocabulary — the mint-request shape, the
// upstream error text, a provider-specific grant model — belong in a plugin's own
// _test.go files.
//
// A plugin that genuinely cannot exercise a category declares it in
// Harness.Skips with a reason. Declaring it is mandatory: RunConformance fails a
// harness that omits a category's required wiring without declaring the skip, so
// coverage gaps are visible in one table instead of being invisible absences.
package plugintest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Category names one conformance suite. Every category runs against every
// plugin unless the plugin's Harness.Skips declares otherwise.
type Category string

const (
	// CategoryReload rehydrates a backend from persisted storage with no
	// intervening config write (raft failover / plugin reload). Catches KI-001.
	CategoryReload Category = "reload"
	// CategoryPerturbation mutates the minter set mid-lease and revokes.
	// Catches KI-002.
	CategoryPerturbation Category = "perturbation"
	// CategoryLease covers the contract between the response envelope and the
	// lease core creates from the same handler: renewability, TTL, expiry, and
	// the RPC-survivability of internal_data. Catches KI-008.
	CategoryLease Category = "lease"
	// CategoryRevoke covers revoke behaviour under repetition.
	CategoryRevoke Category = "revoke"
	// CategoryCapability covers the configuration-time capability probe: a
	// minter that authenticates but cannot mint must be rejected at write time.
	CategoryCapability Category = "capability"
	// CategoryReconcilerSafety covers the owner-tag invariant: the reconciler
	// must never delete an entity the plugin did not create.
	CategoryReconcilerSafety Category = "reconciler-safety"
	// CategoryMinterVisibility covers what an operator can see: per-minter
	// lifecycle and health on the set read endpoint, and no credential material.
	CategoryMinterVisibility Category = "minter-visibility"
	// CategoryErrorTaxonomy covers the error_code contract: every error a client
	// can receive carries a code from the published vocabulary, and the code says
	// what the client should do. Catches the class KI-010 belongs to — a real
	// failure mode collapsing into `internal`.
	CategoryErrorTaxonomy Category = "error-taxonomy"
	// CategoryContainment covers the two levers an operator has when issued
	// credentials are believed to have leaked: stop the role issuing more, and
	// destroy what is already out there. Both must work from one call, without the
	// role's definition to hand.
	CategoryContainment Category = "containment"
	// CategoryRotation covers a credential SHARED by every reader and replaced on a
	// schedule: it is re-served rather than re-minted, a lease ending must not delete
	// it, and the credential it replaces has to stay live for the overlap and be gone
	// after it.
	CategoryRotation Category = "rotation"
	// CategoryProvenance covers WHO obtained a credential: the tracking record names the
	// caller core resolved, a caller cannot forge that, and a role may refuse to issue to a
	// caller this mount cannot name. Without it a leaked cloud credential is traceable to a
	// mount and a role and no further, while the question an incident asks is which unit is
	// compromised.
	CategoryProvenance Category = "provenance"
	// CategoryInventory covers the `issued/` endpoint: what this mount has handed out and not
	// yet revoked, which is what makes provenance answerable over the API rather than only
	// present in storage. It also fences the one place a tracking record becomes public — no
	// credential material may appear in a listing.
	CategoryInventory Category = "inventory"
)

// Harness is supplied by the conformance table, one per plugin. Fields are
// grouped by the category that consumes them; a category whose fields are unset
// must be declared in Skips.
type Harness struct {
	// --- Identity and wiring (every category) ---

	// Cloud is the plugin's cloud name, used only in failure messages.
	Cloud string
	// Factory constructs the backend under test.
	Factory logical.Factory
	// Inject wires per-backend test doubles (an injected cloud client) into a
	// backend instance. It is applied to EVERY backend the suites build,
	// including one rebuilt by a reload, which is what lets the injected-client
	// plugins (AWS/GCP/OCI) run the reload category at all. Nil for plugins
	// whose fake is an HTTP server reached through a config field.
	Inject func(b logical.Backend)
	// Configure writes config, the "default" minter set, and the role at
	// RolePath, so IssuePath can be read.
	Configure func(t *testing.T, b logical.Backend, storage logical.Storage)
	// IssuePath is the credential-issuing path, e.g. "creds/test-role".
	IssuePath string
	// RolePath is the storage/API path of the role Configure writes,
	// e.g. "roles/test-role".
	RolePath string
	// SetPath is the API path of the minter set Configure writes,
	// e.g. "minter-sets/default".
	SetPath string

	// --- Perturbation / revoke ---

	// RewriteDefaultSetWithout replaces the default set's minters with a
	// different minter, so the minter that issued a live lease is gone.
	RewriteDefaultSetWithout func(t *testing.T, b logical.Backend, storage logical.Storage)
	// ProvisionedCount reports upstream credentials the fake holds. On
	// hard-revoke clouds this is a live-entity count; on no-revoke clouds it is
	// a cumulative mint count, so only the hard-revoke clouds' counts are
	// asserted to return to zero.
	ProvisionedCount func() int
	// ExpectsHardRevoke is true when lease revoke deletes an upstream entity.
	ExpectsHardRevoke bool
	// DeletesIssuedCredentials is true when the cloud can destroy a credential this
	// subject has already issued, ahead of whatever expiry it carries.
	//
	// A SEPARATE fact from ExpectsHardRevoke, which says that a LEASE ENDING deletes
	// one. They coincide on most subjects, and keeping them one field made the two
	// unaskable apart: a credential shared by every reader must NOT be deleted when one
	// reader's lease ends, and must be deletable by an operator containing a leak. It is
	// this fact, not the lease's, that decides whether revoke-upstream acts or refuses,
	// and whether a capability probe is expected to leave nothing behind.
	DeletesIssuedCredentials bool
	// SharesOneCredential is true where a credential read serves ONE credential held by
	// every reader of the role, rather than minting one per lease. It changes what a
	// count of upstream credentials means — n reads leave one credential, not n — and it
	// is why minter affinity is unobservable on such a subject: the shared credential was
	// minted once, by one minter, and every later read re-serves it.
	SharesOneCredential bool
	// TrackingPrefix is the storage prefix a plugin writes its active-credential
	// record under, e.g. "active-tokens/". Set it and the revoke category asserts
	// the durability rule that record exists for: a credential whose tracking
	// write FAILS must be revoked rather than returned.
	//
	// Empty skips those cases. For the revoke case it is only meaningful where revoke is
	// hard — on a no-revoke cloud the credential self-expires, so an untracked one is
	// harmless and the write is metrics-only. The `provenance` category reads the record's
	// CONTENTS, so the prefix now matters on the no-revoke clouds too: it is the only
	// durable statement naming who obtained a credential that outlives the lease.
	TrackingPrefix string

	// --- Capability ---

	// ConfigureProbe writes config (with verify_minter_capability set to
	// verify) and the default set, but NO role: the capability suite writes
	// roles itself so it controls when a probe runs.
	ConfigureProbe func(t *testing.T, b logical.Backend, storage logical.Storage, verify bool)
	// ProbeRolePath is the API path of the role the capability suite writes.
	ProbeRolePath string
	// WriteProbeRole attempts to write that role bound to the default set and
	// returns the raw response (an error response is a valid outcome, so it must
	// not t.Fatal on one). The role's fields must be shaped so DenyMint's
	// refusal applies to it.
	WriteProbeRole func(t *testing.T, b logical.Backend, storage logical.Storage) *logical.Response
	// RewriteSet attempts to rewrite the default set so it holds exactly the
	// named minter, returning the raw response.
	RewriteSet func(t *testing.T, b logical.Backend, storage logical.Storage, minterID string) *logical.Response
	// WriteSetWithMinters rewrites the default set so it holds exactly the named
	// minters — two or more. Set it and the `lease` category asserts minter
	// affinity: that a shard key pins a client to one minter and that different
	// keys reach more than one.
	//
	// Separate from RewriteSet, which takes a single id and exists for the
	// minter-visibility and capability categories. Affinity is unobservable with a
	// one-minter set, so a harness that cannot write two declares nothing and the
	// case skips rather than passing vacuously.
	WriteSetWithMinters func(t *testing.T, b logical.Backend, storage logical.Storage, minterIDs ...string) *logical.Response

	// DenyMint makes the upstream refuse the mint call while the health call
	// keeps succeeding — the "authenticates but cannot mint" shape. It must be
	// sticky until AllowMint, not a one-shot next-request override.
	DenyMint func()
	// AllowMint undoes DenyMint.
	AllowMint func()
	// LiveMinterID is the minter ConfigureProbe writes into the default set;
	// ReplacementMinterID is a different id used to attempt a rewrite.
	LiveMinterID        string
	ReplacementMinterID string

	// WorkersRunning reports whether a backend's background workers are running,
	// via the plugin's exported test seam. Required: KI-007's guard asserted only
	// that Initialize returned nil, which it does when InitializeFunc is unset, so
	// the category passed with the defect reintroduced (A11).
	WorkersRunning func(b logical.Backend) bool

	// SeedAgedOrphans plants TWO upstream entities whose creation timestamp is old
	// enough to clear the reconciler's confirmation hold: one foreign (outside the
	// owner-tag scheme) and one owner-prefixed orphan that no lease references. It
	// returns their ids in that order.
	//
	// Required, because the existing SeedForeignEntity plants an entity with NO
	// timestamp — which the fail-closed age guard skips before the prefix filter is
	// ever consulted. The consequence was that the test protecting the invariant
	// CLAUDE.md calls load-bearing passed with the prefix filter deleted outright,
	// and DeleteEntity was never called once across 10 clouds x 7 categories (A9).
	//
	// storage is passed because a cloud whose list API reports no creation time
	// supplies it from the mint ledger instead (A5), which lives in storage. A cloud
	// that can do neither leaves the field nil and the suite prints why.
	SeedAgedOrphans func(t *testing.T, storage logical.Storage) (foreignID, ownedOrphanID string)

	// --- Rotation ---

	// The three seams below move stored DEADLINES into the past and then let the suite
	// make the ordinary call. They exist because a shared credential's contract is about
	// the passage of days — served for ninety, replaced, the replacement's predecessor
	// deleted forty-eight hours later — which cannot be waited for, and which a fake
	// clock would turn into a test of the suite's own arithmetic. Backdating storage is
	// the same state a restart rehydrates, so what runs afterwards is the production
	// path.

	// ForceRotationDue backdates the role's shared credential so it is overdue for
	// replacement.
	ForceRotationDue func(t *testing.T, b logical.Backend, storage logical.Storage) error
	// ForceOverlapExpired brings forward the deletion deadline of every credential the
	// role has retired, so a sweep is entitled to delete them.
	ForceOverlapExpired func(t *testing.T, b logical.Backend, storage logical.Storage) error
	// ForcePastRotationCeiling ages the shared credential past the maximum age its role
	// promises, which is the far side of the window a FAILED rotation may keep serving it in.
	//
	// Separate from ForceRotationDue, which makes the credential merely overdue. The two exist
	// because the fallback has two sides and only one of them is safe to leave unasserted: if
	// the window never closed, "rotate every 90 days" would quietly become "rotate when the
	// cloud lets us". A harness that leaves this nil still gets the inside-the-window case, and
	// the suite prints why the other did not run.
	ForcePastRotationCeiling func(t *testing.T, b logical.Backend, storage logical.Storage) error

	// SweepRetiredCredentials runs one pass of the plugin's own retirement sweep inline —
	// the same function its worker calls on a timer, so the suite exercises the pass
	// rather than a test-only reimplementation of it.
	SweepRetiredCredentials func(t *testing.T, b logical.Backend, storage logical.Storage) error
	// RotationOverlapTTL is the overlap the harness's role declares: how long a replaced
	// credential keeps working. It is the ceiling every lease on the shared credential
	// has to fit inside, because a read answered an instant before a rotation leaves the
	// client holding a credential with exactly this much life left.
	RotationOverlapTTL time.Duration

	// --- Error taxonomy ---

	// FailNextMintWithStatus makes the upstream answer the NEXT mint with the
	// given HTTP status, so the suite can assert the error_code a client is
	// handed. Return "" once applied, or a reason why this cloud's fake cannot
	// produce that status — the reason is printed rather than the case being
	// silently absent. Optional: a nil field means the forced-status cases are
	// not asserted for this cloud, which the suite also prints.
	FailNextMintWithStatus func(t *testing.T, status int) string

	// --- Reconciler safety ---

	// SeedForeignEntity plants an upstream entity whose name does NOT match the
	// owner-tag scheme and returns its id.
	SeedForeignEntity func() string
	// HasEntity reports whether the fake still holds the entity with that id.
	HasEntity func(id string) bool

	// CredentialKeys are the keys the `credential` block of this cloud's envelope
	// must contain, and OptionalCredentialKeys the ones it may. Declared rather than
	// inferred because the credential block is the part of the payload a client
	// actually consumes and it was documented for six of ten clouds and asserted for
	// none — which is how Exoscale shipped an API key with the `secret` that signs
	// requests silently dropped (A28 in docs/audit-2026-08-22.md).
	CredentialKeys []string
	// OptionalCredentialKeys may be present (Azure's subscription_id is set only when
	// the role names one).
	OptionalCredentialKeys []string
	// CredentialKind is the metadata.credential_kind this cloud reports, from the
	// closed vocabulary in pkg/credenvelope. It names the SHAPE of the credential
	// block, so a client can pin the shape it is able to parse instead of inferring it
	// from which cloud it asked.
	CredentialKind string

	// ScopeKind is the metadata.scope_kind this cloud reports, from the closed
	// vocabulary in pkg/credenvelope. It tells a client how to read metadata.scope,
	// which used to be one field name carrying ten different meanings.
	ScopeKind string

	// SecretType is the framework.Secret.Type string this plugin issues under, and
	// LeaseInternalDataKeys are the internal_data keys revoke needs. Both are stated
	// here as DATA rather than left implicit, because both are rename tripwires: the
	// secret type is how core routes a revoke to the right callback, and a lease
	// carrying an internal_data key the new binary no longer reads is a credential
	// nothing will ever revoke. Neither rename fails any other test (A30 in
	// docs/audit-2026-08-22.md), and this is also the only place the per-cloud lease
	// contract is written down at all (A28).
	SecretType string
	// LeaseInternalDataKeys must all be present on an issued lease.
	LeaseInternalDataKeys []string

	// IssuesFromPreprovisionedSlots is true where a credential read serves a slot
	// provisioned earlier rather than minting one, so it selects no minter. Only OCI
	// (phased rotation) sets it. It changes what a minter-level fault can be observed
	// to break: the next rotation, not the next read.
	IssuesFromPreprovisionedSlots bool

	// SystemView, when set, replaces the default logical.TestBackendConfig() system view for
	// every backend this harness builds. The lineage category needs it: the SDK's
	// StaticSystemView answers EntityInfo with one entity for EVERY id, which cannot express
	// "the caller's parent is a different entity" — the whole relationship under test.
	SystemView logical.SystemView

	// Skips declares categories this plugin cannot exercise, mapped to the reason. An
	// empty reason, or a key that is not a known category, fails the conformance run.
	Skips map[Category]string
}

// failWritesUnder wraps storage so Put fails for keys under one prefix, and behaves
// normally otherwise. Used to reach the create-then-track window deliberately: the
// upstream credential exists, and the plugin cannot record it.
type failWritesUnder struct {
	logical.Storage
	prefix string
	err    error
}

func (f *failWritesUnder) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if entry != nil && strings.HasPrefix(entry.Key, f.prefix) {
		return f.err
	}
	return f.Storage.Put(ctx, entry)
}

// newBackendWithStorage builds a configured backend over caller-supplied storage, so a
// test can interpose on it. Configuration is written through the SAME storage, so a
// wrapper that fails selectively must not fail the config writes.
func newBackendWithStorage(t *testing.T, h Harness, storage logical.Storage) logical.Backend {
	t.Helper()
	cfg := logical.TestBackendConfig()
	if h.SystemView != nil {
		cfg.System = h.SystemView
	}
	cfg.StorageView = storage
	b, err := h.Factory(t.Context(), cfg)
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	if h.Inject != nil {
		h.Inject(b)
	}
	h.Configure(t, b, storage)
	return b
}

// newConfiguredBackend builds a backend, injects any test doubles, and applies
// the harness's configuration.
func newConfiguredBackend(t *testing.T, h Harness) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := newBackend(t, h)
	h.Configure(t, b, storage)
	return b, storage
}

// newBackend builds a backend from the harness factory and injects test doubles,
// without writing any configuration.
func newBackend(t *testing.T, h Harness) (logical.Backend, logical.Storage) {
	t.Helper()
	cfg := logical.TestBackendConfig()
	if h.SystemView != nil {
		cfg.System = h.SystemView
	}
	cfg.StorageView = &logical.InmemStorage{}
	b, err := h.Factory(t.Context(), cfg)
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	if h.Inject != nil {
		h.Inject(b)
	}
	return b, cfg.StorageView
}

// Reload calls the factory again against the same storage, with no intervening
// config write — simulating a raft failover / plugin reload / process restart
// where only persisted state is available. Test doubles are re-injected, since a
// real reload keeps whatever client the plugin builds from persisted config.
func Reload(t *testing.T, h Harness, storage logical.Storage) logical.Backend {
	t.Helper()
	cfg := logical.TestBackendConfig()
	if h.SystemView != nil {
		cfg.System = h.SystemView
	}
	cfg.StorageView = storage
	b, err := h.Factory(t.Context(), cfg)
	if err != nil {
		t.Fatalf("reload factory failed: %v", err)
	}
	if h.Inject != nil {
		h.Inject(b)
	}
	return b
}

func issue(t *testing.T, b logical.Backend, storage logical.Storage, path string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   storage,
	})
}

// Write performs an update at path and fails the test if it does not succeed.
// Exported so harness constructors don't each re-declare it.
func Write(t *testing.T, b logical.Backend, storage logical.Storage, path string, data map[string]any) {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("%s write failed: err=%v resp=%v", path, err, resp)
	}
}

// TryWrite performs an update at path and returns the response. A transport-level
// error still fails the test; an error RESPONSE is returned to the caller, which
// is the outcome the capability suite asserts on.
func TryWrite(t *testing.T, b logical.Backend, storage logical.Storage, path string, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data,
	})
	if err != nil {
		t.Fatalf("%s write errored: %v", path, err)
	}
	return resp
}

// Read reads path and fails the test on a transport error. A nil response means
// "absent", which callers assert on.
func Read(t *testing.T, b logical.Backend, storage logical.Storage, path string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: path, Storage: storage,
	})
	if err != nil {
		t.Fatalf("%s read errored: %v", path, err)
	}
	return resp
}
