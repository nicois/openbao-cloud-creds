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
	"testing"

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
	// CategoryErrorTaxonomy covers the error_code contract: every error a client
	// can receive carries a code from the published vocabulary, and the code says
	// what the client should do. Catches the class KI-010 belongs to — a real
	// failure mode collapsing into `internal`.
	CategoryErrorTaxonomy Category = "error-taxonomy"
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
	// PlantDisabledProbeRole writes a DISABLED role bound to the default set
	// straight to storage (there is no disable endpoint), so the suite can check
	// a disabled role is not probed.
	PlantDisabledProbeRole func(t *testing.T, storage logical.Storage)
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

	// Skips declares categories this plugin cannot exercise, mapped to the
	// reason. An empty reason, or a key that is not a known category, fails the
	// conformance run.
	Skips map[Category]string
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
func Write(t *testing.T, b logical.Backend, storage logical.Storage, path string, data map[string]interface{}) {
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
func TryWrite(t *testing.T, b logical.Backend, storage logical.Storage, path string, data map[string]interface{}) *logical.Response {
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
