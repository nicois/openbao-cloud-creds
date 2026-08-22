package credentialoci

import (
	"context"
	"sync"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
	"github.com/nicois/openbao-cloud-creds/pkg/worker"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const backendHelp = `
The OCI credential backend issues short-lived auth tokens via phased rotation.
Unlike JIT plugins, it pre-provisions credential slots and rotates them on a schedule.
OCI limits each user to max 2 auth tokens, so this plugin manages 2 slots per role-user
and rotates one every T/2 (default T=7d).

Slots are provisioned and rotated using a healthy minter from the role's bound minter set.
Each slot records the set + minter that provisioned it so rotation and cleanup stay within
the role's set.
`

type backend struct {
	// instanceID identifies THIS mount in the names of the upstream credentials it
	// creates; see ownerInstanceID. Guarded by mu.
	instanceID string
	*framework.Backend
	mu sync.RWMutex
	// workerLifecycleMu serializes startWorkers so a manager is never Wait()ed
	// by one goroutine while another is still Start()ing it. Multiple writes
	// (config + each minter set) each fire startWorkers, so overlap is common.
	workerLifecycleMu sync.Mutex
	// rotateReconcileMu serializes a slot rotation (create+persist+delete) against
	// a reconcile pass (snapshot known-set -> list upstream -> delete unknowns).
	// Without it a rotation can land mid-reconcile: the reconcile snapshot is taken
	// before the upstream list, so a token created+persisted by rotation in that
	// window is present upstream but absent from the stale snapshot, and reconcile
	// deletes the freshly-rotated live token (audit F4).
	//
	// Lock ordering: rotateReconcileMu is the OUTERMOST lock. b.mu (the request /
	// config RWMutex) is only ever acquired-and-released INSIDE the helper calls
	// (selectMinterForSet, clientForSlot, maxDeletesForPass, etc.) — it is never
	// held across a rotation or reconcile body, so it can never be held while
	// acquiring rotateReconcileMu. No nesting in the opposite order exists, so
	// there is no deadlock.
	rotateReconcileMu sync.Mutex
	config            *cloudconfig.PluginConfig
	minterSets        map[string]map[string]*minterState // setName -> minterID -> state
	region            string
	accessTracker     *metrics.AccessTracker
	workerMgr         *worker.Manager
	workerCancel      context.CancelFunc
	// baseCtx is the parent context for all worker goroutines; baseCancel is
	// fired from Clean (backend teardown) so leaked workers cannot outlive the
	// backend. Worker launch sites use baseCtx, never context.Background().
	//
	// baseCtx is rooted at context.Background() deliberately, and it is the only
	// such root in the plugin: workers must live as long as the BACKEND, and the
	// contexts available where they start (Factory's, Initialize's) are REQUEST
	// contexts that core cancels the moment that request returns — deriving from
	// one would stop every worker seconds after the mount came up.
	baseCtx    context.Context
	baseCancel context.CancelFunc

	// clientFactory builds an OCIIAMClient from a minter token
	// ("tenancy_ocid:user_ocid:fingerprint:private_key_pem"). Tests override this
	// to route every per-set minter through an in-memory fake.
	clientFactory func(token string) OCIIAMClient
}

type minterState struct {
	set    string
	minter cloudconfig.Minter
	sm     *recovery.StateMachine
}

// Factory creates the OCI credential backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		minterSets: make(map[string]map[string]*minterState),
	}
	b.baseCtx, b.baseCancel = context.WithCancel(context.Background())

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,
		Clean:       func(_ context.Context) { b.stopWorkers() },
		// InitializeFunc is the hook core calls on a backend it has just built
		// (mount setup, unseal, plugin reload) — the only place background workers
		// can be started for a backend nobody is about to write config to. Factory
		// must not start them: a config-less construction (a test, a CLI probe)
		// would begin network work with no minters. The config and minter-set write
		// paths also start them, but those do not run on failover, so before this
		// hook existed a rehydrated node had no health checks, no metrics flush and
		// no reconciler until an operator rewrote config (KI-007).
		InitializeFunc: b.initialize,
		Paths: framework.PathAppend(
			b.configPaths(),
			b.minterSetPaths(),
			b.rolePaths(),
			b.credsPaths(),
			b.rotateSlotPaths(),
			b.reconcilePaths(),
			b.metricsPaths(),
		),
		Secrets: []*framework.Secret{
			b.secretOCI(),
		},
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	var store metrics.MetricsStore = metrics.NewInMemoryStore()
	if conf.StorageView != nil {
		store = metrics.NewStorageBackedStore(conf.StorageView)
	}
	b.accessTracker = metrics.NewAccessTracker(metrics.ResolveNodeID(), store)

	if conf.StorageView != nil {
		_ = b.loadConfig(ctx, conf.StorageView)
		_ = b.loadAllMinterSets(ctx, conf.StorageView)
	}

	return b, nil
}

// initialize rehydrates persisted state and starts the background workers. It
// runs on the active node after mount setup and after every unseal or plugin
// reload; see the InitializeFunc comment in Factory for why Factory cannot do
// this. Load failures are logged rather than returned: a malformed stored entry
// must not make the mount unusable, matching Factory's best-effort load.
func (b *backend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	if req == nil || req.Storage == nil {
		return nil
	}
	if err := b.loadConfig(ctx, req.Storage); err != nil {
		b.Logger().Warn("initialize: failed to load stored config", "error", err)
	}
	if err := b.loadAllMinterSets(ctx, req.Storage); err != nil {
		b.Logger().Warn("initialize: failed to load stored minter sets", "error", err)
	}
	go b.startWorkers(b.baseCtx, req.Storage)
	return nil
}

// newOCIClient builds an OCIIAMClient for the given minter token. The token is
// the opaque "tenancy_ocid:user_ocid:fingerprint:private_key_pem" string. When a
// clientFactory is registered (tests), it is used; otherwise a real signing
// client is constructed.
func (b *backend) newOCIClient(token string) OCIIAMClient {
	b.mu.RLock()
	factory := b.clientFactory
	region := b.region
	b.mu.RUnlock()
	if factory != nil {
		return factory(token)
	}
	return newSigningOCIClient(token, region)
}

// SetClientFactory registers a factory used to build OCI clients from minter
// tokens. Tests use this to route the per-set minter through an in-memory fake.
func (b *backend) SetClientFactory(factory func(token string) OCIIAMClient) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clientFactory = factory
}

// machinesOf collects a set's recovery state machines so the shared diagnosis can
// say WHY the set could serve nobody — a rate-limit cooldown that will clear in
// seconds, or credentials that will not.
func machinesOf(states map[string]*minterState) []*recovery.StateMachine {
	machines := make([]*recovery.StateMachine, 0, len(states))
	for _, ms := range states {
		if !ms.minter.Retired {
			machines = append(machines, ms.sm)
		}
	}
	return machines
}

// ownerInstanceID returns this mount's owner instance id, minting and persisting one on
// first use. It is cached because the id is immutable for the life of the mount, and
// because the reconciler's lister and the capability probe both need it in places that
// have no storage handle.
//
// The id is what stops two mounts against one cloud account deleting each other's live
// credentials: the reclaim filter used to be the bare `cloud-creds-` prefix, which
// identifies the product rather than the instance (A19 in docs/audit-2026-08-22.md).
func (b *backend) ownerInstanceID(ctx context.Context, storage logical.Storage) (string, error) {
	b.mu.RLock()
	cached := b.instanceID
	b.mu.RUnlock()
	if cached != "" {
		return cached, nil
	}
	id, err := ownertag.InstanceID(ctx, storage)
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	b.instanceID = id
	b.mu.Unlock()
	return id, nil
}
