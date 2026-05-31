package credentialoci

import (
	"context"
	"sync"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
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

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,
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

	store := metrics.NewInMemoryStore()
	b.accessTracker = metrics.NewAccessTracker("local", store)

	if conf.StorageView != nil {
		_ = b.loadAllMinterSets(ctx, conf.StorageView)
	}

	return b, nil
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
