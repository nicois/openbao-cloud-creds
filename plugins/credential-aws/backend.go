package credentialaws

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
The AWS credential backend issues short-lived STS credentials
by calling AssumeRole directly (JIT strategy).
`

type backend struct {
	*framework.Backend
	mu sync.RWMutex
	// workerLifecycleMu serializes startWorkers so a manager is never Wait()ed
	// by one goroutine while another is still Start()ing it. Multiple writes
	// (config + each minter set) each fire startWorkers, so overlap is common.
	workerLifecycleMu sync.Mutex
	config            *cloudconfig.PluginConfig
	minterSets        map[string]map[string]*minterState // setName -> minterID -> state
	region            string
	stsEndpoint       string
	accessTracker     *metrics.AccessTracker
	workerMgr         *worker.Manager
	workerCancel      context.CancelFunc
	stsClientFn       STSClientFactory
	// iamMinterClientFn builds the IAM access-key management client used for
	// minter self-rotation (CreateAccessKey/DeleteAccessKey/ListAccessKeys on the
	// minter IAM user). Mirrors stsClientFn: tests inject a fake; when nil the
	// real SigV4-signed IAM client is used. This is the KEY-MANAGEMENT client,
	// distinct from the STS issuance client.
	iamMinterClientFn IAMMinterClientFactory
	// rotateSweepMu serializes minter rotation (the rotate endpoint) against the
	// retired-sweep, so a rotation's read-modify-write of a set never interleaves
	// with the sweep's. Held WITHOUT b.mu across the whole orchestration / sweep
	// body; b.mu is taken only inside the small helpers (loadMinterSet,
	// selectMinter, …) — never across a rotateSweepMu critical section — so no
	// AB-BA deadlock with b.mu exists.
	rotateSweepMu sync.Mutex
	// baseCtx is the parent context for all worker goroutines; baseCancel is
	// fired from Clean (backend teardown) so leaked workers cannot outlive the
	// backend. Worker launch sites use baseCtx rather than context.Background().
	baseCtx    context.Context
	baseCancel context.CancelFunc
}

type minterState struct {
	set    string
	minter cloudconfig.Minter
	sm     *recovery.StateMachine
}

// STSClientFactory creates an STSClient for a given minter credential.
type STSClientFactory func(accessKeyID, secretAccessKey, region, endpoint string) STSClient

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
			b.reconcilePaths(),
			b.metricsPaths(),
		),
		Secrets: []*framework.Secret{
			b.secretAWS(),
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
