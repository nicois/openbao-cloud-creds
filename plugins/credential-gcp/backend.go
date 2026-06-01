package credentialgcp

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
The GCP credential backend issues short-lived access tokens
by impersonating service accounts via the IAM Credentials API (JIT strategy).
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
	project           string
	accessTracker     *metrics.AccessTracker
	workerMgr         *worker.Manager
	workerCancel      context.CancelFunc
	// baseCtx is the parent context for all worker goroutines; baseCancel is
	// fired from Clean (backend teardown) so leaked workers cannot outlive the
	// backend. Worker launch sites use baseCtx rather than context.Background().
	baseCtx     context.Context
	baseCancel  context.CancelFunc
	iamClientFn IAMClientFactory
	// saKeyClientFn builds the service-account KEY-MANAGEMENT client used for
	// minter self-rotation (keys.create/keys.delete on the minter's SA). Mirrors
	// iamClientFn: tests inject a fake; when nil the real REST client is used.
	// This is the KEY-MANAGEMENT client, distinct from the impersonation
	// issuance client (iamClientFn / IAMCredentialsClient).
	saKeyClientFn SAKeyClientFactory
	// rotateSweepMu serializes minter rotation (the rotate endpoint) against the
	// retired-sweep, so a rotation's read-modify-write of a set never interleaves
	// with the sweep's. Held WITHOUT b.mu across the whole orchestration / sweep
	// body; b.mu is taken only inside the small helpers (loadMinterSet,
	// selectMinter, …) — never across a rotateSweepMu critical section — so no
	// AB-BA deadlock with b.mu exists.
	rotateSweepMu sync.Mutex
}

type minterState struct {
	set    string
	minter cloudconfig.Minter
	sm     *recovery.StateMachine
}

// IAMClientFactory creates an IAMCredentialsClient for a given minter credential (SA JSON).
type IAMClientFactory func(credentialsJSON string) IAMCredentialsClient

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		minterSets: make(map[string]map[string]*minterState),
	}
	b.baseCtx, b.baseCancel = context.WithCancel(context.Background())

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,
		Clean:       func(_ context.Context) { b.stopWorkers() },
		Paths: framework.PathAppend(
			b.configPaths(),
			b.minterSetPaths(),
			b.rolePaths(),
			b.credsPaths(),
			b.reconcilePaths(),
			b.metricsPaths(),
		),
		Secrets: []*framework.Secret{
			b.secretGCP(),
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
		_ = b.loadAllMinterSets(ctx, conf.StorageView)
	}

	return b, nil
}
