package credentialexoscale

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
The Exoscale credential backend issues short-lived API keys
via the Exoscale /v2/api-key API (JIT strategy).
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
	apiURL            string
	accessTracker     *metrics.AccessTracker
	workerMgr         *worker.Manager
	workerCancel      context.CancelFunc
}

type minterState struct {
	set    string
	minter cloudconfig.Minter
	sm     *recovery.StateMachine
}

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
			b.reconcilePaths(),
			b.metricsPaths(),
		),
		Secrets: []*framework.Secret{
			b.secretExoscale(),
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
