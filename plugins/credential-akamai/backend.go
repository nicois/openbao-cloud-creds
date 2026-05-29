package credentialakamai

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
The Akamai credential backend issues short-lived API client credentials
by creating API clients via the Akamai Identity Management v3 API (JIT strategy).
`

type backend struct {
	*framework.Backend
	mu            sync.RWMutex
	config        *cloudconfig.PluginConfig
	minters       map[string]*minterState
	host          string
	apiURL        string
	accessTracker *metrics.AccessTracker
	workerMgr     *worker.Manager
	workerCancel  context.CancelFunc
}

type minterState struct {
	minter cloudconfig.Minter
	sm     *recovery.StateMachine
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		minters: make(map[string]*minterState),
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,
		Paths: framework.PathAppend(
			b.configPaths(),
			b.rolePaths(),
			b.credsPaths(),
			b.reconcilePaths(),
			b.metricsPaths(),
		),
		Secrets: []*framework.Secret{
			b.secretAkamai(),
		},
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	store := metrics.NewInMemoryStore()
	b.accessTracker = metrics.NewAccessTracker("local", store)

	return b, nil
}
