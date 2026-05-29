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
`

type backend struct {
	*framework.Backend
	mu            sync.RWMutex
	config        *cloudconfig.PluginConfig
	minters       map[string]*minterState
	client        OCIIAMClient
	region        string
	accessTracker *metrics.AccessTracker
	workerMgr     *worker.Manager
	workerCancel  context.CancelFunc
}

type minterState struct {
	minter cloudconfig.Minter
	sm     *recovery.StateMachine
}

// Factory creates the OCI credential backend.
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

	return b, nil
}

// SetClient allows tests to inject a fake OCI client.
func (b *backend) SetClient(client OCIIAMClient) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.client = client
}

func (b *backend) getClient() OCIIAMClient {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.client
}
