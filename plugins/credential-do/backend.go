package credentialdo

import (
	"context"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

const backendHelp = `
The DigitalOcean credential backend issues short-lived API tokens
via the DigitalOcean /v2/tokens API (JIT strategy).
`

type backend struct {
	*framework.Backend
	mu      sync.RWMutex
	config  *cloudconfig.PluginConfig
	minters map[string]*minterState
	apiURL  string
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
		),
		Secrets: []*framework.Secret{
			b.secretDO(),
		},
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}
