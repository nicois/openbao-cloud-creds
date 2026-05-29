package main

import (
	"os"

	credentialvultr "github.com/nicois/openbao-cloud-creds/plugins/credential-vultr"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: credentialvultr.Factory,
	}); err != nil {
		os.Exit(1)
	}
}
