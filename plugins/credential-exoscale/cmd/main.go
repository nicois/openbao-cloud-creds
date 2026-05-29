package main

import (
	"os"

	credentialexoscale "github.com/nicois/openbao-cloud-creds/plugins/credential-exoscale"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: credentialexoscale.Factory,
	}); err != nil {
		os.Exit(1)
	}
}
