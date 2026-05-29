package main

import (
	"os"

	credentialakamai "github.com/nicois/openbao-cloud-creds/plugins/credential-akamai"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: credentialakamai.Factory,
	}); err != nil {
		os.Exit(1)
	}
}
