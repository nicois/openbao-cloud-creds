package main

import (
	"os"

	credentialupcloud "github.com/nicois/openbao-cloud-creds/plugins/credential-upcloud"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: credentialupcloud.Factory,
	}); err != nil {
		os.Exit(1)
	}
}
