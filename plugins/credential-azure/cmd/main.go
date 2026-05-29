package main

import (
	"os"

	credentialazure "github.com/nicois/openbao-cloud-creds/plugins/credential-azure"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: credentialazure.Factory,
	}); err != nil {
		os.Exit(1)
	}
}
