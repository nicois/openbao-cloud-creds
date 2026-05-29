package main

import (
	"os"

	"github.com/openbao/openbao/sdk/v2/plugin"
	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
)

func main() {
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: credentialdo.Factory,
	}); err != nil {
		os.Exit(1)
	}
}
