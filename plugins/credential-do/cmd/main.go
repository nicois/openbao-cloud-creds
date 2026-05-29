package main

import (
	"os"

	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: credentialdo.Factory,
	}); err != nil {
		os.Exit(1)
	}
}
