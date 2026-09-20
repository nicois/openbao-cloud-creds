//go:build e2e

package e2e

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

// Azure adds a password credential to an existing app registration with an
// endDateTime fixed at mint, so the lease must not be renewable. Both the Graph
// and the login (OAuth2) endpoints are config fields, so one fake serves both.
const (
	azureTenantField   = "tenant_id"
	azureGraphField    = "graph_endpoint"
	azureLoginField    = "login_endpoint"
	azureAppObjIDField = "app_object_id"
	azureClientIDField = "client_id"
	azureTenant        = "e2e-tenant-id"
	azureAppObjectID   = "fake-app-object-id"
	azureAppClientID   = "fake-app-client-id"
	azureMinterToken   = "fake-client-id:fake-client-secret"
)

func azureCase(t *testing.T) e2eCase {
	srv := fakes.NewAzureServer()
	t.Cleanup(srv.Close)

	return e2eCase{
		Cloud: "azure",
		Config: map[string]any{
			azureTenantField: azureTenant,
			azureGraphField:  srv.URL,
			azureLoginField:  srv.URL,
		},
		MinterSet: minterSet(tokenMinter(azureMinterToken)),
		Role: map[string]any{
			fieldDefaultTTL: hourTTL, fieldMaxTTL: dayTTL,
			azureAppObjIDField: azureAppObjectID, azureClientIDField: azureAppClientID,
			fieldMinterSet: defaultSet,
		},
		TTLSeconds:              hourTTL,
		Renewable:               false,
		HardRevoke:              true,
		TracksIssuedCredentials: true,
		// Every hard-revoke cloud can also be purged: the same delete call serves both.
		DeletesIssuedCredentials: true,
		Upstream:                 srv.ProvisionedCount,
	}
}
