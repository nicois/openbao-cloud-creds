package credentialazure

import (
	"context"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const keyPrefix = "cloud-creds-"

type azureCloudLister struct {
	client       *azureClient
	appObjectIDs []string
}

func (l *azureCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	var entities []reconciler.UpstreamEntity

	for _, appObjID := range l.appObjectIDs {
		app, _, err := l.client.GetApplication(ctx, appObjID)
		if err != nil {
			return nil, err
		}

		for _, pw := range app.PasswordCredentials {
			if strings.HasPrefix(pw.DisplayName, keyPrefix) {
				entities = append(entities, reconciler.UpstreamEntity{
					ID:        pw.KeyID,
					Name:      pw.DisplayName,
					CreatedAt: reconciler.ParseCreatedAt(pw.StartDateTime),
				})
			}
		}
	}

	return entities, nil
}

func (l *azureCloudLister) DeleteEntity(ctx context.Context, id string) error {
	// We need to find which app this password belongs to.
	// For simplicity, try all known apps. In practice the reconciler stores
	// the app_object_id in active-tokens, but for orphan cleanup we iterate.
	for _, appObjID := range l.appObjectIDs {
		_, err := l.client.RemovePassword(ctx, appObjID, id)
		if err == nil {
			return nil
		}
	}
	// If we get here, the password was already gone or not found
	return nil
}

type leaseRegistry struct {
	storage logical.Storage
	ctx     context.Context
}

func (r *leaseRegistry) IsKnown(id string) bool {
	entries, err := r.storage.List(r.ctx, "active-tokens/")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry == id {
			return true
		}
	}
	return false
}
