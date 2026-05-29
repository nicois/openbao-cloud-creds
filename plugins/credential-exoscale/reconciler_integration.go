package credentialexoscale

import (
	"context"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const keyPrefix = "cloud-creds-"

type exoscaleCloudLister struct {
	client *exoscaleClient
}

func (l *exoscaleCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	keys, err := l.client.ListAPIKeys(ctx)
	if err != nil {
		return nil, err
	}

	var entities []reconciler.UpstreamEntity
	for _, k := range keys {
		if strings.HasPrefix(k.Name, keyPrefix) {
			entities = append(entities, reconciler.UpstreamEntity{
				ID:   k.KeyID,
				Name: k.Name,
			})
		}
	}
	return entities, nil
}

func (l *exoscaleCloudLister) DeleteEntity(ctx context.Context, id string) error {
	_, err := l.client.DeleteAPIKey(ctx, id)
	return err
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
