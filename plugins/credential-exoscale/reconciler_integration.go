package credentialexoscale

import (
	"context"
	"net/http"
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
	status, err := l.client.DeleteAPIKey(ctx, id)
	if err != nil && status != http.StatusNotFound {
		return err
	}
	return nil
}

type leaseRegistry struct {
	storage logical.Storage
}

func (r *leaseRegistry) KnownIDs(ctx context.Context) (map[string]struct{}, error) {
	entries, err := r.storage.List(ctx, "active-tokens/")
	if err != nil {
		return nil, err
	}
	known := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		known[entry] = struct{}{}
	}
	return known, nil
}
