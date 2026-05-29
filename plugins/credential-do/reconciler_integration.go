package credentialdo

import (
	"context"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const tokenPrefix = "cloud-creds-"

type doCloudLister struct {
	client *doClient
}

func (l *doCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	tokens, err := l.client.ListTokens(ctx)
	if err != nil {
		return nil, err
	}

	var entities []reconciler.UpstreamEntity
	for _, t := range tokens {
		if strings.HasPrefix(t.Name, tokenPrefix) {
			entities = append(entities, reconciler.UpstreamEntity{
				ID:   t.ID,
				Name: t.Name,
			})
		}
	}
	return entities, nil
}

func (l *doCloudLister) DeleteEntity(ctx context.Context, id string) error {
	_, err := l.client.DeleteToken(ctx, id)
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
