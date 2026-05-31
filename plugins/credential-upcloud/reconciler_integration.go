package credentialupcloud

import (
	"context"
	"net/http"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const tokenPrefix = "cloud-creds-"

type upcloudCloudLister struct {
	client *upcloudClient
}

func (l *upcloudCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	tokens, err := l.client.ListTokens(ctx)
	if err != nil {
		return nil, err
	}

	var entities []reconciler.UpstreamEntity
	for _, t := range tokens {
		if strings.HasPrefix(t.Name, tokenPrefix) {
			entities = append(entities, reconciler.UpstreamEntity{
				ID:        t.ID,
				Name:      t.Name,
				CreatedAt: reconciler.ParseCreatedAt(t.Created),
			})
		}
	}
	return entities, nil
}

func (l *upcloudCloudLister) DeleteEntity(ctx context.Context, id string) error {
	status, err := l.client.DeleteToken(ctx, id)
	if err != nil && status != http.StatusNotFound {
		return err
	}
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
