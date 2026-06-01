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
