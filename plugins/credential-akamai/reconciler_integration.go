package credentialakamai

import (
	"context"
	"net/http"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const clientPrefix = "cloud-creds-"

type akamaiCloudLister struct {
	client *akamaiClient
}

func (l *akamaiCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	clients, err := l.client.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	var entities []reconciler.UpstreamEntity
	for _, c := range clients {
		if strings.HasPrefix(c.ClientName, clientPrefix) {
			entities = append(entities, reconciler.UpstreamEntity{
				ID:        c.ClientID,
				Name:      c.ClientName,
				CreatedAt: reconciler.ParseCreatedAt(c.CreatedDate),
			})
		}
	}
	return entities, nil
}

func (l *akamaiCloudLister) DeleteEntity(ctx context.Context, id string) error {
	status, err := l.client.DeleteClient(ctx, id)
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
	entries, err := r.storage.List(r.ctx, "active-clients/")
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
