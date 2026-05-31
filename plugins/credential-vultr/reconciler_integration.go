package credentialvultr

import (
	"context"
	"net/http"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const userPrefix = "cloud-creds-"

type vultrCloudLister struct {
	client *vultrClient
}

func (l *vultrCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	users, err := l.client.ListUsers(ctx)
	if err != nil {
		return nil, err
	}

	var entities []reconciler.UpstreamEntity
	for _, u := range users {
		if strings.HasPrefix(u.Name, userPrefix) {
			entities = append(entities, reconciler.UpstreamEntity{
				ID:   u.ID,
				Name: u.Name,
			})
		}
	}
	return entities, nil
}

func (l *vultrCloudLister) DeleteEntity(ctx context.Context, id string) error {
	status, err := l.client.DeleteUser(ctx, id)
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
	entries, err := r.storage.List(r.ctx, "active-users/")
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
