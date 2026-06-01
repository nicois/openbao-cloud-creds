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
}

func (r *leaseRegistry) KnownIDs(ctx context.Context) (map[string]struct{}, error) {
	entries, err := r.storage.List(ctx, "active-users/")
	if err != nil {
		return nil, err
	}
	known := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		known[entry] = struct{}{}
	}
	return known, nil
}
