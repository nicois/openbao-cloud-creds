package credentialakamai

import (
	"context"
	"net/http"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type akamaiCloudLister struct {
	// instanceID scopes the reclaim filter to THIS mount. Matching the bare
	// cloud-creds- prefix meant two mounts against one cloud account each saw the
	// other's LIVE credentials as orphans and deleted them (A19).
	instanceID string
	client     *akamaiClient
}

func (l *akamaiCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	clients, err := l.client.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	var entities []reconciler.UpstreamEntity
	for _, c := range clients {
		if ownertag.Owns(l.instanceID, c.ClientName) {
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
}

func (r *leaseRegistry) OwnedIDs(ctx context.Context) (map[string]struct{}, error) {
	entries, err := r.storage.List(ctx, "active-clients/")
	if err != nil {
		return nil, err
	}
	owned := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		owned[entry] = struct{}{}
	}
	// A rotation successor is owner-prefixed (so the lister selects it) but is
	// not a lease, so it is invisible to the tracking entries above. Merging the
	// minter-recorded upstream ids is what makes the owned-set complete; without
	// it the reconciler deletes the set's own mint-capable credential (A1).
	// Fail-closed: an error here aborts the pass with zero deletes.
	minters, err := cloudconfig.MinterUpstreamIDs(ctx, r.storage, fieldClientID)
	if err != nil {
		return nil, err
	}
	return cloudconfig.MergeOwned(owned, minters), nil
}
