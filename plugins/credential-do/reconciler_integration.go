package credentialdo

import (
	"context"
	"net/http"

	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type doCloudLister struct {
	// instanceID scopes the reclaim filter to THIS mount. Matching the bare
	// cloud-creds- prefix meant two mounts against one cloud account each saw the
	// other's LIVE credentials as orphans and deleted them (A19).
	instanceID string
	client     *doClient
}

func (l *doCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	tokens, err := l.client.ListTokens(ctx)
	if err != nil {
		return nil, err
	}

	var entities []reconciler.UpstreamEntity
	for _, t := range tokens {
		if ownertag.Owns(l.instanceID, t.Name) {
			entities = append(entities, reconciler.UpstreamEntity{
				ID:        t.ID,
				Name:      t.Name,
				CreatedAt: reconciler.ParseCreatedAt(t.CreatedAt),
			})
		}
	}
	return entities, nil
}

func (l *doCloudLister) DeleteEntity(ctx context.Context, id string) error {
	status, err := l.client.DeleteToken(ctx, id)
	if err != nil && status != http.StatusNotFound {
		return err
	}
	return nil
}

type leaseRegistry struct {
	storage logical.Storage
}

func (r *leaseRegistry) OwnedIDs(ctx context.Context) (map[string]struct{}, error) {
	entries, err := r.storage.List(ctx, "active-tokens/")
	if err != nil {
		return nil, err
	}
	owned := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		owned[entry] = struct{}{}
	}
	// No minter ids to merge: this cloud cannot mint a mint-capable successor
	// (rotation is rejected), so no minter credential ever carries the owner
	// prefix the lister selects on. If rotation is ever implemented here, this is
	// where its RotationParams key must be merged in — see A1.
	return owned, nil
}
