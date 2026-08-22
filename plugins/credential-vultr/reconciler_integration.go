package credentialvultr

import (
	"context"
	"net/http"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/mintledger"
	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const userPrefix = "cloud-creds-"

type vultrCloudLister struct {
	client *vultrClient
	// storage is needed to read the mint ledger, which supplies the creation
	// time this cloud's list API does not report (A5).
	storage logical.Storage
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
				// This cloud's list API reports no creation time, so the age the
				// reconciler needs comes from our own mint ledger. Absent from the
				// ledger means unconfirmable, which means it survives (A5).
				CreatedAt: mintledger.CreatedAt(ctx, l.storage, u.ID),
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

func (r *leaseRegistry) OwnedIDs(ctx context.Context) (map[string]struct{}, error) {
	entries, err := r.storage.List(ctx, "active-users/")
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
