package credentialazure

import (
	"context"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const keyPrefix = "cloud-creds-"

type azureCloudLister struct {
	client       *azureClient
	appObjectIDs []string
}

func (l *azureCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	var entities []reconciler.UpstreamEntity

	for _, appObjID := range l.appObjectIDs {
		app, _, err := l.client.GetApplication(ctx, appObjID)
		if err != nil {
			return nil, err
		}

		for _, pw := range app.PasswordCredentials {
			if strings.HasPrefix(pw.DisplayName, keyPrefix) {
				entities = append(entities, reconciler.UpstreamEntity{
					ID:        pw.KeyID,
					Name:      pw.DisplayName,
					CreatedAt: reconciler.ParseCreatedAt(pw.StartDateTime),
				})
			}
		}
	}

	return entities, nil
}

func (l *azureCloudLister) DeleteEntity(ctx context.Context, id string) error {
	// We need to find which app this password belongs to.
	// For simplicity, try all known apps. In practice the reconciler stores
	// the app_object_id in active-tokens, but for orphan cleanup we iterate.
	for _, appObjID := range l.appObjectIDs {
		_, err := l.client.RemovePassword(ctx, appObjID, id)
		if err == nil {
			return nil
		}
	}
	// If we get here, the password was already gone or not found
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
	// A rotation successor is owner-prefixed (so the lister selects it) but is
	// not a lease, so it is invisible to the tracking entries above. Merging the
	// minter-recorded upstream ids is what makes the owned-set complete; without
	// it the reconciler deletes the set's own mint-capable credential (A1).
	// Fail-closed: an error here aborts the pass with zero deletes.
	minters, err := cloudconfig.MinterUpstreamIDs(ctx, r.storage, fieldKeyID)
	if err != nil {
		return nil, err
	}
	return cloudconfig.MergeOwned(owned, minters), nil
}
