package credentialexoscale

import (
	"context"
	"net/http"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/mintledger"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type exoscaleCloudLister struct {
	// instanceID scopes the reclaim filter to THIS mount. Matching the bare
	// cloud-creds- prefix meant two mounts against one cloud account each saw the
	// other's LIVE credentials as orphans and deleted them (A19).
	instanceID string
	client     *exoscaleClient
	// storage is needed to read the mint ledger, which supplies the creation
	// time this cloud's list API does not report (A5).
	storage logical.Storage
}

func (l *exoscaleCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	keys, err := l.client.ListAPIKeys(ctx)
	if err != nil {
		return nil, err
	}

	var entities []reconciler.UpstreamEntity
	for _, k := range keys {
		if ownertag.Owns(l.instanceID, k.Name) {
			entities = append(entities, reconciler.UpstreamEntity{
				ID:   k.KeyID,
				Name: k.Name,
				// This cloud's list API reports no creation time, so the age the
				// reconciler needs comes from our own mint ledger. Absent from the
				// ledger means unconfirmable, which means it survives (A5).
				CreatedAt: mintledger.CreatedAt(ctx, l.storage, k.KeyID),
			})
		}
	}
	return entities, nil
}

func (l *exoscaleCloudLister) DeleteEntity(ctx context.Context, id string) error {
	status, err := l.client.DeleteAPIKey(ctx, id)
	if err != nil && status != http.StatusNotFound {
		return err
	}
	return nil
}

type leaseRegistry struct {
	storage logical.Storage
}

func (r *leaseRegistry) OwnedIDs(ctx context.Context) (map[string]struct{}, error) {
	entries, err := r.storage.List(ctx, activeTrackingPrefix)
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
