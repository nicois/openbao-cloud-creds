package credentialazure

import (
	"context"
	"fmt"
	"net/http"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type azureCloudLister struct {
	// instanceID scopes the reclaim filter to THIS mount. Matching the bare
	// cloud-creds- prefix meant two mounts against one cloud account each saw the
	// other's LIVE credentials as orphans and deleted them (A19).
	instanceID   string
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
			if ownertag.Owns(l.instanceID, pw.DisplayName) {
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
	// Try each known app registration: a password id alone does not say which app
	// owns it. A 404 from one app simply means "not this one".
	//
	// Every error used to be swallowed and nil returned unconditionally, so the
	// reconciler incremented Deleted and left Errors empty even when every Graph
	// call failed on auth, throttling or 5xx — a false record of a
	// security-relevant deletion, with live client secrets still valid (A8 in
	// docs/audit-2026-08-22.md). The other five listers propagate unless 404.
	var lastErr error
	for _, appObjID := range l.appObjectIDs {
		status, err := l.client.RemovePassword(ctx, appObjID, id)
		if err == nil {
			return nil
		}
		if status == http.StatusNotFound {
			continue // this app does not own that password; try the next
		}
		lastErr = err
	}
	if lastErr != nil {
		return fmt.Errorf("removing password %q from %d app registration(s): %w",
			id, len(l.appObjectIDs), lastErr)
	}
	// Every app answered 404: the password is genuinely gone, which is success for
	// a reclamation pass.
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
