package credentialdo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Orphan reclamation for a plugin that issues TWO credential classes.
//
// pkg/reconciler moves opaque ids between a lister and a registry, which is exactly the right
// shape here — but it means the classes are indistinguishable to it, so both sides of this file
// speak ids that carry their class (`token:<id>`, `spaces_key:<access key>`). Two things depend on
// that, and neither is cosmetic:
//
//   - DeleteEntity receives nothing but an id, and the two classes are different endpoints. A bare
//     id would have to be guessed at, and a guess deletes from an id space the credential may not
//     belong to.
//   - Ownership is decided by membership of a set. The id spaces are independent, so the same
//     string can name a live credential in one class and an orphan in the other; sharing a key
//     space would let a tracked token shield a Spaces key from reclamation forever.

// reconcileClassSeparator joins a credential class to its upstream id. A colon is safe in both id
// spaces: DO token ids are uuids and Spaces access keys are upper-case alphanumerics, so neither
// can contain one, and the split takes the FIRST colon regardless.
const reconcileClassSeparator = ":"

// classedID renders the form the reconciler passes around.
func classedID(class, id string) string {
	return class + reconcileClassSeparator + id
}

// splitClassedID recovers the class and upstream id, reporting false for anything that is not in
// the classed form at all. Not tolerant by design — see DeleteEntity.
func splitClassedID(classed string) (class, id string, ok bool) {
	class, id, ok = strings.Cut(classed, reconcileClassSeparator)
	if !ok || class == "" || id == "" {
		return "", "", false
	}
	return class, id, true
}

type doCloudLister struct {
	// instanceID scopes the reclaim filter to THIS mount. Matching the bare
	// cloud-creds- prefix meant two mounts against one cloud account each saw the
	// other's LIVE credentials as orphans and deleted them (A19).
	instanceID string
	client     *doClient
	// logger carries the one signal a partial pass has. A class that cannot be listed is
	// tolerated rather than fatal (see ListTaggedEntities), which would otherwise be silent.
	logger hclog.Logger
}

// classListing is one credential class's contribution to a pass: its name, for diagnostics, and
// the listing that yields its owned entities already in classed form.
type classListing struct {
	class string
	list  func(context.Context) ([]reconciler.UpstreamEntity, error)
}

func (l *doCloudLister) classListings() []classListing {
	return []classListing{
		{credentialTypeToken, l.listTokens},
		{credentialTypeSpacesKey, l.listSpacesKeys},
	}
}

// ListTaggedEntities enumerates the owner-tagged credentials of every class this plugin issues.
//
// A class that cannot be listed is WARNED about and skipped; only a pass where every class failed
// is an error. That asymmetry is the point rather than laxity: on real DigitalOcean GET /v2/tokens
// is fenced at the edge gateway for every PAT (KI-009), so an all-or-nothing pass would disable
// orphan reclamation for Spaces keys — the class that works, and the one that needs it most, since
// a Spaces key has no upstream expiry and counts against a 200-per-account cap until something
// deletes it. Skipping a class is safe in the direction that matters: an unlisted credential is
// never nominated for deletion, so a partial listing can only under-reclaim.
//
// Every class failing is different. Then the pass has learned nothing about what exists upstream,
// and reporting an empty listing would be indistinguishable from an empty account.
func (l *doCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	var entities []reconciler.UpstreamEntity
	var failures []error

	listings := l.classListings()
	for _, listing := range listings {
		found, err := listing.list(ctx)
		if err != nil {
			failures = append(failures, fmt.Errorf("listing %s credentials: %w", listing.class, err))
			l.warn("reconciler: a credential class could not be listed and was skipped this pass; "+
				"its orphans are not reclaimable until it can be listed",
				fieldCloud, cloudName, fieldCredentialType, listing.class, "error", err)
			continue
		}
		entities = append(entities, found...)
	}

	if len(failures) == len(listings) {
		return nil, errors.Join(failures...)
	}
	return entities, nil
}

// upstreamCredential is all a reclamation decision needs from a listing, whichever class it came
// from: what a delete would address, the name ownership is judged by, and how old it is. The two
// classes' upstream records share no Go type and never will — they are different DO products — but
// they share this view, which is what lets one filter serve both.
type upstreamCredential struct{ id, name, createdAt string }

// ownedEntities keeps the credentials THIS mount owns and renders them in the classed form. Every
// reclamation-safety property lives in these few lines — the owner-tag filter that is the
// load-bearing invariant, and the class prefix without which one class's live credentials read as
// the other's orphans — so both classes run the same copy of them rather than a parallel one that
// could be fixed on one side only.
func ownedEntities[T any](
	instanceID, class string,
	records []T,
	view func(T) upstreamCredential,
) []reconciler.UpstreamEntity {
	var entities []reconciler.UpstreamEntity
	for _, record := range records {
		credential := view(record)
		if !ownertag.Owns(instanceID, credential.name) {
			continue
		}
		entities = append(entities, reconciler.UpstreamEntity{
			ID:        classedID(class, credential.id),
			Name:      credential.name,
			CreatedAt: reconciler.ParseCreatedAt(credential.createdAt),
		})
	}
	return entities
}

func (l *doCloudLister) listTokens(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	tokens, err := l.client.ListTokens(ctx)
	if err != nil {
		return nil, err
	}
	return ownedEntities(l.instanceID, credentialTypeToken, tokens,
		func(t tokenInfo) upstreamCredential {
			return upstreamCredential{id: t.ID, name: t.Name, createdAt: t.CreatedAt}
		}), nil
}

// listSpacesKeys yields Spaces keys with no ExpiresAt, which is not an omission: this credential
// type has no upstream expiry at all, so every orphan of it is a LIVE one and draws on the
// conservative per-pass budget rather than the housekeeping one.
func (l *doCloudLister) listSpacesKeys(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	keys, err := l.client.ListSpacesKeys(ctx)
	if err != nil {
		return nil, err
	}
	return ownedEntities(l.instanceID, credentialTypeSpacesKey, keys,
		func(k spacesKeyInfo) upstreamCredential {
			// The access key IS the identifier — DO gives a Spaces key no separate id — so it is
			// what a delete addresses, exactly as a lease's internal_data records it.
			return upstreamCredential{id: k.AccessKey, name: k.Name, createdAt: k.CreatedAt}
		}), nil
}

// DeleteEntity dispatches on the class carried by the id.
//
// An id that does not carry one is REFUSED rather than assumed to be a token. Defaulting would
// reintroduce precisely the bug the classed form exists to prevent — a delete issued against the
// wrong id space, which on a 404 reports success and leaves a live credential in place — and an
// unclassed id reaching here means something in this file is out of step with itself, which is
// worth failing loudly for. The reconciler records a failed delete and continues, so refusing one
// entity never stops the pass.
func (l *doCloudLister) DeleteEntity(ctx context.Context, id string) error {
	class, upstreamID, ok := splitClassedID(id)
	if !ok {
		return fmt.Errorf("cannot delete %q: it names no credential class, and choosing one would "+
			"mean deleting from an id space it may not belong to", id)
	}

	switch class {
	case credentialTypeToken:
		status, err := l.client.DeleteToken(ctx, upstreamID)
		if err != nil && status != http.StatusNotFound {
			return err
		}
	case credentialTypeSpacesKey:
		status, err := l.client.DeleteSpacesKey(ctx, upstreamID)
		if err != nil && status != http.StatusNotFound {
			return err
		}
	default:
		return fmt.Errorf("cannot delete %q: unknown credential class %q", id, class)
	}
	return nil
}

func (l *doCloudLister) warn(msg string, args ...interface{}) {
	if l.logger != nil {
		l.logger.Warn(msg, args...)
	}
}

type leaseRegistry struct {
	storage logical.Storage
}

// OwnedIDs enumerates what this mount owns, from EVERY class's tracking prefix, in the same classed
// form the lister emits. A class left untranslated here would have all of its live credentials read
// as orphans on the next pass.
//
// Unlike a listing failure, a storage failure is fatal to the pass — pkg/reconciler's contract, and
// the right one: an incomplete owned-set nominates live credentials for deletion, whereas an
// incomplete upstream listing can only under-reclaim.
func (r *leaseRegistry) OwnedIDs(ctx context.Context) (map[string]struct{}, error) {
	owned := make(map[string]struct{})
	for class, prefix := range map[string]string{
		credentialTypeToken:     activeTrackingPrefix,
		credentialTypeSpacesKey: spacesTrackingPrefix,
	} {
		entries, err := r.storage.List(ctx, prefix)
		if err != nil {
			return nil, fmt.Errorf("listing %s tracking records: %w", class, err)
		}
		for _, entry := range entries {
			owned[classedID(class, entry)] = struct{}{}
		}
	}
	// No minter ids to merge: this cloud cannot mint a mint-capable successor
	// (rotation is rejected), so no minter credential ever carries the owner
	// prefix the lister selects on. If rotation is ever implemented here, this is
	// where its RotationParams key must be merged in — see A1.
	return owned, nil
}
