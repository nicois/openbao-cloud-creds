package credentialdo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/mintercapacity"
	"github.com/nicois/openbao-cloud-creds/pkg/requester"
	"github.com/nicois/openbao-cloud-creds/pkg/telemetry"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// sharedSpacesPrefix is where the ONE key a rotated role serves is recorded, keyed by role
// name: shared-spaces-keys/<role>.
//
// Separate from spacesTrackingPrefix, which stays exactly what it was — a record per live
// upstream key, for the capacity counter and the reconciler. A rotated key gets BOTH: this
// record says which key the role currently serves and when each one dies, while the tracking
// record says the key exists upstream and this mount owns it. Collapsing them would either
// hide a rotated key from the account's 200-key accounting or make the reconciler try to
// reclaim a role name.
const sharedSpacesPrefix = "shared-spaces-keys/"

// sharedSpacesSweepInterval is how often the shared-key lifecycle is advanced. Minutes rather
// than seconds because both deadlines it enforces are hours or days apart, and running late
// only ever makes a retiring key live a little longer — never a served one die early. Matches
// the health check's cadence, so a quiet mount has one wake-up rather than two.
const sharedSpacesSweepInterval = healthCheckInterval

// sharedSpacesLockStripes is how many mutexes guard the decide-then-mint, striped by role name.
//
// A power of two large enough that collisions are rare at the rotation rates this type is built
// for: one mount can hold hundreds of thousands of rotated roles, each rotating a few times a
// year, so simultaneous rotations of two roles are already unlikely and a collision merely
// serializes them.
const sharedSpacesLockStripes = 1024

// lockSharedRole takes the stripe guarding one role's shared-key record and returns its release.
//
// Correctness needs only that the SAME role serializes: two goroutines that both decide to
// rotate would mint twice, and the loser's key would be recorded nowhere while still existing
// upstream — an orphan, on a credential type with no upstream expiry.
func (b *backend) lockSharedRole(roleName string) func() {
	m := &b.sharedSpacesLocks[sharedSpacesStripe(roleName)]
	m.Lock()
	return m.Unlock
}

func sharedSpacesStripe(roleName string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(roleName))
	return h.Sum32() % sharedSpacesLockStripes
}

// sharedSpacesKey is the key a rotated role is currently serving.
//
// It holds the SECRET, which no other DO credential type does: DigitalOcean returns a Spaces
// secret key exactly once, at create, and this type's whole contract is to hand the same
// credential to a reader who asks again — so either the mount stores it or the contract is
// unimplementable. OCI already makes the same trade for its rotation slots.
type sharedSpacesKey struct {
	AccessKey string        `json:"access_key"`
	SecretKey string        `json:"secret_key"`
	Grants    []spacesGrant `json:"grants"`
	MintedAt  time.Time     `json:"minted_at"`
	// RotateAt is when this key is due to be replaced: minted_at + rotation_period, less a
	// jitter rolled ONCE here rather than recomputed per read. Recomputing it would make the
	// rotation date jump about under a client that is watching its TTL.
	RotateAt  time.Time `json:"rotate_at"`
	MinterSet string    `json:"minter_set"`
	MinterID  string    `json:"minter_id"`
}

// retiringSpacesKey is a key that has been replaced and is living out its overlap.
//
// DeleteAt is our own deadline, in our own storage, because DigitalOcean cannot be told that
// a key expires — there is no expiry field on a Spaces key and none can be added later
// (docs/cloud-credential-research.md). The sweeper is therefore the only thing that enforces
// it, and the record is what tells the sweeper which key and which minter to use.
type retiringSpacesKey struct {
	AccessKey string    `json:"access_key"`
	MinterSet string    `json:"minter_set"`
	MinterID  string    `json:"minter_id"`
	RetiredAt time.Time `json:"retired_at"`
	DeleteAt  time.Time `json:"delete_at"`
}

// sharedSpacesState is one role's whole shared-key world: what is served now, and what is
// still working but on its way out. One record per role so that a rotation — which changes
// both at once — is a single storage write, and a reader can never observe a state where the
// replacement exists and the retirement has not been recorded.
type sharedSpacesState struct {
	// Versioned because this record has lifecycle fields and is mutated by read-struct →
	// change → write-the-whole-struct-back. encoding/json drops what it does not know, so a
	// binary predating a field ERASES it: dropping `retiring` un-retires a rotated-out key and
	// cancels the sweep that was going to delete it. That is worse here than on a minter set,
	// because a Spaces key has no upstream expiry — nothing else ever reclaims the orphan.
	cloudconfig.Versioned
	Current  *sharedSpacesKey    `json:"current,omitempty"`
	Retiring []retiringSpacesKey `json:"retiring,omitempty"`
}

// empty reports whether the record no longer describes anything, in which case it is deleted
// rather than left as an empty husk — a role that is read again should mint as if new.
func (s *sharedSpacesState) empty() bool {
	return s == nil || (s.Current == nil && len(s.Retiring) == 0)
}

// forget removes an access key from the state wherever it appears. Used by the purge lever,
// which deletes keys upstream without consulting this record: without this, the state would
// keep pointing at a key that no longer exists and the role would serve a dead credential
// until its rotation came round.
func (s *sharedSpacesState) forget(accessKey string) bool {
	found := false
	if s.Current != nil && s.Current.AccessKey == accessKey {
		s.Current = nil
		found = true
	}
	if n := len(s.Retiring); n > 0 {
		s.Retiring = slices.DeleteFunc(s.Retiring, func(r retiringSpacesKey) bool {
			return r.AccessKey == accessKey
		})
		found = found || len(s.Retiring) != n
	}
	return found
}

// forgetSharedSpacesKey takes a purged key out of a role's record, so the role stops serving
// an access key DigitalOcean no longer has.
//
// It runs after the upstream delete rather than before, matching the sweeper's order: a record
// pruned first, followed by a failed delete, would leave a live key nothing knows about, and a
// Spaces key never expires on its own. Under the read path's lock, because that path decides
// whether to rotate from this record and then writes it back.
func (b *backend) forgetSharedSpacesKey(ctx context.Context, storage logical.Storage, roleName, accessKey string) error {
	release := b.lockSharedRole(roleName)
	defer release()

	state, err := loadSharedSpacesState(ctx, storage, roleName)
	if err != nil {
		return fmt.Errorf("loading the shared key record for role %q: %w", roleName, err)
	}
	if !state.forget(accessKey) {
		return nil
	}
	if err := saveSharedSpacesState(ctx, storage, roleName, state); err != nil {
		return fmt.Errorf("saving the shared key record for role %q: %w", roleName, err)
	}
	return nil
}

func sharedSpacesStateKey(roleName string) string {
	return sharedSpacesPrefix + roleName
}

// loadSharedSpacesState reads a role's shared-key record. A missing record is not an error:
// it is a role no client has read yet, and the read path mints on the spot.
func loadSharedSpacesState(ctx context.Context, storage logical.Storage, roleName string) (*sharedSpacesState, error) {
	entry, err := storage.Get(ctx, sharedSpacesStateKey(roleName))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return &sharedSpacesState{}, nil
	}
	var state sharedSpacesState
	if err := json.Unmarshal(entry.Value, &state); err != nil {
		return nil, err
	}
	// Refused rather than downgraded: rewriting an entry written by a newer binary would drop
	// the fields this one cannot see, and every one of them governs when a live upstream key is
	// deleted.
	if err := state.CheckSchema("shared Spaces key record for role " + roleName); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveSharedSpacesState(ctx context.Context, storage logical.Storage, roleName string, state *sharedSpacesState) error {
	if state.empty() {
		return storage.Delete(ctx, sharedSpacesStateKey(roleName))
	}
	state.Stamp()
	entry, err := logical.StorageEntryJSON(sharedSpacesStateKey(roleName), state)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// jitterFraction is where the rotation jitter's randomness comes from. Package-level so a
// test can pin it and get a deterministic rotation date without threading a source through
// the backend, matching pkg/recovery's backoff jitter.
var jitterFraction = rand.Float64

// rotationSeq discriminates two keys minted within the same nanosecond.
var rotationSeq atomic.Uint64

// rotationSuffix is the unique tail of a rotated key's upstream name. The request id serves
// that purpose everywhere else, and a rotation driven by the worker has no request — but the
// name must still be unique, because two keys of one role are live at once during an overlap
// and the name is what an operator reads in DigitalOcean's own panel.
func rotationSuffix() string {
	return "rot-" +
		strconv.FormatInt(time.Now().UnixNano(), 36) +
		strconv.FormatUint(rotationSeq.Add(1), 36)
}

// scheduleRotation returns when a key minted now is due to be replaced.
//
// The jitter is SUBTRACTED, never added. A role that says "rotate every 90 days" is a
// promise about the maximum age of a credential, so spreading rotations out must make them
// earlier — an added jitter would quietly serve a key for 99 days.
func scheduleRotation(role *doRole, now time.Time) time.Time {
	period := role.RotationPeriod
	if role.RotationJitter > 0 {
		period -= time.Duration(jitterFraction() * float64(role.RotationJitter))
	}
	return now.Add(period)
}

// dueAt is when this key must be replaced, given the role as it stands NOW.
//
// The stored schedule is re-clamped to minted_at + rotation_period on every read rather than
// rewritten when the role changes, so shortening a role's period takes effect on the key
// already minted. Doing it at role write instead would mean the write had to know whether a
// key existed, and an operator who shortens a period after a scare must not be told it
// applies to the next key only.
func (k *sharedSpacesKey) dueAt(role *doRole) time.Time {
	ceiling := k.MintedAt.Add(role.RotationPeriod)
	if k.RotateAt.After(ceiling) {
		return ceiling
	}
	return k.RotateAt
}

// deadline is the earliest moment this key could be deleted: it rotates at dueAt and is
// swept overlap_ttl later. Earliest rather than actual, because a late worker only ever
// makes the key live longer — so a TTL bounded by this can never outlive the credential.
func (k *sharedSpacesKey) deadline(role *doRole) time.Time {
	return k.dueAt(role).Add(role.OverlapTTL)
}

// servableUntil is the last moment this key may still be handed out once it is OVERDUE and the
// rotation that should have replaced it is failing.
//
// Two bounds, and it is the earlier of them:
//
//   - minted_at + rotation_period. `rotation_period` reads as a promise about the maximum age of
//     a credential — that is why the jitter is subtracted rather than added — so the retry window
//     has to fit INSIDE it. An operator who wrote 90 days must not get 91 because DigitalOcean
//     was unreachable on day 90, and the window's length is therefore the jitter they chose.
//   - deadline(). A lease may never outlive the credential it names (techrfc OBC-002), and
//     deadline() is the earliest moment this key could be deleted. Past it there is no positive
//     TTL left to hand out that keeps that true.
//
// Which one binds depends on whether the role's overlap_ttl exceeds its jitter, so both are
// computed rather than one assumed.
func (k *sharedSpacesKey) servableUntil(role *doRole) time.Time {
	ceiling := k.MintedAt.Add(role.RotationPeriod)
	if lease := k.deadline(role); lease.Before(ceiling) {
		return lease
	}
	return ceiling
}

// rotationCause says why the role's key must be replaced before it can be served. Its values are
// the strings the rotation log carries, so `string(cause)` is the log field and comparison is
// still typed — the read path has to distinguish the causes, because only ONE of them may fall
// back to serving the existing key.
type rotationCause string

const (
	// causeNone: the key can be served exactly as it is.
	causeNone rotationCause = ""
	// causeUnminted: there is nothing to serve, so nothing to fall back to.
	causeUnminted rotationCause = "no key has been minted for this role yet"
	// causeGrants: the key that exists carries privilege the role no longer authorises, so
	// serving it when the rotation fails would hand out exactly what the operator revoked.
	// This cause must NEVER fall back.
	causeGrants rotationCause = "the role's grants no longer match the key's"
	// causeAge: the key is merely old. It still works, DigitalOcean does not expire it, and a
	// reader held a valid copy of it a moment ago — so this is the one cause where a failed
	// rotation must not cost the client its credential.
	causeAge rotationCause = "the key reached its rotation age"
)

// rotationReason says why the role's key must be replaced before it can be served, or causeNone.
func rotationReason(state *sharedSpacesState, role *doRole, now time.Time) rotationCause {
	switch {
	case state == nil || state.Current == nil:
		return causeUnminted
	case !grantsMatch(state.Current.Grants, role.Grants):
		// The key already handed out carries the grants it was minted with, and DigitalOcean
		// cannot change them (PUT/PATCH alter the name and nothing else). So a narrowed role
		// and its live credential disagree about privilege until the key is replaced.
		return causeGrants
	case !state.Current.dueAt(role).After(now):
		return causeAge
	default:
		return causeNone
	}
}

// grantsMatch compares two grant lists as PRIVILEGE rather than as text, so re-writing a
// role with its grants in a different order does not rotate a perfectly good key.
func grantsMatch(a, b []spacesGrant) bool {
	left, right := renderGrants(a), renderGrants(b)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

// rotateSharedSpacesKey mints the role's next key, retires the one it replaces, and persists
// both in one write. It returns the state the caller should serve from.
//
// The order is create → track → save, and each failure undoes what came before it. Never
// hand out (or record) a credential this mount cannot later find: a Spaces key has no
// upstream expiry, so one that is untracked or unrecorded is permanent (audit F6).
// rotationRequest is one rotation's inputs: which role, the record it is replacing, when, and
// why. Bundled because the reason is only ever a log field and the four others always travel
// together — the read path, the worker and the operator endpoint all supply the same set.
type rotationRequest struct {
	role     *doRole
	roleName string
	state    *sharedSpacesState
	now      time.Time
	reason   rotationCause
}

func (b *backend) rotateSharedSpacesKey(ctx context.Context, storage logical.Storage,
	req rotationRequest,
) (*sharedSpacesState, *logical.Response) {
	role, roleName, state, now := req.role, req.roleName, req.state, req.now
	capacity, err := mintercapacity.Snapshot(ctx, storage, spacesTrackingPrefix, b.credentialLimitPerMinter())
	if err != nil {
		return nil, credenvelope.InternalResponse(b.Logger().Warn, "counting outstanding credentials", err)
	}
	b.warnOnNearingCapacity(capacity)

	// The ROLE is the affinity key, not the caller: a shared key has no one client to pin,
	// and keying on the role spreads roles across a set's minters while keeping one role's
	// successive keys on the same minter — which is what makes the capacity count per minter
	// stable instead of drifting at every rotation.
	sel, err := b.selectMinter(role.MinterSet, roleName, capacity, now)
	if err != nil {
		return nil, credenvelope.ResponseFor(err)
	}

	keyName, errResp := b.credentialName(ctx, storage, roleName, rotationSuffix())
	if errResp != nil {
		return nil, errResp
	}
	created, httpStatus, err := sel.client.CreateSpacesKey(ctx, keyName, role.Grants)
	if err != nil {
		b.recordMinterError(sel.setID, sel.minterID, httpStatus, err, now)
		return nil, b.issuanceError(httpStatus, err, telemetry.IssuanceAttempt{
			Cloud: cloudName, Role: roleName, MinterSet: sel.setID, MinterID: sel.minterID,
		})
	}
	b.recordMinterSuccess(sel.setID, sel.minterID, now)
	key := &created.Key

	undo := func(why string, err error) *logical.Response {
		if _, delErr := sel.client.DeleteSpacesKey(ctx, key.AccessKey); delErr != nil {
			b.Logger().Error("could not delete the Spaces key this mount had just minted; it is "+
				"left for the owner-tag reconciler, and it does not expire on its own",
				fieldCloud, cloudName, "access_key", key.AccessKey, "error", delErr)
		}
		return credenvelope.InternalResponse(b.Logger().Error, why, err)
	}

	// nil request, deliberately: a rotation is not somebody's read. The key it mints is served
	// to every reader of the role until the next rotation, so there is no one caller who
	// obtained it — and the worker that drives most rotations has no request in scope at all.
	if err := b.trackSpacesKey(ctx, storage, nil, spacesKeyRecord{
		roleName: roleName, minterID: sel.minterID, accessKey: key.AccessKey, createdAt: now,
	}); err != nil {
		return nil, undo("persisting the credential tracking record", err)
	}

	next := &sharedSpacesState{
		Current: &sharedSpacesKey{
			AccessKey: key.AccessKey,
			SecretKey: key.SecretKey,
			Grants:    role.Grants,
			MintedAt:  now,
			RotateAt:  scheduleRotation(role, now),
			MinterSet: sel.setID,
			MinterID:  sel.minterID,
		},
		Retiring: state.Retiring,
	}
	if state.Current != nil {
		// The replaced key keeps working for the overlap. This is the only reason two keys
		// exist at once, and it is unavoidable rather than chosen: DigitalOcean's grants are
		// immutable, so a rotation can only be create-new-then-delete-old.
		next.Retiring = append(next.Retiring, retiringSpacesKey{
			AccessKey: state.Current.AccessKey,
			MinterSet: state.Current.MinterSet,
			MinterID:  state.Current.MinterID,
			RetiredAt: now,
			DeleteAt:  now.Add(role.OverlapTTL),
		})
	}

	if err := saveSharedSpacesState(ctx, storage, roleName, next); err != nil {
		// Rolling the tracking record back too: leaving it would make the key invisible to
		// the reconciler (it looks owned and accounted for) while nothing served or swept it.
		if delErr := storage.Delete(ctx, spacesTrackingPrefix+key.AccessKey); delErr != nil {
			b.Logger().Error("could not remove the tracking record for a key whose state write failed",
				fieldCloud, cloudName, "access_key", key.AccessKey, "error", delErr)
		}
		return nil, undo("recording the role's shared credential", err)
	}

	b.logRotation(roleName, req.reason, state.Current, next.Current, role.OverlapTTL)
	return next, nil
}

// logRotation is an operator's only account of a rotation: metrics do not reach anybody in
// this deployment (A12), and this is the event that explains why a client saw a new
// credential and when the old one stops working.
func (b *backend) logRotation(roleName string, reason rotationCause, replaced, minted *sharedSpacesKey, overlap time.Duration) {
	fields := []any{
		fieldCloud, cloudName, fieldRole, roleName, "reason", reason,
		"access_key", minted.AccessKey, "next_rotation", minted.RotateAt.UTC().Format(time.RFC3339),
	}
	if replaced != nil {
		fields = append(fields,
			"replaced_access_key", replaced.AccessKey,
			"replaced_key_deleted_at", minted.MintedAt.Add(overlap).UTC().Format(time.RFC3339))
	}
	b.Logger().Info("rotated the shared Spaces key for a role", fields...)
}

// spacesKeyRecord is one entry of the tracking prefix, which is what the capacity counter,
// the orphan reconciler and the purge lever all read. Both Spaces types write the same shape
// under the same prefix, because to everything downstream of the mint they are one credential
// class against one account cap.
type spacesKeyRecord struct {
	roleName  string
	minterID  string
	accessKey string
	createdAt time.Time
}

// trackSpacesKey records an issued Spaces key, stamped with WHICH caller obtained it.
//
// req may be nil, and on one of the two callers it always is. A per-lease key was obtained by
// the request that read the lease, so that request's identity belongs on the record — but a
// rotated role's key is minted on a schedule and then served to every reader, so no single
// caller obtained it and there is nobody to name. requester.Stamp omits what it is not given,
// which is the honest record in that case rather than a missing one.
func (b *backend) trackSpacesKey(ctx context.Context, storage logical.Storage, req *logical.Request,
	rec spacesKeyRecord,
) error {
	entry, err := logical.StorageEntryJSON(spacesTrackingPrefix+rec.accessKey,
		requester.Stamp(map[string]any{
			fieldRole:         rec.roleName,
			trackFieldMinter:  rec.minterID,
			trackFieldCreated: rec.createdAt.UTC().Format(time.RFC3339),
		}, req))
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// sweepSharedSpacesKeys is one pass of the shared-key lifecycle, and the only thing that
// enforces either half of it.
//
// It deletes keys whose overlap has elapsed — which the orphan reconciler structurally
// cannot do, because a retiring key still has a tracking record and so is not an orphan —
// and it rotates roles that are overdue, because "rotate every 90 days" cannot depend on a
// client happening to read on the right day.
//
// The two halves are driven from different places on purpose. Deletions walk the STATE
// records, so a key belonging to a role that has since been deleted is still swept; rotations
// walk the ROLES, because rotating needs the period, the grants and the minter set.
func (b *backend) sweepSharedSpacesKeys(ctx context.Context, storage logical.Storage) error {
	now := time.Now()
	// No lock for the pass. A pass walks EVERY role, and holding one lock across it would block
	// every client's read for the length of a full scan plus each upstream mint the rotation half
	// performs. Both halves take the per-role stripe around their own role's work instead, which
	// is where the race with a reader actually is.
	return errors.Join(
		b.sweepRetiredSpacesKeys(ctx, storage, now),
		b.rotateOverdueSpacesRoles(ctx, storage, now),
	)
}

func (b *backend) sweepRetiredSpacesKeys(ctx context.Context, storage logical.Storage, now time.Time) error {
	roles, err := storage.List(ctx, sharedSpacesPrefix)
	if err != nil {
		return fmt.Errorf("listing shared Spaces key records: %w", err)
	}
	var errs []error
	for _, roleName := range roles {
		errs = append(errs, b.sweepOneRoleRetiredKeys(ctx, storage, roleName, now)...)
	}
	return errors.Join(errs...)
}

// sweepOneRoleRetiredKeys holds one role's stripe for the length of its own deletions, so a
// reader of a DIFFERENT role never waits on this, and a reader of THIS role cannot rotate
// underneath a half-applied prune.
func (b *backend) sweepOneRoleRetiredKeys(ctx context.Context, storage logical.Storage,
	roleName string, now time.Time,
) []error {
	release := b.lockSharedRole(roleName)
	defer release()

	var errs []error
	state, err := loadSharedSpacesState(ctx, storage, roleName)
	if err != nil {
		return []error{fmt.Errorf("loading the shared key record for role %q: %w", roleName, err)}
	}
	changed := false
	state.Retiring = slices.DeleteFunc(state.Retiring, func(r retiringSpacesKey) bool {
		if r.DeleteAt.After(now) {
			return false
		}
		if err := b.deleteRetiredSpacesKey(ctx, storage, roleName, r); err != nil {
			errs = append(errs, err)
			return false
		}
		changed = true
		return true
	})
	if changed {
		if err := saveSharedSpacesState(ctx, storage, roleName, state); err != nil {
			errs = append(errs, fmt.Errorf("saving the shared key record for role %q: %w", roleName, err))
		}
	}
	return errs
}

// deleteRetiredSpacesKey removes one key whose overlap has elapsed, upstream first and then
// its tracking record — never the other way round, since a record deleted first would leave
// a key nothing knows about, and this credential type never expires on its own.
func (b *backend) deleteRetiredSpacesKey(ctx context.Context, storage logical.Storage,
	roleName string, retiring retiringSpacesKey,
) error {
	client, err := b.getMinter(retiring.MinterSet, retiring.MinterID)
	if err != nil {
		// The minter that minted it may be gone (rotated out, or its set rewritten); any
		// healthy minter on the account can delete the key, because the key belongs to the
		// account rather than to a minter.
		client, err = b.anyHealthyMinterInSet(retiring.MinterSet)
		if err != nil {
			return fmt.Errorf("no minter in set %q can delete the retired Spaces key of role %q: %w",
				retiring.MinterSet, roleName, err)
		}
	}
	status, err := client.DeleteSpacesKey(ctx, retiring.AccessKey)
	// 404 is success: the key is gone, which is all the sweep wanted.
	if err != nil && status != http.StatusNotFound {
		b.recordMinterError(retiring.MinterSet, retiring.MinterID, status, err, time.Now())
		return fmt.Errorf("deleting the retired Spaces key of role %q (status %d): %w",
			roleName, status, err)
	}
	b.recordMinterSuccess(retiring.MinterSet, retiring.MinterID, time.Now())
	if err := storage.Delete(ctx, spacesTrackingPrefix+retiring.AccessKey); err != nil {
		return fmt.Errorf("removing the tracking record of a deleted Spaces key: %w", err)
	}
	b.Logger().Info("deleted a retired shared Spaces key at the end of its overlap",
		fieldCloud, cloudName, fieldRole, roleName, "access_key", retiring.AccessKey,
		"retired_at", retiring.RetiredAt.UTC().Format(time.RFC3339))
	return nil
}

func (b *backend) rotateOverdueSpacesRoles(ctx context.Context, storage logical.Storage, now time.Time) error {
	names, err := storage.List(ctx, "roles/")
	if err != nil {
		return fmt.Errorf("listing roles: %w", err)
	}
	var errs []error
	for _, roleName := range names {
		if strings.HasSuffix(roleName, "/") {
			continue
		}
		if err := b.rotateRoleIfOverdue(ctx, storage, roleName, now); err != nil {
			// One role's failure does not end the pass: the roles are independent, and a role
			// whose minter set is unreachable must not stop another rotating on time.
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// rotateRoleIfOverdue rotates one role's shared key if it is due, and otherwise does nothing.
//
// Every early return here is a role the worker must leave alone: one that does not serve a
// shared key, one an operator has disabled, one no client has ever read (minting there would
// spend the account's key allowance on a credential nobody has asked for, and the first read
// mints in any case), and one whose key is simply not due yet.
func (b *backend) rotateRoleIfOverdue(ctx context.Context, storage logical.Storage,
	roleName string, now time.Time,
) error {
	// This role's stripe only, and taken before the role is read so the decide-then-mint below
	// cannot interleave with a reader's. A reader of any OTHER role is unaffected.
	release := b.lockSharedRole(roleName)
	defer release()

	entry, err := storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return fmt.Errorf("loading role %q: %w", roleName, err)
	}
	if entry == nil {
		return nil
	}
	var role doRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return fmt.Errorf("parsing role %q: %w", roleName, err)
	}
	// A disabled role is the incident lever, so the worker must not mint on its behalf either —
	// but its retiring keys are still swept, because a disabled role's old keys should disappear
	// on schedule rather than outlive the incident.
	if !role.rotatesSharedKey() || role.Disabled {
		return nil
	}
	state, err := loadSharedSpacesState(ctx, storage, roleName)
	if err != nil {
		return fmt.Errorf("loading the shared key record for role %q: %w", roleName, err)
	}
	if state.Current == nil {
		return nil
	}
	reason := rotationReason(state, &role, now)
	if reason == causeNone {
		return nil
	}
	if _, errResp := b.rotateSharedSpacesKey(ctx, storage, rotationRequest{
		role: &role, roleName: roleName, state: state, now: now, reason: reason,
	}); errResp != nil {
		return fmt.Errorf("rotating the shared Spaces key of role %q: %w", roleName, errResp.Error())
	}
	return nil
}
