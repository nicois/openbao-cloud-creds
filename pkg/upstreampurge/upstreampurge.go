// Package upstreampurge deletes the credentials one role has already issued, from the
// mount's own tracking records.
//
// # The problem
//
// A credential is believed to have leaked. Disabling the role stops the next one being
// issued and does nothing about the ones already out: every credential in a client's hands
// keeps working until its own expiry, and on the four clouds whose credentials have no
// upstream expiry at all — DigitalOcean, Exoscale, Vultr, Akamai — that means until a lease
// revoke reaches the cloud. Deleting the role is worse than useless, because it reads like
// containment while leaving the leases renewable.
//
// An operator can revoke leases one at a time, but only for the leases they can enumerate,
// and a lease id is not what an incident hands you. What they have is a role name.
//
// # What this does about it
//
// Every plugin that hard-revokes already writes a tracking record per issued credential,
// keyed by the upstream id and naming the role. That set of records is the answer to "what
// has this role issued": it is what the reconciler and the capacity counter already read,
// and it is addressable by role name. This package walks it and deletes the credentials
// upstream, deleting each record only once its credential is gone.
//
// # Why it is armed rather than done
//
// A role may have thousands of live credentials, and deleting them is one API call each
// against the same quota the mount is issuing from. Doing that inside one request would
// either time out or spend the whole account's quota and take issuance down — turning a
// leak of some credentials into an outage for all of them.
//
// So a purge is a durable INTENT plus bounded passes. The write arms the intent, runs one
// paced pass inline so the operator sees it working, and returns progress; a background
// worker on the active node continues in equally bounded passes until nothing in scope is
// left. The operator's one call is what survives a restart and a failover, which is what
// makes it safe to answer them before the work is finished.
//
// # Why the cutoff
//
// The intent covers what existed when it was armed, and nothing issued after. Without that
// bound a purge on a mount that keeps issuing never terminates, and — worse — it deletes the
// credentials issued DURING the incident response, including the ones the responder just
// minted to do the response with. The role is deliberately left issuing: closing the tap is
// the other lever, and an operator has to be able to use one without the other.
package upstreampurge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// The keys a tracking record carries that this package reads. Every plugin writes all
// three, inline as a map rather than through a shared struct; a plugin that spelled `role`
// differently would purge nothing and report success, so these are single-sourced here and
// asserted per plugin.
const (
	FieldRole    = "role"
	FieldMinter  = "minter"
	FieldCreated = "created"
)

// Prefix is where a role's purge intent is stored, one entry per role.
const Prefix = "purge/"

// ErrThrottled is what a Deleter returns when the cloud refused the call for rate limiting.
// It ends the pass without counting a failure: the credential is still there and still
// deletable, and continuing would spend the rest of the budget on calls the cloud has just
// said no to — while the callers issuing from the same quota are waiting on it.
var ErrThrottled = errors.New("upstream is rate-limiting us")

// Outcome converts what a cloud's delete client answered — every one of them returns an HTTP
// status alongside the error — into what a Deleter must return.
//
// The three cases are each silent when got wrong, which is why they are here once rather than
// per plugin. A 404 is SUCCESS: the credential is gone, which is the outcome asked for, and
// reading it as a failure means retrying forever against nothing while the tracking record
// survives to be retried again. A 429 is ErrThrottled, not a failure: the credential is still
// there and the pass should pause, and counting it as a failure would spend the rest of the
// budget the pacing exists to protect. Anything else is the cloud's error, unchanged.
func Outcome(status int, err error) error {
	if err == nil || status == http.StatusNotFound {
		return nil
	}
	if status == http.StatusTooManyRequests {
		return ErrThrottled
	}
	return err
}

// Record is one tracked credential: the upstream id it is addressed by, the fields every
// plugin records, and the rest of the record for the clouds where the id alone is not
// enough to delete it (Azure needs the application that holds the password).
type Record struct {
	ID      string
	Role    string
	Minter  string
	Created time.Time
	Fields  map[string]any
}

// Deleter deletes one credential upstream. A credential the cloud says is already gone is a
// success — that is the outcome asked for. ErrThrottled ends the pass; any other error
// counts as a failure and leaves the tracking record for a later pass.
type Deleter func(context.Context, Record) error

// Config is one pass: which records are in scope, and how many of them it may delete.
type Config struct {
	// Prefix is the storage prefix the plugin writes tracking records under. Not uniform
	// across clouds, and a plugin serving two credential types has one per type.
	Prefix string
	// Role names the role whose credentials are in scope. Another role's are not: a role is
	// the privilege boundary, so it is also the containment boundary.
	Role string
	// Cutoff excludes anything issued after the purge was armed.
	Cutoff time.Time
	// MaxDeletes bounds the upstream calls this pass will make.
	MaxDeletes int
}

// Result is what one pass did. Failed is this pass's failures, not a running total: it
// answers "is it still going wrong", which a total stops answering after the first retry.
type Result struct {
	Tracked   int
	Deleted   int
	Failed    int
	Remaining int
	Throttled bool
}

// DefaultMaxDeletes bounds a pass that names no budget of its own.
//
// Fifty upstream deletes: enough that a purge of an ordinary role finishes in one pass, few
// enough that it cannot exhaust an account's quota or hold a request open long enough for
// core to give up on it. A pass with no budget must not mean an unbounded one — that is the
// failure mode this whole design exists to avoid, and an omitted number is the likeliest way
// to ask for it by accident.
const DefaultMaxDeletes = 50

// Complete reports whether a pass left nothing in scope.
func (r Result) Complete() bool { return r.Remaining == 0 }

// Intent is the durable record of an operator's decision to purge a role. It outlives the
// request that made it, which is the whole point.
type Intent struct {
	Role     string    `json:"role"`
	ArmedAt  time.Time `json:"armed_at"`
	Cutoff   time.Time `json:"cutoff"`
	Tracked  int       `json:"tracked"`
	Deleted  int       `json:"deleted"`
	Failed   int       `json:"failed"`
	Complete bool      `json:"complete"`
}

// Scan returns the tracking records in scope for a role: the ones that name it, created no
// later than the cutoff.
//
// A record whose timestamp is missing or unreadable is IN scope. It was written by an
// earlier issuance either way, and of the two ways to be wrong here, excluding it leaves a
// live credential the operator has been told was destroyed.
func Scan(ctx context.Context, storage logical.Storage, prefix, role string, cutoff time.Time) ([]Record, error) {
	ids, err := storage.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", prefix, err)
	}
	// Sorted so successive bounded passes work through the same order rather than
	// re-reading whichever records the backend happened to return first.
	sort.Strings(ids)

	records := make([]Record, 0, len(ids))
	for _, id := range ids {
		entry, err := storage.Get(ctx, prefix+id)
		if err != nil {
			return nil, fmt.Errorf("reading %s%s: %w", prefix, id, err)
		}
		if entry == nil {
			continue
		}
		var fields map[string]any
		if err := json.Unmarshal(entry.Value, &fields); err != nil {
			// Unreadable, so there is no role to match and no way to know it is this one's.
			// Deleting it would be deleting a credential belonging to who-knows-which role.
			continue
		}
		if recordRole, _ := fields[FieldRole].(string); recordRole != role {
			continue
		}
		created := recordCreated(fields)
		if !created.IsZero() && created.After(cutoff) {
			continue
		}
		minter, _ := fields[FieldMinter].(string)
		records = append(records, Record{
			ID:      id,
			Role:    role,
			Minter:  minter,
			Created: created,
			Fields:  fields,
		})
	}
	return records, nil
}

// recordCreated reads a record's creation time, returning the zero time when it is absent
// or unparseable — which Scan reads as "in scope".
func recordCreated(fields map[string]any) time.Time {
	raw, _ := fields[FieldCreated].(string)
	if raw == "" {
		return time.Time{}
	}
	created, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return created
}

// Pass deletes up to cfg.MaxDeletes of a role's in-scope credentials and reports what is
// left. A delete that fails is reported, not returned: the other credentials in scope are
// still worth deleting, and the one that failed is still worth another pass.
func Pass(ctx context.Context, storage logical.Storage, cfg Config, del Deleter) (Result, error) {
	records, err := Scan(ctx, storage, cfg.Prefix, cfg.Role, cfg.Cutoff)
	if err != nil {
		return Result{}, err
	}
	budget := cfg.MaxDeletes
	if budget <= 0 {
		budget = DefaultMaxDeletes
	}
	result := Result{Tracked: len(records)}
	for _, record := range records {
		if result.Deleted+result.Failed >= budget {
			break
		}
		err := del(ctx, record)
		if errors.Is(err, ErrThrottled) {
			result.Throttled = true
			break
		}
		if err != nil {
			result.Failed++
			continue
		}
		// Only now: the record holds the upstream id, which is the one thing that makes the
		// credential reachable, so losing it before the credential is gone strands it.
		if err := storage.Delete(ctx, cfg.Prefix+record.ID); err != nil {
			return result, fmt.Errorf("deleting %s%s after its credential was deleted upstream: %w",
				cfg.Prefix, record.ID, err)
		}
		result.Deleted++
	}
	result.Remaining = result.Tracked - result.Deleted
	return result, nil
}

// SaveIntent stores a role's purge intent.
func SaveIntent(ctx context.Context, storage logical.Storage, intent *Intent) error {
	entry, err := logical.StorageEntryJSON(Prefix+intent.Role, intent)
	if err != nil {
		return fmt.Errorf("encoding the purge intent for %s: %w", intent.Role, err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("storing the purge intent for %s: %w", intent.Role, err)
	}
	return nil
}

// LoadIntent reads a role's purge intent, returning nil when the role has never been
// purged. That is an ordinary answer, not an error: most roles have no intent.
func LoadIntent(ctx context.Context, storage logical.Storage, role string) (*Intent, error) {
	entry, err := storage.Get(ctx, Prefix+role)
	if err != nil {
		return nil, fmt.Errorf("reading the purge intent for %s: %w", role, err)
	}
	if entry == nil {
		return nil, nil
	}
	var intent Intent
	if err := json.Unmarshal(entry.Value, &intent); err != nil {
		return nil, fmt.Errorf("parsing the purge intent for %s: %w", role, err)
	}
	return &intent, nil
}

// ArmedRoles lists every role with a stored intent. This is how a background worker finds
// the work an operator asked for before the restart it is starting from.
func ArmedRoles(ctx context.Context, storage logical.Storage) ([]string, error) {
	roles, err := storage.List(ctx, Prefix)
	if err != nil {
		return nil, fmt.Errorf("listing purge intents: %w", err)
	}
	return roles, nil
}

// The progress report's keys. One schema for every cloud and for both operations, so a
// runbook and any automation watching for completion are written once.
const (
	keyRole      = "role"
	keyArmed     = "armed"
	keyCutoff    = "cutoff"
	keyTracked   = "tracked"
	keyDeleted   = "deleted"
	keyRemaining = "remaining"
	keyFailed    = "failed"
	keyComplete  = "complete"
)

// KeyMode is the one key a write response carries beyond the progress report: the mode the
// call actually ran in. A caller that asked for a dry run and got a purge — or the reverse —
// must be able to tell from the response alone.
const KeyMode = "mode"

// Report renders an intent's progress. remaining is passed in rather than stored because it
// is derived: a completed purge whose role has since issued more credentials still has
// nothing remaining IN SCOPE, and that is the number an operator is asking about.
func (i *Intent) Report(remaining int) map[string]any {
	return map[string]any{
		keyRole:  i.Role,
		keyArmed: !i.Complete,
		// Formatted rather than left as a time, because this crosses the plugin RPC boundary
		// and an operator reading it wants to know which credentials the purge covers.
		keyCutoff:    i.Cutoff.UTC().Format(time.RFC3339),
		keyTracked:   i.Tracked,
		keyDeleted:   i.Deleted,
		keyRemaining: remaining,
		keyFailed:    i.Failed,
		keyComplete:  i.Complete,
	}
}

// NoIntentReport is the progress of a role nobody has purged. It reports the same keys as
// every other answer, so a reader never has to handle an absence specially — and an empty
// cutoff is what says no purge covers anything.
func NoIntentReport(role string) map[string]any {
	return map[string]any{
		keyRole:      role,
		keyArmed:     false,
		keyCutoff:    "",
		keyTracked:   0,
		keyDeleted:   0,
		keyRemaining: 0,
		keyFailed:    0,
		keyComplete:  false,
	}
}

// DryRunReport is what a dry run answers: how big the incident is, having changed nothing.
// It arms nothing, so `armed` is false — otherwise the background worker would finish a
// purge the operator was only asking about.
func DryRunReport(role string, cutoff time.Time, tracked int) map[string]any {
	return map[string]any{
		keyRole:      role,
		keyArmed:     false,
		keyCutoff:    cutoff.UTC().Format(time.RFC3339),
		keyTracked:   tracked,
		keyDeleted:   0,
		keyRemaining: tracked,
		keyFailed:    0,
		keyComplete:  false,
	}
}
