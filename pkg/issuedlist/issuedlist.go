// Package issuedlist is the shared `issued/` endpoint: what credentials this mount has handed out
// and are still outstanding.
//
// It exists because provenance had nothing to join against. Every plugin records who obtained each
// credential (see pkg/requester), but only `roles` and `minter-sets` had a ListOperation — so the
// records naming a leaked credential's owner were reachable only by reading the mount's raw storage.
// An incident asks "what is outstanding, and who holds it"; until this endpoint that question had no
// answer over the API.
//
// # Three properties this package exists to hold, none of them incidental
//
// **Fields are published by allowlist, not by copying the record.** A tracking record is internal
// state that a plugin may extend at any time; this response is a published API on a path an operator
// may grant broadly. Copying values through would mean a future field — a token, a password, a URL
// with a signature in it — became public the moment someone added it to a record, in a diff that
// mentions no endpoint at all. So Fields() is the whole vocabulary, an unknown key is dropped, and
// publishing one is a deliberate edit here.
//
// **It pages.** This is the one keyspace that grows with the FLEET rather than with the operator's
// configuration: one record per outstanding credential, at a design target of 10^5 roles. An
// unbounded list would be a response nobody can receive and a storage scan nobody can bound, so the
// endpoint takes `after`/`limit` and reports its own cursor. logical.Storage.ListPage is what makes
// that cheap — the page is a page at the storage layer, not a slice of a full listing.
//
// **It is an inventory, not a log.** A record is deleted when its credential is revoked, so this
// answers "what is live NOW". That is exactly the report's question and exactly not an audit trail;
// the help text says so, because the difference is invisible from the response.
package issuedlist

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/lineage"
	"github.com/nicois/openbao-cloud-creds/pkg/requester"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Path is the endpoint's location under the mount, deliberately NOT under roles/: an operator
// granting a policy over a role's own paths must not acquire the inventory of every credential that
// role has issued as a side effect. Enumeration is its own privilege.
const Path = "issued"

// Query and response field names.
const (
	// FieldAfter is the cursor. OPAQUE: it encodes which prefix the previous page ended in as
	// well as where, so a client passes back what it was given rather than parsing it.
	FieldAfter = "after"
	// FieldLimit caps one page.
	FieldLimit = "limit"
	// FieldNextAfter is the cursor to pass next, present only when there may be more.
	FieldNextAfter = "next_after"
	// FieldMore says whether another page may exist, so a client loops on a boolean rather than
	// inferring "a short page means the end" — which is wrong the moment a filter drops entries.
	FieldMore = "more"
)

// DefaultLimit is a page size chosen well below logical.DefaultScanViewPageLimit (2500): every key
// in a page costs one storage Get to render its metadata, so the cost of a page here is not the
// cost of a page of keys.
const DefaultLimit = 200

// MaxLimit bounds what a caller may ask for, because the caller is not the one paying for it.
const MaxLimit = 1000

// Fields is the published vocabulary of a listing entry: the keys of a tracking record this endpoint
// will report, and nothing else.
//
// It is a union across clouds rather than a per-cloud set, so one report reads every mount the same
// way and a cloud that lacks a field simply omits it. The provenance and lineage keys are the point
// of the endpoint; the rest is what makes an entry actionable — which role issued it, which minter,
// when, and for Azure which application holds the password.
func Fields() []string {
	return []string{
		"role", "minter", "minter_set", "created", "expires_at", "app_object_id",
		requester.FieldTokenAccessor, requester.FieldEntityID,
		lineage.FieldParentEntityID, lineage.FieldUnitID, lineage.FieldSource,
	}
}

// Endpoint is one plugin's inventory path. The plugin supplies only where its records live.
type Endpoint struct {
	// Prefixes are the storage prefixes the plugin writes tracking records under, in the order
	// they are paged. They are not uniform across clouds (active-tokens/, active-users/,
	// active-clients/, active-spaces-keys/), which is exactly why the API path is.
	//
	// A LIST, not a string, because credential-do writes two: one per credential type family,
	// deliberately separate because they count against separate upstream quotas. One path has to
	// cover both — an inventory that silently reports the tokens and omits the Spaces keys is the
	// short-answer failure this endpoint exists to avoid, and it would look like a working
	// listing.
	//
	// The ids in different prefixes come from different upstream namespaces (a DO token id and a
	// Spaces access key cannot collide), so entries are keyed by the bare upstream id — which is
	// what makes a listing joinable to what the cloud's own console shows.
	Prefixes []string
}

// FrameworkPath returns the framework path to register.
func (e Endpoint) FrameworkPath() *framework.Path {
	return &framework.Path{
		Pattern: Path + "/?$",
		Fields: map[string]*framework.FieldSchema{
			FieldAfter: {
				Type: framework.TypeString,
				Description: "Cursor from a previous page's " + FieldNextAfter +
					". Opaque: pass back what was returned. Omit to start at the beginning",
			},
			FieldLimit: {
				Type: framework.TypeInt,
				Description: fmt.Sprintf("Maximum entries in one page (default %d, maximum %d)",
					DefaultLimit, MaxLimit),
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: e.list},
		},
		HelpSynopsis: "List the credentials this mount has issued and not yet revoked",
		HelpDescription: "Returns one entry per OUTSTANDING credential: its upstream id as the " +
			"key, and as key_info the role that issued it, the minter that minted it, when, and " +
			"who obtained it (" + requester.FieldTokenAccessor + ", " + requester.FieldEntityID +
			"). No credential material is ever included.\n\n" +
			"This is an INVENTORY, not an audit log: an entry disappears when its credential is " +
			"revoked, so the response says what is live now and nothing about what was issued " +
			"before.\n\n" +
			"Pages with " + FieldAfter + "/" + FieldLimit + "; loop while " + FieldMore +
			" is true, passing " + FieldNextAfter + " back as " + FieldAfter + ".",
	}
}

// UnsupportedPath is the same path on a cloud that tracks no per-credential record, refusing with a
// reason and naming what the operator does have instead.
//
// A refusal rather than an empty listing, for the reason the containment note gives about
// zero-deletion successes: mid-incident, `keys: []` reads as "this mount has issued nothing", and a
// responder stops looking. The path still exists on every cloud so one runbook can name it.
func UnsupportedPath(reason, remedy string) *framework.Path {
	refuse := func(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
		return credenvelope.ErrorResponse(credenvelope.ErrUnsupported,
			"this cloud keeps no per-credential record to list: %s. %s", reason, remedy), nil
	}
	return &framework.Path{
		Pattern: Path + "/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: refuse},
		},
		HelpSynopsis: "Refused on this cloud: it keeps no per-credential record",
		HelpDescription: "This cloud's credentials are not tracked one-per-credential (" + reason +
			"), so there is nothing to enumerate. Instead: " + remedy,
	}
}

func (e Endpoint) list(ctx context.Context, req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	limit, errResp := pageLimit(d)
	if errResp != nil {
		return errResp, nil
	}
	cursor, errResp := parseCursor(d.Get(FieldAfter).(string), len(e.Prefixes))
	if errResp != nil {
		return errResp, nil
	}

	keys := make([]string, 0, limit)
	info := make(map[string]any, limit)
	last := cursor
	for index := cursor.prefix; index < len(e.Prefixes) && len(keys) < limit; index++ {
		prefix := e.Prefixes[index]
		after := ""
		// Only the prefix the previous page ended in resumes from a key; the ones after it
		// start at the beginning.
		if index == cursor.prefix {
			after = cursor.key
		}
		page, err := req.Storage.ListPage(ctx, prefix, after, limit-len(keys))
		if err != nil {
			return credenvelope.ErrorResponse(credenvelope.ErrInternal,
				"listing issued credentials failed"), nil
		}
		for _, key := range page {
			entry, err := req.Storage.Get(ctx, prefix+key)
			if err != nil {
				return credenvelope.ErrorResponse(credenvelope.ErrInternal,
					"reading the record for an issued credential failed"), nil
			}
			last = cursorAt{prefix: index, key: key}
			// A record that vanished between the page and the read was revoked concurrently.
			// It is absent from the inventory, which is the honest answer, not an error.
			if entry == nil {
				continue
			}
			keys = append(keys, key)
			info[key] = published(entry.Value)
		}
	}

	resp := logical.ListResponseWithInfo(keys, info)
	// A full page means there MAY be more: either this prefix has more keys or a later prefix
	// does. Stated as a boolean because a client must not have to know that rule — and "a short
	// page means the end" stops being true the moment a concurrently-revoked entry is dropped.
	if len(keys) == limit {
		resp.Data[FieldMore] = true
		resp.Data[FieldNextAfter] = last.String()
	} else {
		resp.Data[FieldMore] = false
	}
	return resp, nil
}

// cursorAt is a position across the endpoint's prefixes: which prefix, and how far into it.
type cursorAt struct {
	prefix int
	key    string
}

// cursorSeparator cannot appear in a storage key, so a cursor round-trips unambiguously.
const cursorSeparator = "|"

func (c cursorAt) String() string {
	return strconv.Itoa(c.prefix) + cursorSeparator + c.key
}

// parseCursor reads a cursor this endpoint issued. A malformed one is refused rather than silently
// restarting from the beginning: a client looping on a cursor it mangled would otherwise page
// forever over the same entries and never learn why.
func parseCursor(value string, prefixes int) (cursorAt, *logical.Response) {
	if value == "" {
		return cursorAt{}, nil
	}
	index, key, found := strings.Cut(value, cursorSeparator)
	if !found {
		return cursorAt{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s is not a cursor this endpoint issued; pass back the %s it returned",
			FieldAfter, FieldNextAfter)
	}
	at, err := strconv.Atoi(index)
	if err != nil || at < 0 || at >= prefixes {
		return cursorAt{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s names a keyspace this mount does not have; pass back the %s it returned",
			FieldAfter, FieldNextAfter)
	}
	return cursorAt{prefix: at, key: key}, nil
}

// published renders one record through the allowlist. An unreadable record still yields an entry:
// the credential IS outstanding, and dropping it would understate the inventory — the one direction
// that must never happen on this endpoint.
func published(value []byte) map[string]any {
	record := map[string]any{}
	if err := json.Unmarshal(value, &record); err != nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(record))
	for key, v := range record {
		if slices.Contains(Fields(), key) {
			out[key] = v
		}
	}
	return out
}

func pageLimit(d *framework.FieldData) (int, *logical.Response) {
	limit := d.Get(FieldLimit).(int)
	switch {
	case limit == 0:
		return DefaultLimit, nil
	case limit < 0:
		return 0, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s must be positive", FieldLimit)
	case limit > MaxLimit:
		return 0, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s may not exceed %d", FieldLimit, MaxLimit)
	}
	return limit, nil
}
