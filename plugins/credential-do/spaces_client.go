package credentialdo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

// Spaces access keys are the credential type this plugin can actually issue against
// real DigitalOcean. Unlike the /v2/tokens endpoints in do_client.go — which are absent
// from DO's public OpenAPI spec AND refused at the edge gateway for every PAT (KI-009) —
// `/v2/spaces/keys` IS in the public spec, with full CRUD, and answers a plain bearer
// PAT holding the `spaces_key:*` scopes. DO's own product docs claim the opposite
// ("cannot currently be created, edited, or deleted using the DigitalOcean API or CLI")
// and are wrong: the endpoint is in production use with bearer-PAT auth. See
// docs/do-spaces-keys-handover.md.
//
// Two properties of this API shape every caller below:
//
//   - The SECRET IS RETURNED ONLY ON CREATE. There is no read-back, so the mint response
//     is the single opportunity to capture it; a lost secret means a dead credential that
//     still counts against the account's quota.
//   - There is NO UPSTREAM EXPIRY. A Spaces key lives until something deletes it, so the
//     lease TTL is honoured by hard revoke plus the owner-tag reconciler and by nothing
//     else — exactly like Exoscale, Vultr and Akamai (docs/ttl-semantics.md).

// spacesGrant is one entry of a Spaces key's per-bucket grant list. This is why the
// credential's scope_kind is `grants` rather than `scopes`: the privilege is a pairing of
// a named bucket with a permission, not a flat list of account-wide verbs.
//
// An empty Bucket is how DO expresses an account-wide grant, so it is not treated as a
// missing field on the wire — see the `*` rendering in credenvelope.ScopeKindGrants.
type spacesGrant struct {
	Bucket     string `json:"bucket"`
	Permission string `json:"permission"`
}

// The permission values DO accepts on a grant. Its spec types the field as a plain string
// rather than an enum, naming read, readwrite, fullaccess and "" in the description; the
// three below are the ones this plugin offers, and one of them is dangerous in
// combination — see checkGrantPrivilege in spaces_grants.go for why fullaccess cannot be
// mixed with scoped grants.
const (
	permissionRead       = "read"
	permissionReadWrite  = "readwrite"
	permissionFullAccess = "fullaccess"
)

type createSpacesKeyRequest struct {
	Name   string        `json:"name"`
	Grants []spacesGrant `json:"grants"`
}

// spacesKeyInfo is one Spaces key as DO reports it. SecretKey is populated only by the
// create response; a listing leaves it empty, and nothing may depend on recovering it.
type spacesKeyInfo struct {
	Name      string        `json:"name"`
	AccessKey string        `json:"access_key"`
	SecretKey string        `json:"secret_key"`
	Grants    []spacesGrant `json:"grants"`
	CreatedAt string        `json:"created_at"`
}

type spacesKeyResponse struct {
	Key spacesKeyInfo `json:"key"`
}

type listSpacesKeysResponse struct {
	Keys []spacesKeyInfo `json:"keys"`
	// Links carries DigitalOcean's pagination. Only the PRESENCE of a next page is read
	// from it, never the URL — see ListSpacesKeys.
	Links struct {
		Pages struct {
			Next string `json:"next"`
		} `json:"pages"`
	} `json:"links"`
}

const (
	// spacesListPageSize is the largest page DigitalOcean's spec allows (per_page maxes at
	// 200, defaulting to 20). Asking for the maximum keeps a whole account inside one
	// request today, since Spaces keys cap at 200 — but the traversal below does not rely
	// on that, because DO support raises the cap on request.
	spacesListPageSize = 200
	// spacesListMaxPages bounds the traversal. Reaching it means DO claims more than
	// 10000 keys on one account, which is not a listing worth continuing.
	spacesListMaxPages = 50
)

// CreateSpacesKey mints a Spaces access key. The returned status is reported alongside
// the error deliberately: a 403 here means the minter PAT lacks `spaces_key:create_
// credentials` (a capability fault, which must not indict the credential) and a 429 means
// the account's quota, so the caller classifies on the status rather than on the message.
func (c *doClient) CreateSpacesKey(ctx context.Context, name string, grants []spacesGrant) (*spacesKeyResponse, int, error) {
	if grants == nil {
		// An explicit empty list, not `null`: DO's spec types grants as an array, and a
		// null there is a different request from an empty one.
		grants = []spacesGrant{}
	}
	body, err := json.Marshal(createSpacesKeyRequest{Name: name, Grants: grants})
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v2/spaces/keys", bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("DO API create spaces key returned %d: %s",
			resp.StatusCode, string(bodyBytes))
	}

	var result spacesKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}
	return &result, resp.StatusCode, nil
}

// ListSpacesKeys enumerates the account's Spaces keys for the owner-tag reconciler. It
// reports the name (the owner tag), the access key (what a delete needs) and created_at
// (what the confirmation hold needs); it never yields a secret.
//
// It walks EVERY page. DigitalOcean paginates this endpoint at 20 by default, and a
// truncated listing is uniquely damaging for this credential type: a Spaces key has no
// upstream expiry, so the owner-tag reconciler is the only thing that ever reclaims a
// leaked one (docs/ttl-semantics.md), and an orphan it never sees lives until somebody
// deletes it by hand while still consuming the account's cap.
//
// A partial result is never returned: the traversal either completes or errors. Truncating
// quietly is the failure mode being avoided, and a listing error is the safe direction —
// the reconciler deletes nothing on a failed pass.
//
// The next page is requested by NUMBER, not by following `links.pages.next`, even though
// DO supplies a ready-made URL there. That URL comes from the response, and this request
// carries the minter's bearer token: following an upstream-chosen host would let a
// compromised or misconfigured API redirect the credential elsewhere. The link's presence
// is read as "more pages exist"; the address is this client's own.
func (c *doClient) ListSpacesKeys(ctx context.Context) ([]spacesKeyInfo, error) {
	var all []spacesKeyInfo
	for page := 1; ; page++ {
		var result listSpacesKeysResponse
		path := fmt.Sprintf("/v2/spaces/keys?per_page=%d&page=%d", spacesListPageSize, page)
		if err := c.listJSON(ctx, path, "list spaces keys", &result); err != nil {
			return nil, err
		}
		all = append(all, result.Keys...)

		if result.Links.Pages.Next == "" {
			return all, nil
		}
		if page >= spacesListMaxPages {
			return nil, fmt.Errorf("DO API list spaces keys still reported a next page after %d "+
				"pages of %d; refusing to return a partial listing, because the reconciler would "+
				"read the missing keys as absent upstream", page, spacesListPageSize)
		}
	}
}

// DeleteSpacesKey revokes a key by its ACCESS KEY, which is the only identifier DO gives
// it — there is no separate id, so the access key is what a lease has to remember. The
// status is returned even on failure so a caller can treat 404 as already-revoked instead
// of retrying a revoke forever (KI-002).
func (c *doClient) DeleteSpacesKey(ctx context.Context, accessKey string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.baseURL+"/v2/spaces/keys/"+cloudconfig.PathSegment(accessKey), http.NoBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusNoContent {
		return resp.StatusCode, fmt.Errorf("DO API delete spaces key returned %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
