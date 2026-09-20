package plugintest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/issuedlist"
	"github.com/nicois/openbao-cloud-creds/pkg/requester"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// inventoryPath is the same on every cloud, deliberately, even though the storage prefix behind it is
// not: one runbook, and one report, can name it without knowing which cloud a mount serves.
const inventoryPath = issuedlist.Path + "/"

// RunInventorySuite covers the `issued/` endpoint: what this mount has handed out and not yet
// revoked.
//
// It exists because provenance had nothing to join against — every plugin records who obtained a
// credential, and no plugin could be ASKED. The two cases that carry the most weight are the
// material check (this endpoint is the one place a tracking record becomes public, so a field added
// to a record must not become public with it) and the revoked-credential case (an inventory that
// overstates what is live sends a responder after credentials that no longer exist, and one that
// understates it is worse).
func RunInventorySuite(t *testing.T, h Harness) {
	for _, c := range []struct {
		name string
		run  func(*testing.T, Harness)
	}{
		{"AnIssuedCredentialAppearsInTheInventory", invListsWhatWasIssued},
		{"TheInventoryNamesTheRoleAndTheCallerThatObtainedIt", invCarriesProvenance},
		{"NoCredentialMaterialAppearsInTheInventory", invPublishesNoSecrets},
		{"ARevokedCredentialLeavesTheInventory", invRevokedIsGone},
		{"TheInventoryPagesWithoutLosingAnEntry", invPages},
		{"AnOverLargePageIsRefused", invLimitIsBounded},
		{"TheInventoryIsRefusedWhereNothingIsTracked", invUnsupported},
	} {
		t.Run(c.name, func(t *testing.T) { c.run(t, h) })
	}
}

func invListsWhatWasIssued(t *testing.T, h Harness) {
	requireInventory(t, h)
	b, storage := newConfiguredBackend(t, h)
	issued := issueOrFail(t, b, storage, h.IssuePath)

	keys := inventoryKeys(t, b, storage)
	if len(keys) != 1 {
		t.Fatalf("one credential was issued and the inventory lists %d entries: %v", len(keys), keys)
	}
	// The key is the credential's UPSTREAM id, which is what makes the inventory joinable to what
	// an operator finds in the cloud's own console. An internal handle would be useless there.
	if id := credentialID(t, issued); keys[0] != id {
		t.Errorf("the inventory lists %q; the envelope reported credential id %q. The key must be "+
			"the upstream id, or nothing can be joined to what the cloud shows", keys[0], id)
	}
}

func invCarriesProvenance(t *testing.T, h Harness) {
	requireInventory(t, h)
	if h.SharesOneCredential || h.IssuesFromPreprovisionedSlots {
		t.Skipf("%s serves ONE credential to every reader, so its record was written by the "+
			"rotation that minted it and names no caller — the same fact the provenance category "+
			"declares", h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	if resp := issueAsCaller(t, b, storage, h.IssuePath, nil); resp == nil || resp.IsError() {
		t.Fatalf("issue failed: %v", resp)
	}

	entry := soleInventoryEntry(t, b, storage)
	if entry["role"] == nil {
		t.Errorf("the inventory entry names no role, so an operator cannot tell which privilege "+
			"boundary this credential came from: %v", entry)
	}
	for _, key := range []string{requester.FieldTokenAccessor, requester.FieldEntityID} {
		if entry[key] != nil {
			continue
		}
		t.Errorf("the inventory entry omits %q, so the endpoint cannot answer the question it "+
			"exists for — which unit holds this credential: %v", key, entry)
	}
}

// invPublishesNoSecrets: nothing the client was handed as credential material appears in a listing.
//
// Asserted against the ACTUAL credential just issued rather than against a list of known field
// names, so it holds for a cloud whose credential block gains a field, and for a plugin that starts
// writing something new into its tracking record. That is the direction the risk comes from: the
// record is internal state, the listing is a published API, and the gap between them is one careless
// line in an unrelated change.
func invPublishesNoSecrets(t *testing.T, h Harness) {
	requireInventory(t, h)
	b, storage := newConfiguredBackend(t, h)
	issued := issueOrFail(t, b, storage, h.IssuePath)

	listed, err := json.Marshal(inventoryResponse(t, b, storage, 0, "").Data)
	if err != nil {
		t.Fatalf("marshalling the inventory response failed: %v", err)
	}
	// The credential's own IDENTIFIER is published deliberately — it is the listing key, and it is
	// what makes an entry joinable to the cloud's console. So it is excluded by identity rather
	// than by pattern: everything else in the credential block is material.
	identifier := credentialID(t, issued)
	for key, value := range credentialBlock(t, issued) {
		secret, isString := value.(string)
		// Short values are region names and endpoints, not material, and would produce false
		// positives against a base64 id that happens to contain them.
		if !isString || len(secret) < minSecretLength || secret == identifier {
			continue
		}
		if strings.Contains(string(listed), secret) {
			t.Errorf("the inventory response contains the value of the credential's %q field. "+
				"This endpoint is the one place a tracking record becomes public; credential "+
				"material must never reach it", key)
		}
	}
}

// minSecretLength is the shortest credential value worth searching for. An access key id is public
// and an endpoint or region is neither secret nor long; what matters is the secret half.
const minSecretLength = 16

func invRevokedIsGone(t *testing.T, h Harness) {
	requireInventory(t, h)
	if h.SharesOneCredential {
		t.Skipf("%s serves one credential to every reader, so one lease ending must NOT remove it "+
			"from the inventory: it is still live for every other holder", h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	issued := issueOrFail(t, b, storage, h.IssuePath)
	if issued.Secret == nil {
		t.Fatal("issue returned no lease, so there is nothing to revoke")
	}
	if before := inventoryKeys(t, b, storage); len(before) != 1 {
		t.Fatalf("expected one entry before the revoke, got %v", before)
	}

	if r, err := revokeSecret(t, b, storage, h.IssuePath, issued.Secret); err != nil ||
		(r != nil && r.IsError()) {
		t.Fatalf("revoke failed: err=%v resp=%v", err, r)
	}

	if after := inventoryKeys(t, b, storage); len(after) != 0 {
		t.Errorf("a revoked credential is still listed as outstanding: %v. An inventory that "+
			"overstates what is live sends a responder after credentials that no longer exist",
			after)
	}
}

// invPages: the cursor walks every entry exactly once.
//
// Driven at limit=1 so the paging runs whatever the fleet size, and asserted as a SET so a page
// boundary cannot silently drop or repeat an entry — the two failures a cursor has.
func invPages(t *testing.T, h Harness) {
	requireInventory(t, h)
	b, storage := newConfiguredBackend(t, h)
	for range 3 {
		issueOrFail(t, b, storage, h.IssuePath)
	}
	// What one unpaged listing reports IS the answer paging has to reproduce. Asserted against
	// that rather than against the number of reads, because a cloud's fake may reuse one upstream
	// id across mints (AWS's does) and a shared credential is re-served rather than re-minted —
	// neither of which is a property of the cursor under test.
	want := len(inventoryKeys(t, b, storage))
	if want == 0 {
		t.Fatal("three reads left nothing in the inventory, so paging cannot be observed")
	}

	seen := map[string]int{}
	after := ""
	for page := 0; page <= want+1; page++ {
		resp := inventoryResponse(t, b, storage, 1, after)
		for _, key := range listedKeys(t, resp) {
			seen[key]++
		}
		more, _ := resp.Data[issuedlist.FieldMore].(bool)
		if !more {
			break
		}
		next, _ := resp.Data[issuedlist.FieldNextAfter].(string)
		if next == "" {
			t.Fatalf("the inventory reported %s=true with no %s, so a client cannot continue",
				issuedlist.FieldMore, issuedlist.FieldNextAfter)
		}
		after = next
	}

	if len(seen) != want {
		t.Errorf("paging at limit=1 saw %d distinct credentials, want %d: %v", len(seen), want, seen)
	}
	for key, count := range seen {
		if count != 1 {
			t.Errorf("paging returned %q %d times; a cursor must not repeat an entry", key, count)
		}
	}
}

func invLimitIsBounded(t *testing.T, h Harness) {
	requireInventory(t, h)
	b, storage := newConfiguredBackend(t, h)

	resp := listWith(t, b, storage, map[string]any{
		issuedlist.FieldLimit: issuedlist.MaxLimit + 1,
	})
	assertCode(t, resp, credenvelope.ErrConfigInvalid,
		"asking for a page larger than the endpoint's maximum")
}

// invUnsupported: a cloud that keeps no per-credential record REFUSES rather than answering with an
// empty list, because mid-incident `keys: []` reads as "this mount has issued nothing".
func invUnsupported(t *testing.T, h Harness) {
	if h.TrackingPrefix != "" {
		t.Skipf("%s tracks each credential it issues, so the inventory answers rather than refusing",
			h.Cloud)
	}
	b, storage := newConfiguredBackend(t, h)
	assertCode(t, listWith(t, b, storage, nil), credenvelope.ErrUnsupported,
		"listing issued credentials on a cloud that keeps no per-credential record")
}

// requireInventory skips the cases that need records to list, printing the reason.
func requireInventory(t *testing.T, h Harness) {
	t.Helper()
	if h.TrackingPrefix == "" {
		t.Skipf("%s keeps no per-credential record, so its inventory refuses; that refusal is "+
			"asserted by TheInventoryIsRefusedWhereNothingIsTracked", h.Cloud)
	}
}

func listWith(t *testing.T, b logical.Backend, storage logical.Storage,
	data map[string]any,
) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      inventoryPath,
		Storage:   storage,
		Data:      data,
	})
	if err != nil {
		t.Fatalf("listing %s returned a transport error rather than a response: %v",
			inventoryPath, err)
	}
	if resp == nil {
		t.Fatalf("listing %s returned no response at all", inventoryPath)
	}
	return resp
}

func inventoryResponse(t *testing.T, b logical.Backend, storage logical.Storage,
	limit int, after string,
) *logical.Response {
	t.Helper()
	data := map[string]any{}
	if limit > 0 {
		data[issuedlist.FieldLimit] = limit
	}
	if after != "" {
		data[issuedlist.FieldAfter] = after
	}
	resp := listWith(t, b, storage, data)
	if resp.IsError() {
		t.Fatalf("listing %s was refused: %v", inventoryPath, resp.Error())
	}
	return resp
}

// inventoryKeys is the whole inventory in one default-sized page, which is what every case that is
// not about paging wants.
func inventoryKeys(t *testing.T, b logical.Backend, storage logical.Storage) []string {
	t.Helper()
	return listedKeys(t, inventoryResponse(t, b, storage, 0, ""))
}

func listedKeys(t *testing.T, resp *logical.Response) []string {
	t.Helper()
	raw, present := resp.Data["keys"]
	if !present {
		return nil
	}
	keys, ok := raw.([]string)
	if !ok {
		t.Fatalf("the inventory's keys are %T, not []string", raw)
	}
	return keys
}

// soleInventoryEntry returns the key_info of the one listed credential.
func soleInventoryEntry(t *testing.T, b logical.Backend, storage logical.Storage,
) map[string]any {
	t.Helper()
	resp := inventoryResponse(t, b, storage, 0, "")
	keys := listedKeys(t, resp)
	if len(keys) != 1 {
		t.Fatalf("expected one listed credential, got %v", keys)
	}
	info, ok := resp.Data["key_info"].(map[string]any)
	if !ok {
		t.Fatalf("the inventory carries no key_info, so an entry says nothing but an id: %v",
			resp.Data)
	}
	entry, ok := info[keys[0]].(map[string]any)
	if !ok {
		t.Fatalf("key_info has no object for %q: %v", keys[0], info)
	}
	return entry
}

func issueOrFail(t *testing.T, b logical.Backend, storage logical.Storage,
	path string,
) *logical.Response {
	t.Helper()
	resp := issueAsCaller(t, b, storage, path, nil)
	if resp == nil || resp.IsError() {
		t.Fatalf("issuing from %s failed: %v", path, resp)
	}
	return resp
}

// credentialBlock returns the envelope's credential block: the material the client was handed.
func credentialBlock(t *testing.T, resp *logical.Response) map[string]any {
	t.Helper()
	block, ok := resp.Data["credential"].(map[string]any)
	if !ok {
		t.Fatalf("the issuance response carries no credential block: %v", resp.Data)
	}
	return block
}
