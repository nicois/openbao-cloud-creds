package issuedlist

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const testPrefix = "active-tokens/"

// TestAnUnpublishedFieldIsDropped is why the allowlist exists rather than the record being copied
// through. A tracking record is internal state any plugin may extend; this response is a published
// API. Without the filter, a field added to a record — a token, a password, a pre-signed URL —
// becomes public in a diff that mentions no endpoint at all.
func TestAnUnpublishedFieldIsDropped(t *testing.T) {
	storage := seed(t, map[string]map[string]any{
		"AKIAEXAMPLE": {
			"role":              "executor",
			"minter":            "aws_v1",
			"secret_access_key": "wJalrXUtnFEMI-must-never-be-published",
			"some_future_field": "added by a later binary",
		},
	})

	entry := soleEntry(t, list(t, storage, nil))
	if _, present := entry["secret_access_key"]; present {
		t.Error("a record field outside Fields() reached the response")
	}
	if _, present := entry["some_future_field"]; present {
		t.Error("an unknown record field reached the response; publishing must be opt-in")
	}
	if entry["role"] != "executor" || entry["minter"] != "aws_v1" {
		t.Errorf("the allowlisted fields did not survive: %v", entry)
	}
}

// TestAnUnreadableRecordStillCountsAsOutstanding pins the direction the failure must take. The
// credential IS live; dropping its entry because its metadata will not parse would understate the
// inventory, and understating is the one error this endpoint must never make.
func TestAnUnreadableRecordStillCountsAsOutstanding(t *testing.T) {
	storage := &logical.InmemStorage{}
	if err := storage.Put(t.Context(), &logical.StorageEntry{
		Key: testPrefix + "AKIABROKEN", Value: []byte("{not json"),
	}); err != nil {
		t.Fatalf("seeding failed: %v", err)
	}

	resp := list(t, storage, nil)
	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "AKIABROKEN" {
		t.Fatalf("an outstanding credential with an unparseable record vanished from the "+
			"inventory: %v", resp.Data)
	}
}

// TestPagingVisitsEveryEntryExactlyOnce covers a cursor's two failure modes — skipping an entry at a
// page boundary and repeating one — at the page size that makes boundaries most frequent.
func TestPagingVisitsEveryEntryExactlyOnce(t *testing.T) {
	seeded := map[string]map[string]any{}
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		seeded[id] = map[string]any{"role": "executor"}
	}
	storage := seed(t, seeded)

	seen := map[string]int{}
	after := ""
	for range len(seeded) + 2 {
		resp := list(t, storage, map[string]any{FieldLimit: 2, FieldAfter: after})
		keys, _ := resp.Data["keys"].([]string)
		for _, key := range keys {
			seen[key]++
		}
		if more, _ := resp.Data[FieldMore].(bool); !more {
			break
		}
		after, _ = resp.Data[FieldNextAfter].(string)
	}

	if len(seen) != len(seeded) {
		t.Errorf("paging saw %d of %d entries: %v", len(seen), len(seeded), seen)
	}
	for key, count := range seen {
		if count != 1 {
			t.Errorf("%q was returned %d times", key, count)
		}
	}
}

// TestAFullPageReportsMore is the rule a client must not have to know: "a short page means the end"
// is wrong the moment an entry is dropped mid-page, so the endpoint states it.
func TestAFullPageReportsMore(t *testing.T) {
	storage := seed(t, map[string]map[string]any{
		"a": {"role": "r"}, "b": {"role": "r"},
	})

	full := list(t, storage, map[string]any{FieldLimit: 2})
	if more, _ := full.Data[FieldMore].(bool); !more {
		t.Error("a page filled to the limit reported more=false, so a client stops early")
	}
	// The cursor is opaque by contract, so what is asserted is that it exists and RESUMES —
	// not its spelling, which a client must never parse.
	next, _ := full.Data[FieldNextAfter].(string)
	if next == "" {
		t.Fatalf("a full page reported no %s, so a client cannot continue", FieldNextAfter)
	}
	resumed := list(t, storage, map[string]any{FieldAfter: next})
	if keys, _ := resumed.Data["keys"].([]string); len(keys) != 0 {
		t.Errorf("resuming from the cursor after the last entry returned %v, want nothing", keys)
	}

	short := list(t, storage, map[string]any{FieldLimit: 5})
	if more, _ := short.Data[FieldMore].(bool); more {
		t.Error("a page under the limit reported more=true, so a client loops forever")
	}
}

func TestAnUnusablePageSizeIsRefused(t *testing.T) {
	storage := seed(t, map[string]map[string]any{"a": {"role": "r"}})

	for name, limit := range map[string]int{
		"negative":     -1,
		"over maximum": MaxLimit + 1,
	} {
		t.Run(name, func(t *testing.T) {
			resp := list(t, storage, map[string]any{FieldLimit: limit})
			if !resp.IsError() {
				t.Fatalf("limit=%d was accepted", limit)
			}
			code, known := credenvelope.CodeOf(resp.Error().Error())
			if !known || code != credenvelope.ErrConfigInvalid {
				t.Errorf("limit=%d refused with %q, want %s", limit, resp.Error(),
					credenvelope.ErrConfigInvalid)
			}
		})
	}
}

// TestRefusalCarriesTheCloudsOwnRemedy: a cloud with nothing to enumerate must refuse rather than
// answer `keys: []`, and the refusal has to name what the operator DOES have — an empty success
// reads mid-incident as "this mount has issued nothing".
func TestRefusalCarriesTheCloudsOwnRemedy(t *testing.T) {
	path := UnsupportedPath("a credential is a shared slot", "rotate the slot")
	resp, err := path.Operations[logical.ListOperation].Handler()(t.Context(),
		&logical.Request{Operation: logical.ListOperation}, nil)
	if err != nil {
		t.Fatalf("the refusal returned a transport error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("a cloud that tracks nothing answered instead of refusing")
	}
	code, known := credenvelope.CodeOf(resp.Error().Error())
	if !known || code != credenvelope.ErrUnsupported {
		t.Errorf("refused with %q, want %s", resp.Error(), credenvelope.ErrUnsupported)
	}
	for _, want := range []string{"a credential is a shared slot", "rotate the slot"} {
		if !strings.Contains(resp.Error().Error(), want) {
			t.Errorf("the refusal omits %q, so an operator is told no and nothing else", want)
		}
	}
}

func seed(t *testing.T, records map[string]map[string]any) logical.Storage {
	t.Helper()
	storage := &logical.InmemStorage{}
	for id, record := range records {
		entry, err := logical.StorageEntryJSON(testPrefix+id, record)
		if err != nil {
			t.Fatalf("encoding %s failed: %v", id, err)
		}
		if err := storage.Put(t.Context(), entry); err != nil {
			t.Fatalf("seeding %s failed: %v", id, err)
		}
	}
	return storage
}

func list(t *testing.T, storage logical.Storage, data map[string]any) *logical.Response {
	t.Helper()
	return listOver(t, storage, data, testPrefix)
}

// listOver drives the endpoint over the given prefixes, so the multi-prefix behaviour credential-do
// needs is exercised by the same helper as the single-prefix case.
func listOver(t *testing.T, storage logical.Storage, data map[string]any,
	prefixes ...string,
) *logical.Response {
	t.Helper()
	path := Endpoint{Prefixes: prefixes}.FrameworkPath()
	resp, err := path.Operations[logical.ListOperation].Handler()(t.Context(),
		&logical.Request{Operation: logical.ListOperation, Storage: storage},
		&framework.FieldData{Raw: data, Schema: path.Fields})
	if err != nil {
		t.Fatalf("listing returned a transport error: %v", err)
	}
	if resp == nil {
		t.Fatal("listing returned no response")
	}
	return resp
}

func soleEntry(t *testing.T, resp *logical.Response) map[string]any {
	t.Helper()
	if resp.IsError() {
		t.Fatalf("listing was refused: %v", resp.Error())
	}
	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 1 {
		t.Fatalf("expected one entry, got %v", keys)
	}
	info, ok := resp.Data["key_info"].(map[string]any)
	if !ok {
		t.Fatalf("no key_info in %v", resp.Data)
	}
	entry, ok := info[keys[0]].(map[string]any)
	if !ok {
		// key_info values survive a JSON round trip in the real transport, so accept either.
		raw, err := json.Marshal(info[keys[0]])
		if err != nil {
			t.Fatalf("key_info[%q] is %T: %v", keys[0], info[keys[0]], info[keys[0]])
		}
		entry = map[string]any{}
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatalf("key_info[%q] does not decode: %v", keys[0], err)
		}
	}
	return entry
}

// TestTwoKeyspacesAreOneInventory is credential-do's shape: tokens and Spaces keys are tracked under
// separate prefixes because their upstream quotas are separate, and ONE listing has to cover both. An
// inventory that reported the first keyspace and stopped would look exactly like a working one.
func TestTwoKeyspacesAreOneInventory(t *testing.T) {
	const second = "active-spaces-keys/"
	storage := seed(t, map[string]map[string]any{"tok-1": {"role": "executor"}})
	entry, err := logical.StorageEntryJSON(second+"DO00KEY", map[string]any{"role": "backups"})
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if err := storage.Put(t.Context(), entry); err != nil {
		t.Fatalf("seeding the second keyspace failed: %v", err)
	}

	resp := listOver(t, storage, nil, testPrefix, second)
	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 2 {
		t.Fatalf("an inventory over two keyspaces listed %v; both credentials are outstanding", keys)
	}
}

// TestACursorCarriesWhichKeyspaceItIsIn: paging across two prefixes at limit=1 must visit every entry
// once. A cursor that carried only a key would either restart in the wrong keyspace or skip one.
func TestACursorCarriesWhichKeyspaceItIsIn(t *testing.T) {
	const second = "active-spaces-keys/"
	storage := seed(t, map[string]map[string]any{"tok-1": {"role": "r"}, "tok-2": {"role": "r"}})
	for _, id := range []string{"DO00A", "DO00B"} {
		entry, err := logical.StorageEntryJSON(second+id, map[string]any{"role": "r"})
		if err != nil {
			t.Fatalf("encoding failed: %v", err)
		}
		if err := storage.Put(t.Context(), entry); err != nil {
			t.Fatalf("seeding failed: %v", err)
		}
	}

	seen := map[string]int{}
	after := ""
	for range 8 {
		resp := listOver(t, storage, map[string]any{FieldLimit: 1, FieldAfter: after},
			testPrefix, second)
		if resp.IsError() {
			t.Fatalf("paging was refused: %v", resp.Error())
		}
		keys, _ := resp.Data["keys"].([]string)
		for _, key := range keys {
			seen[key]++
		}
		if more, _ := resp.Data[FieldMore].(bool); !more {
			break
		}
		after, _ = resp.Data[FieldNextAfter].(string)
	}

	if len(seen) != 4 {
		t.Errorf("paging two keyspaces at limit=1 saw %v, want all four", seen)
	}
	for key, count := range seen {
		if count != 1 {
			t.Errorf("%q returned %d times across a keyspace boundary", key, count)
		}
	}
}

// TestAMangledCursorIsRefused: a client looping on a cursor it damaged must be told, not silently
// restarted at the beginning — which would page forever over the same entries.
func TestAMangledCursorIsRefused(t *testing.T) {
	storage := seed(t, map[string]map[string]any{"a": {"role": "r"}})

	for name, cursor := range map[string]string{
		"no separator":     "AKIAEXAMPLE",
		"unknown keyspace": "7|AKIAEXAMPLE",
		"not a number":     "x|AKIAEXAMPLE",
	} {
		t.Run(name, func(t *testing.T) {
			resp := list(t, storage, map[string]any{FieldAfter: cursor})
			if !resp.IsError() {
				t.Fatalf("cursor %q was accepted", cursor)
			}
		})
	}
}
