package cloudconfig

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// A role schema shaped like a plugin's: a required field, a defaulted duration, a
// slice, and the containment flag.
func testRoleSchema() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name":        {Type: framework.TypeString},
		"minter_set":  {Type: framework.TypeString},
		"default_ttl": {Type: framework.TypeDurationSecond, Default: 900},
		"scopes":      {Type: framework.TypeCommaStringSlice},
		"disabled":    {Type: framework.TypeBool},
	}
}

// storedRole is a plugin's role as it is persisted: a duration in nanoseconds, which
// is exactly the value that must NOT reach a TypeDurationSecond field unconverted.
type storedRole struct {
	Name       string   `json:"name"`
	MinterSet  string   `json:"minter_set"`
	DefaultTTL int64    `json:"default_ttl"`
	Scopes     []string `json:"scopes"`
	Disabled   bool     `json:"disabled,omitempty"`
}

// render is the plugin's read-endpoint shape: seconds, not nanoseconds, plus a field
// the write schema does not accept.
func renderStoredRole(raw []byte) (map[string]interface{}, error) {
	var role storedRole
	if err := json.Unmarshal(raw, &role); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"name":        role.Name,
		"minter_set":  role.MinterSet,
		"default_ttl": int(role.DefaultTTL / 1e9),
		"scopes":      role.Scopes,
		"disabled":    role.Disabled,
		"credential":  "not a write field",
	}, nil
}

func putStoredRole(t *testing.T, storage logical.Storage, key string, role storedRole) {
	t.Helper()
	entry, err := logical.StorageEntryJSON(key, role)
	if err != nil {
		t.Fatalf("encoding the stored role: %v", err)
	}
	if err := storage.Put(t.Context(), entry); err != nil {
		t.Fatalf("storing the role: %v", err)
	}
}

func fieldData(raw map[string]interface{}) *framework.FieldData {
	return &framework.FieldData{Raw: raw, Schema: testRoleSchema()}
}

// The case the flag exists for: one field in, and everything else the role already
// said stays exactly as it was.
func TestPrefillRoleWriteFillsInWhatTheRequestOmitted(t *testing.T) {
	storage := &logical.InmemStorage{}
	putStoredRole(t, storage, "roles/backups", storedRole{
		Name: "backups", MinterSet: "prod", DefaultTTL: 1800e9, Scopes: []string{"droplet:create"},
	})

	d := fieldData(map[string]interface{}{"name": "backups", "disabled": true})
	if err := PrefillRoleWrite(t.Context(), storage, "roles/backups", d, renderStoredRole); err != nil {
		t.Fatalf("prefill failed: %v", err)
	}

	if got := d.Get("minter_set"); got != "prod" {
		t.Errorf("minter_set is %v, want prod — a one-field write must not drop the binding", got)
	}
	if got := d.Get("default_ttl"); got != 1800 {
		t.Errorf("default_ttl is %v, want 1800 seconds; a stored duration is nanoseconds and must "+
			"be prefilled in the units the schema reads", got)
	}
	if got := d.Get("scopes").([]string); len(got) != 1 || got[0] != "droplet:create" {
		t.Errorf("scopes is %v, want [droplet:create]", got)
	}
	if got := d.Get("disabled"); got != true {
		t.Errorf("disabled is %v, want the value the request supplied", got)
	}
}

// A value the request DID supply wins, including one that clears a field.
func TestPrefillRoleWriteKeepsWhatTheRequestSupplied(t *testing.T) {
	storage := &logical.InmemStorage{}
	putStoredRole(t, storage, "roles/backups", storedRole{
		Name: "backups", MinterSet: "prod", DefaultTTL: 1800e9, Disabled: true,
	})

	d := fieldData(map[string]interface{}{"name": "backups", "minter_set": "staging", "disabled": false})
	if err := PrefillRoleWrite(t.Context(), storage, "roles/backups", d, renderStoredRole); err != nil {
		t.Fatalf("prefill failed: %v", err)
	}

	if got := d.Get("minter_set"); got != "staging" {
		t.Errorf("minter_set is %v, want staging", got)
	}
	if got := d.Get("disabled"); got != false {
		t.Errorf("disabled is %v; re-enabling a role must not be overwritten by its stored value", got)
	}
}

// A create is untouched: the defaults apply and a required field is still absent, so
// the handler's own validation still refuses an incomplete role.
func TestPrefillRoleWriteLeavesACreateAlone(t *testing.T) {
	d := fieldData(map[string]interface{}{"name": "backups"})
	if err := PrefillRoleWrite(t.Context(), &logical.InmemStorage{}, "roles/backups", d, renderStoredRole); err != nil {
		t.Fatalf("prefill failed: %v", err)
	}
	if got := d.Get("default_ttl"); got != 900 {
		t.Errorf("default_ttl is %v, want the schema default 900", got)
	}
	if got := d.Get("minter_set"); got != "" {
		t.Errorf("minter_set is %v, want empty so the handler still refuses the write", got)
	}
}

// A field the read endpoint reports but the write schema does not accept must not be
// copied in: d.Get panics on a field with no schema.
func TestPrefillRoleWriteIgnoresFieldsOutsideTheSchema(t *testing.T) {
	storage := &logical.InmemStorage{}
	putStoredRole(t, storage, "roles/backups", storedRole{Name: "backups", MinterSet: "prod", DefaultTTL: 900e9})

	d := fieldData(map[string]interface{}{"name": "backups", "disabled": true})
	if err := PrefillRoleWrite(t.Context(), storage, "roles/backups", d, renderStoredRole); err != nil {
		t.Fatalf("prefill failed: %v", err)
	}
	if _, copied := d.Raw["credential"]; copied {
		t.Error("a stored field absent from the write schema was copied into the request body")
	}
}

// An unparseable stored role prefills nothing rather than failing, so a full rewrite
// remains the way to repair it.
func TestPrefillRoleWriteToleratesAnUnparseableStoredRole(t *testing.T) {
	storage := &logical.InmemStorage{}
	if err := storage.Put(t.Context(), &logical.StorageEntry{Key: "roles/backups", Value: []byte("{not json")}); err != nil {
		t.Fatalf("storing the corrupt entry: %v", err)
	}

	d := fieldData(map[string]interface{}{"name": "backups", "minter_set": "prod"})
	if err := PrefillRoleWrite(t.Context(), storage, "roles/backups", d, renderStoredRole); err != nil {
		t.Fatalf("an unparseable stored role must not fail the write: %v", err)
	}
	if got := d.Get("default_ttl"); got != 900 {
		t.Errorf("default_ttl is %v, want the schema default 900", got)
	}
}

// A storage read that fails is reported: the write would otherwise be built on a base
// nobody read, and silently rebuild the role from defaults.
func TestPrefillRoleWriteReportsAStorageFailure(t *testing.T) {
	want := errors.New("quorum lost")
	d := fieldData(map[string]interface{}{"name": "backups"})
	err := PrefillRoleWrite(t.Context(), failingReads{err: want}, "roles/backups", d, renderStoredRole)
	if !errors.Is(err, want) {
		t.Fatalf("prefill returned %v, want the storage error", err)
	}
}

type failingReads struct {
	logical.Storage
	err error
}

func (f failingReads) Get(context.Context, string) (*logical.StorageEntry, error) {
	return nil, f.err
}
