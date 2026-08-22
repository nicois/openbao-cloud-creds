package cloudconfig

import (
	"encoding/json"
	"testing"
)

// The version exists for one job: stop THIS binary from touching an entry a NEWER
// binary wrote, because every mutation rewrites the whole struct and encoding/json
// drops what it does not know (A30).
func TestCheckSchemaRefusesOnlyTheFuture(t *testing.T) {
	cases := []struct {
		name    string
		version int
		wantErr bool
	}{
		{"written before versioning existed", 0, false},
		{"written by this binary", SchemaVersion, false},
		{"written by a newer binary", SchemaVersion + 1, true},
		{"written by a much newer binary", 9999, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Versioned{Schema: tc.version}.CheckSchema("minter set \"default\"")
			if tc.wantErr && err == nil {
				t.Fatalf("schema %d was accepted; a rewrite would erase the fields this binary does "+
					"not know about", tc.version)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("schema %d was refused: %v", tc.version, err)
			}
			if tc.wantErr && !containsAll(err.Error(), `minter set "default"`, "refusing") {
				t.Errorf("the refusal should name the entry and say it is refusing: %v", err)
			}
		})
	}
}

func containsAll(haystack string, needles ...string) bool {
	for _, n := range needles {
		found := false
		for i := 0; i+len(n) <= len(haystack); i++ {
			if haystack[i:i+len(n)] == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// An entry written before versioning existed must round-trip unchanged, so
// introducing the field does not itself rewrite every stored entry.
func TestVersionedIsOmittedWhenZero(t *testing.T) {
	raw, err := json.Marshal(MinterSet{Name: "default"})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if containsAll(string(raw), "schema_version") {
		t.Errorf("an unstamped entry carries a schema_version field: %s", raw)
	}

	stamped := MinterSet{Name: "default"}
	stamped.Stamp()
	raw, err = json.Marshal(stamped)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !containsAll(string(raw), `"schema_version":1`) {
		t.Errorf("Stamp did not record the version: %s", raw)
	}
}

// DefaultConfig is used when no config has ever been written (A14), so it must
// stamp the version like any other write path — otherwise the first real write
// after it would be the only thing that ever did.
func TestDefaultConfigIsStamped(t *testing.T) {
	if got := DefaultConfig("do").Schema; got != SchemaVersion {
		t.Errorf("DefaultConfig schema is %d, want %d", got, SchemaVersion)
	}
}
