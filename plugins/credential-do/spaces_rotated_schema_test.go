package credentialdo_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The shared-key record is the one persisted struct here with lifecycle fields, and every
// mutation of it is read-struct → change → write the WHOLE struct back. encoding/json drops
// what it does not know, so a binary predating a field ERASES it — and on this record that is
// worse than on a minter set: dropping `retiring` un-retires a rotated-out Spaces key and
// cancels the sweep that was going to delete it, and a Spaces key has NO upstream expiry, so
// nothing else ever reclaims the orphan.
//
// Both halves are asserted together, the way the shared reload suite does it for minter sets:
// this binary must refuse to serve from a record it cannot safely rewrite, and it must leave
// that record untouched.

const rotatedStateKey = "shared-spaces-keys/" + rotatedRoleName

func TestRotatedSpacesState_FromANewerSchemaIsRefusedAndLeftIntact(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	b, storage := setupRotatedBackend(t, srv)

	// Mint the first key so there is a record to tamper with.
	first := accessKeyOf(t, issueFrom(t, b, storage, rotatedRoleName, nil))

	entry, err := storage.Get(t.Context(), rotatedStateKey)
	if err != nil || entry == nil {
		t.Fatalf("no shared-key record at %q: err=%v entry=%v", rotatedStateKey, err, entry)
	}
	var state map[string]any
	if err := json.Unmarshal(entry.Value, &state); err != nil {
		t.Fatalf("the persisted record is not JSON: %v", err)
	}
	if state["schema_version"] == nil {
		t.Fatal("the record carries no schema_version, so a newer binary's fields can be erased " +
			"silently on the next rotation or sweep")
	}

	// A version from the future, plus a field this binary knows nothing about — which is exactly
	// what a whole-struct rewrite would destroy.
	state["schema_version"] = 9999
	state["a_field_this_binary_does_not_know"] = "must survive"
	value, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("could not re-encode the record: %v", err)
	}
	if err := storage.Put(t.Context(), &logical.StorageEntry{Key: rotatedStateKey, Value: value}); err != nil {
		t.Fatalf("could not write the future-schema record back: %v", err)
	}

	if resp := issueFrom(t, b, storage, rotatedRoleName, nil); resp != nil && !resp.IsError() {
		t.Errorf("a backend that does not understand the persisted record served from it anyway "+
			"(%v). The next rotation would rewrite it and erase whatever the newer binary put there",
			resp.Data["credential"])
	}

	after, err := storage.Get(t.Context(), rotatedStateKey)
	if err != nil || after == nil {
		t.Fatalf("the record went missing: err=%v", err)
	}
	if !bytes.Contains(after.Value, []byte("a_field_this_binary_does_not_know")) {
		t.Errorf("the unknown field was erased, which is the exact damage the version check exists "+
			"to prevent: %s", after.Value)
	}
	if !bytes.Contains(after.Value, []byte(first)) {
		t.Errorf("the live key %q vanished from the record; nothing would ever delete it upstream "+
			"now: %s", first, after.Value)
	}
}
