package credentialvultr

import (
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	rotationTestSet = "default"
	notSupportedMsg = "not supported"
)

// TestMinterSetRotate_RejectsAndDoesNotMutate verifies the uniform rotate
// endpoint exists but rejects with a clear "not supported" message and leaves
// the minter set entirely unchanged. Vultr cannot self-rotate minters; the
// endpoint is reject-only.
func TestMinterSetRotate_RejectsAndDoesNotMutate(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	storage := config.StorageView

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]any{},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config: %v %v", err, resp)
	}

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/" + rotationTestSet, Storage: storage,
		Data: map[string]any{fieldMintersKey: []any{
			map[string]any{"id": "minter-1", minterTokenKey: "vultr_key_1", "never_expires": true},
			map[string]any{"id": "minter-2", minterTokenKey: "vultr_key_2", "never_expires": true},
		}},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write: %v %v", err, resp)
	}

	before := readSetSnapshot(t, b, storage)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/" + rotationTestSet + "/rotate", Storage: storage,
		Data: map[string]any{fieldMinterID: "minter-1"},
	})
	if err != nil {
		t.Fatalf("rotate request errored: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error response, got %v", resp)
	}
	if msg := resp.Error().Error(); !strings.Contains(msg, notSupportedMsg) {
		t.Fatalf("expected %q in rejection, got %q", notSupportedMsg, msg)
	}

	after := readSetSnapshot(t, b, storage)
	if before != after {
		t.Fatalf("minter set mutated by rotate: before=%q after=%q", before, after)
	}
}

// TestConfigMinterRetireGraceRejectedWhereNothingRetires: this cloud's minters
// cannot self-rotate, so no minter is ever retired and the retired-sweep has nothing
// to sweep — the field is inert here.
//
// This test used to assert the OPPOSITE: that the value round-trips. Uniformity of
// the config schema is worth something, but not at the price of telling an operator
// a setting is in force when nothing will ever read it — which is the same defect as
// UpCloud's `scopes` and is what A28 is about. A uniform template that omits the
// field still works; only setting it explicitly is refused.
func TestConfigMinterRetireGraceRejectedWhereNothingRetires(t *testing.T) {
	const graceSeconds = 86400
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	storage := config.StorageView

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: pathConfigKey, Storage: storage,
		Data: map[string]any{fieldMinterRetireGrace: graceSeconds},
	})
	if err != nil {
		t.Fatalf("config write errored: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("an explicitly-set %s was accepted on a cloud where nothing is ever retired, so "+
			"the operator is told a setting is in force that will never be read: %v",
			fieldMinterRetireGrace, resp)
	}
	if got := resp.Error().Error(); !strings.Contains(got, "has no effect on this cloud") {
		t.Errorf("the rejection should say the field has no effect here, got: %v", got)
	}
}

// readSetSnapshot returns a stable string describing the persisted set's minter
// membership and retired flags, for before/after equality assertions.
func readSetSnapshot(t *testing.T, b logical.Backend, storage logical.Storage) string {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "minter-sets/" + rotationTestSet, Storage: storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("set read: %v %v", err, resp)
	}
	bk := b.(*backend)
	bk.mu.RLock()
	defer bk.mu.RUnlock()
	var sb strings.Builder
	states := bk.minterSets[rotationTestSet]
	ids, _ := resp.Data["minter_ids"].([]string)
	for _, id := range ids {
		sb.WriteString(id)
		if st, ok := states[id]; ok && st.minter.Retired {
			sb.WriteString(":retired")
		}
		sb.WriteString(";")
	}
	return sb.String()
}
