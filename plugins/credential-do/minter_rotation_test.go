package credentialdo

import (
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	rotationTestSet = "default"
	notSupportedMsg = "not supported"
)

// TestMinterSetRotate_RejectsAndDoesNotMutate verifies the uniform rotate
// endpoint exists but rejects with a clear "not supported" message and leaves
// the minter set entirely unchanged (no minter retired, same membership). DO
// cannot self-rotate minters; the endpoint is reject-only.
func TestMinterSetRotate_RejectsAndDoesNotMutate(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	storage := config.StorageView

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{"do_api_url": srv.URL},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config: %v %v", err, resp)
	}

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/" + rotationTestSet, Storage: storage,
		Data: map[string]interface{}{"minters": []interface{}{
			map[string]interface{}{"id": "minter-1", minterTokenKey: "dop_v1_a", "never_expires": true},
			map[string]interface{}{"id": "minter-2", minterTokenKey: "dop_v1_b", "never_expires": true},
		}},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("minter-set write: %v %v", err, resp)
	}

	before := readSetSnapshot(t, b, storage)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "minter-sets/" + rotationTestSet + "/rotate", Storage: storage,
		Data: map[string]interface{}{fieldMinterID: "minter-1"},
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

// TestConfigMinterRetireGraceRoundTrip verifies the uniform minter_retire_grace
// config field writes and reads back unchanged.
func TestConfigMinterRetireGraceRoundTrip(t *testing.T) {
	const graceSeconds = 86400
	srv := fakes.NewDOServer()
	defer srv.Close()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	storage := config.StorageView

	if resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{"do_api_url": srv.URL, fieldMinterRetireGrace: graceSeconds},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: %v %v", err, resp)
	}

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("config read: %v %v", err, resp)
	}
	if got := resp.Data[fieldMinterRetireGrace]; got != graceSeconds {
		t.Fatalf("minter_retire_grace = %v, want %d", got, graceSeconds)
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
	// minter_ids from storage gives a deterministic ordering.
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
